"""
proc_sniffer — 按进程名抓取本机网络报文（Windows 10 本机版，含 L3/L4 + L7）

链路:
  软件名 --psutil--> PID/端口
    L3/L4: pktmon(带PID抓全量) --> ETL --etl2pcapng--> pcapng --按PID/端口过滤--> filtered.pcap
    L7   : mitmproxy(代理, 按源端口->PID过滤) --> http_traffic.jsonl (HTTP 明文 req/resp)
    导出 : requests.json / index.md / filtered.pcap / http_traffic.jsonl

说明:
  - pktmon 为 Win10 1809+ 内置, 抓包时原生记录进程(PID)。
  - PID 过滤优先用 tshark 的 _ws.process.id 元数据(精确), 失败回退端口映射。
  - L7 明文需目标进程走代理(系统代理或单独设代理), 并信任 mitmproxy CA;
    证书绑定(SSL Pinning)需 Frida 绕过(超出本工具范围, 见 README)。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

import psutil
from scapy.all import rdpcap, wrpcap, IP, TCP, UDP

PKTMON = "pktmon"                                  # Win10 1809+ 内置, 需管理员
ETL2PCAP = "etl2pcap"                               # pktmon 子命令: pktmon etl2pcap <etl> --out <pcapng>
# 可选, 下载: https://github.com/microsoft/etl2pcapng  (也可用 PROC_SNIFFER_ETL2PCAPNG 覆盖)
ETL2PCAPNG_FALLBACK = os.environ.get(
    "PROC_SNIFFER_ETL2PCAPNG", r"C:\tools\etl2pcapng.exe")
# 可选, 用于 PID 元数据精确过滤 (也可用 PROC_SNIFFER_TSHARK 覆盖)
TSHARK = os.environ.get(
    "PROC_SNIFFER_TSHARK", r"C:\Program Files\Wireshark\tshark.exe")
# 抓包工作目录 (也可用 PROC_SNIFFER_WORKDIR 覆盖)
WORK_DIR = Path(os.environ.get("PROC_SNIFFER_WORKDIR", str(Path.home() / "proc_sniffer_caps")))
L7_PROXY_PORT = int(os.environ.get("PROC_SNIFFER_L7_PORT", "8080"))


class ProcSniffer:
    def __init__(self, work_dir: str | None = None):
        self.work_dir = Path(work_dir) if work_dir else WORK_DIR
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._etl = self.work_dir / "capture.etl"
        self._pcapng = self.work_dir / "capture.pcapng"
        self._filtered = self.work_dir / "filtered.pcap"
        self._http = self.work_dir / "http_traffic.jsonl"
        self._pids_file = self.work_dir / "pids.txt"
        self._running = False
        self._target_pids: set[int] = set()
        self._ports_snapshot: set[int] = set()
        self._timer = None
        self._l7_proc = None
        self._tshark_cache: str | None = None
        self._layers = "l3"

    # ① 软件名 -> PID 列表(模糊匹配 name/exe/cmdline, 含子进程)
    def resolve_pids(self, app_name: str) -> list[int]:
        app = app_name.lower()
        pids: set[int] = set()
        for p in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                info = p.info
                hay = " ".join(filter(None, [
                    (info.get("name") or "").lower(),
                    (info.get("exe") or "").lower(),
                    " ".join(info.get("cmdline") or []).lower(),
                ]))
                if app in hay:
                    pids.add(info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return sorted(pids)

    # ② 采样指定 PID 使用的本地端口
    def sample_ports(self, pids: set[int]) -> set[int]:
        ports: set[int] = set()
        for c in psutil.net_connections(kind="inet"):
            if c.pid in pids and c.laddr:
                ports.add(c.laddr.port)
        return ports

    def _port_sampler(self):
        while self._running:
            self._ports_snapshot |= self.sample_ports(self._target_pids)
            time.sleep(1)

    # ③ 启动抓取
    def start_capture(self, pids: list[int], duration: int | None = None,
                      layers: str = "full"):
        """
        layers:
          "l3"  仅 L3/L4 报文(pktmon)
          "l7"  仅 HTTP 明文(mitmproxy, 需目标进程走代理)
          "full" 两者都开(默认)
        """
        if self._running:
            raise RuntimeError("已在抓取中, 请先 stop_capture")
        if not pids:
            raise ValueError("pids 为空")
        self._target_pids = set(pids)
        self._ports_snapshot = set()
        self._layers = layers
        # 写 pids 文件供 L7 addon 读取(支持动态进程)
        self._pids_file.write_text(" ".join(map(str, pids)), encoding="utf-8")
        for f in (self._etl, self._pcapng, self._filtered, self._http):
            if f.exists():
                f.unlink()
        self._running = True
        if layers in ("l3", "full"):
            self._port_sampler_thread = threading.Thread(
                target=self._port_sampler, daemon=True)
            self._port_sampler_thread.start()
            subprocess.run([PKTMON, "start", "--capture", "--pkt-size", "4096",
                            "--file-size", "512",
                            "--file-name", str(self._etl)], check=True)
        if layers in ("l7", "full"):
            self._start_l7()
        if duration:
            self._timer = threading.Timer(duration, self.stop_capture)
            self._timer.start()

    def _start_l7(self, port: int = L7_PROXY_PORT):
        from l7_capture import run_mitmproxy
        self._l7_proc = run_mitmproxy(
            port=port, pids_file=self._pids_file, out_file=self._http)

    # ④ 停止 + 转换 + 过滤
    def stop_capture(self):
        if not self._running:
            return None
        try:
            if self._layers in ("l3", "full") and self._etl.exists():
                r = subprocess.run([PKTMON, "stop"], check=False, capture_output=True)
                stdout = r.stdout.decode("utf-8", errors="replace") if r.stdout else ""
                stderr = r.stderr.decode("utf-8", errors="replace") if r.stderr else ""
                print(f"[pktmon stop] rc={r.returncode} {stdout.strip()} {stderr.strip()}")
        finally:
            self._running = False
        # L3/L4 处理
        if self._layers in ("l3", "full") and self._etl.exists():
            self.convert()
            self.filter_by_pid(self._target_pids)
        # L7 处理
        if self._l7_proc is not None:
            try:
                self._l7_proc.terminate()
            except Exception:
                pass
            self._l7_proc = None
        return str(self._pcapng)

    def convert(self) -> Path:
        if not self._etl.exists():
            raise RuntimeError("未找到 ETL, 请确认以管理员身份运行且 pktmon 可用")
        # 优先使用系统内置 pktmon etl2pcap, 回退可选 etl2pcapng.exe
        if Path(ETL2PCAPNG_FALLBACK).exists():
            subprocess.run([ETL2PCAPNG_FALLBACK, str(self._etl), str(self._pcapng)], check=True)
        else:
            subprocess.run([PKTMON, ETL2PCAP, str(self._etl), "--out", str(self._pcapng)], check=True)
        return self._pcapng

    # ⑤ 按端口集合过滤 pcapng -> pcap(回退方案)
    def filter_by_ports(self, ports: set[int], src: str | None = None) -> Path:
        src = Path(src) if src else self._pcapng
        if not src.exists():
            return self._filtered
        packets = rdpcap(str(src))
        kept = []
        for pkt in packets:
            if IP in pkt and (TCP in pkt or UDP in pkt):
                l4 = pkt[TCP] if TCP in pkt else pkt[UDP]
                if int(l4.sport) in ports or int(l4.dport) in ports:
                    kept.append(pkt)
        wrpcap(str(self._filtered), kept)
        return self._filtered

    # ⑥ 精确 PID 过滤: tshark 元数据优先, 端口映射回退
    def filter_by_pid(self, pids: set[int]) -> Path:
        if not self._pcapng.exists():
            return self._filtered
        ts = self._tshark_path()
        if ts:
            try:
                expr = " or ".join(f"_ws.process.id == {p}" for p in pids) or "tcp"
                subprocess.run([ts, "-r", str(self._pcapng), "-Y", expr,
                                "-w", str(self._filtered)],
                               check=True, capture_output=True, text=True)
                if self._filtered.exists() and self._filtered.stat().st_size > 0:
                    return self._filtered
            except Exception:
                pass  # 回退端口映射
        ports = self._ports_snapshot | self.sample_ports(set(pids))
        return self.filter_by_ports(ports)

    def _tshark_path(self) -> str | None:
        if self._tshark_cache:
            return self._tshark_cache
        if Path(TSHARK).exists():
            self._tshark_cache = TSHARK
            return TSHARK
        from shutil import which
        p = which("tshark")
        if p:
            self._tshark_cache = p
        return p

    # ⑦ 导出
    def export(self, app_name: str, pids: list[int], out_dir: str | None = None) -> dict:
        out = Path(out_dir) if out_dir else (self.work_dir / "exports" / app_name)
        out.mkdir(parents=True, exist_ok=True)
        # L3/L4 连接清单
        packets = rdpcap(str(self._filtered)) if self._filtered.exists() else []
        conns: dict = {}
        for pkt in packets:
            if IP in pkt and (TCP in pkt or UDP in pkt):
                l4 = pkt[TCP] if TCP in pkt else pkt[UDP]
                key = (pkt[IP].src, int(l4.sport), pkt[IP].dst, int(l4.dport),
                       "TCP" if TCP in pkt else "UDP")
                c = conns.setdefault(key, {"packets": 0, "bytes": 0})
                c["packets"] += 1
                c["bytes"] += len(pkt)
        stats = {
            "app_name": app_name,
            "pids": pids,
            "captured_at": datetime.now().isoformat(timespec="seconds"),
            "connections": [
                {"src": s, "sport": sp, "dst": d, "dport": dp, "proto": pr,
                 "packets": v["packets"], "bytes": v["bytes"]}
                for (s, sp, d, dp, pr), v in conns.items()
            ],
        }
        (out / "requests.json").write_text(
            json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
        # index.md
        lines = [
            f"# {app_name} 流量导出",
            f"- 时间: {stats['captured_at']}",
            f"- PID: {pids}",
            f"- L3/L4 连接数: {len(stats['connections'])}",
            f"- L7 HTTP 记录数: {self._count_http()}",
            "",
            "## L3/L4 连接清单", "",
            "| 源 | 源端口 | 目的 | 目的端口 | 协议 | 包数 | 字节 |",
            "|---|---|---|---|---|---|---|",
        ]
        for c in stats["connections"]:
            lines.append(
                f"| {c['src']} | {c['sport']} | {c['dst']} | {c['dport']} | {c['proto']} | {c['packets']} | {c['bytes']} |")
        (out / "index.md").write_text("\n".join(lines), encoding="utf-8")
        # 复制产物
        if self._filtered.exists():
            shutil.copy(self._filtered, out / "filtered.pcap")
        if self._http.exists():
            shutil.copy(self._http, out / "http_traffic.jsonl")
        return {
            "json": str(out / "requests.json"),
            "index": str(out / "index.md"),
            "pcap": str(out / "filtered.pcap"),
            "http": str(out / "http_traffic.jsonl") if self._http.exists() else None,
            "connections": len(stats["connections"]),
            "http_records": self._count_http(),
        }

    def _count_http(self) -> int:
        if not self._http.exists():
            return 0
        try:
            return sum(1 for _ in open(self._http, encoding="utf-8"))
        except Exception:
            return 0


if __name__ == "__main__":
    # CLI 自测: python proc_sniffer.py <软件名> [秒] [l3|l7|full]
    # 注意: 必须在管理员终端运行(pktmon 需要内核权限)
    import sys
    if len(sys.argv) < 2:
        print(__doc__)
        print("用法: python proc_sniffer.py <软件名或exe名> [秒=30] [l3|l7|full]")
        sys.exit(2)
    app = sys.argv[1]
    dur = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    layers = sys.argv[3] if len(sys.argv) > 3 else "full"
    s = ProcSniffer()
    pids = s.resolve_pids(app)
    print("解析到 PID:", pids)
    if not pids:
        print("未找到进程, 退出")
        sys.exit(1)
    if layers in ("l7", "full"):
        print(f"[提示] L7 模式需让 '{app}' 走代理 127.0.0.1:{L7_PROXY_PORT} (系统代理或单独设)")
    print(f"[*] 开始抓取 {dur}s")
    s.start_capture(pids, duration=None, layers=layers)  # 不用 timer, 主线程同步等待
    print(f">>> 现在去操作 '{app}' 触发目标请求(窗口越长越容易漏, 建议开始后立即操作) <<<")
    try:
        time.sleep(dur)                                # 抓取窗口
    finally:
        s.stop_capture()                               # 同步 stop + convert + filter
    print("抓取完成, 导出中...")
    print(json.dumps(s.export(app, pids), ensure_ascii=False, indent=2))
