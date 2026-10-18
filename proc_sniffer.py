"""
proc_sniffer — 按进程名抓取本机网络报文（Windows 10 本机版，含 L3/L4 + L7）

链路:
  软件名 --psutil--> PID/端口
    L3/L4: pktmon(抓全量) + Kernel-Network(每条 socket 操作带 PID) --> ETL
           --etl2pcapng--> pcapng --按 4 元组 join ETW 的 PID--> filtered.pcap
    L7   : mitmproxy(代理, 按源端口->PID过滤) --> http_traffic.jsonl (HTTP 明文 req/resp)
    导出 : requests.json / index.md / filtered.pcap / http_traffic.jsonl

说明:
  - pktmon 为 Win10 1809+ 内置。它记录的报文本身不带 PID, pktmon etl2pcap
    转出的 pcapng 里也没有进程元数据(Wireshark 的 _ws.process.id 字段并不存在)。
  - 真正带 PID 的是 Microsoft-Windows-Kernel-Network 这个 ETW provider: 每条
    TCP/UDP send/recv/connect 事件都有 PID + saddr/sport/daddr/dport。所以抓包时
    同时挂上它, 事后用 4 元组把 pcapng 报文 join 到 PID。
  - ETW 拿不到时回退端口采样(精度低, 短连接可能漏)。
  - L7 明文需目标进程走代理(系统代理或单独设代理), 并信任 mitmproxy CA;
    证书绑定(SSL Pinning)需 Frida 绕过(超出本工具范围, 见 README)。
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

import psutil
from scapy.all import PcapReader, rdpcap, wrpcap, IP, TCP, UDP

PKTMON = "pktmon"                                  # Win10 1809+ 内置, 需管理员
ETL2PCAP = "etl2pcap"                               # pktmon 子命令: pktmon etl2pcap <etl> --out <pcapng>
# 可选, 下载: https://github.com/microsoft/etl2pcapng  (也可用 PROC_SNIFFER_ETL2PCAPNG 覆盖)
ETL2PCAPNG_FALLBACK = os.environ.get(
    "PROC_SNIFFER_ETL2PCAPNG", r"C:\tools\etl2pcapng.exe")
# 抓包工作目录 (也可用 PROC_SNIFFER_WORKDIR 覆盖)
WORK_DIR = Path(os.environ.get("PROC_SNIFFER_WORKDIR", str(Path.home() / "proc_sniffer_caps")))
L7_PROXY_PORT = int(os.environ.get("PROC_SNIFFER_L7_PORT", "8080"))
# 带 PID 的 ETW provider: 每条 TCP/UDP 收发事件都有 PID + 4 元组
ETW_PROVIDER = "Microsoft-Windows-Kernel-Network"


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
        self._layers = "l3"
        self._etw_xml: Path | None = None
        self._peer_only = 0

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
        self._etw_xml = self.work_dir / "etw_network.xml"
        for f in (self._etl, self._pcapng, self._filtered, self._http, self._etw_xml):
            if f.exists():
                f.unlink()
        self._running = True
        if layers in ("l3", "full"):
            self._port_sampler_thread = threading.Thread(
                target=self._port_sampler, daemon=True)
            self._port_sampler_thread.start()
            # 同时挂 Kernel-Network provider: pktmon 的报文不带 PID, 这个带。
            subprocess.run([PKTMON, "start", "--capture", "--trace",
                            "--provider", ETW_PROVIDER,
                            "--pkt-size", "4096", "--file-size", "512",
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
        # ETL 里同时含 PktMon 报文和 Kernel-Network 事件, 先把事件侧导出成 XML
        self._export_etw()
        # 优先使用系统内置 pktmon etl2pcap, 回退可选 etl2pcapng.exe
        if Path(ETL2PCAPNG_FALLBACK).exists():
            subprocess.run([ETL2PCAPNG_FALLBACK, str(self._etl), str(self._pcapng)], check=True)
        else:
            subprocess.run([PKTMON, ETL2PCAP, str(self._etl), "--out", str(self._pcapng)], check=True)
        return self._pcapng

    def _export_etw(self):
        """用 tracerpt 把 ETL 里的 ETW 事件导成 XML(报文由 pktmon etl2pcap 单独转)。"""
        if self._etw_xml is None:
            self._etw_xml = self.work_dir / "etw_network.xml"
        r = subprocess.run(["tracerpt", str(self._etl), "-of", "XML",
                            "-o", str(self._etw_xml), "-y"],
                           check=False, capture_output=True)
        if not self._etw_xml.exists() or self._etw_xml.stat().st_size == 0:
            print(f"[etw] tracerpt 未产出 XML rc={r.returncode}")

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

    # ⑥ 精确 PID 过滤: ETW 4 元组 join 优先, 端口映射回退
    def filter_by_pid(self, pids: set[int]) -> Path:
        if not self._pcapng.exists():
            return self._filtered
        try:
            kept = self.filter_by_etw(pids)
            if kept is not None:
                return kept
        except Exception:
            pass  # 回退端口映射
        ports = self._ports_snapshot | self.sample_ports(set(pids))
        return self.filter_by_ports(ports)

    # ⑥a 解析 ETW: (saddr,sport,daddr,dport) -> {pid}
    def _local_ips(self) -> set[str]:
        ips: set[str] = set()
        try:
            for _, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family in (socket.AF_INET, socket.AF_INET6):
                        ips.add(a.address.split("%")[0])
        except Exception:
            pass
        return ips

    def _etw_tuples(self) -> dict[tuple, set[int]]:
        if self._etw_xml is None or not self._etw_xml.exists():
            return {}
        import xml.etree.ElementTree as ET
        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        m: dict[tuple, set[int]] = {}
        for _, el in ET.iterparse(str(self._etw_xml), events=("end",)):
            if el.tag != ns + "Event":
                continue
            prov = el.find(ns + "System/" + ns + "Provider")
            if prov is None or ETW_PROVIDER not in (prov.get("Name") or ""):
                el.clear()
                continue
            d = {x.get("Name"): (x.text or "").strip()
                 for x in el.findall(ns + "EventData/" + ns + "Data")}
            try:
                key = (d["saddr"], int(d["sport"]), d["daddr"], int(d["dport"]))
                m.setdefault(key, set()).add(int(d["PID"]))
            except (KeyError, ValueError):
                pass
            el.clear()
        return m

    # ⑥b 用 ETW 的 PID 过滤 pcapng。ETW 一条记录都没解析到 -> 返回 None(交给回退)
    def filter_by_etw(self, pids: set[int]) -> Path | None:
        m = self._etw_tuples()
        if not m:
            return None
        pids = set(pids)
        # 两级匹配。
        #   exact: (ip,port) 端点, 该进程自己那一侧出现过的。直连时这已经够准。
        #   peer : 对端 ip。走 VPN/TUN 时 ETW 记的是隧道侧 4 元组, pcapng 里是
        #          物理网卡侧, 源端口被 NAT 改写过, 只有对端 ip 能对上。
        exact: set[tuple] = set()
        peer: set[str] = set()
        local_ips = self._local_ips()
        for (sa, sp, da, dp), owners in m.items():
            if not (owners & pids):
                continue
            # exact 只收本机这一侧端点。对端 (ip,port) 是所有进程共用的,
            # 把它算作精确命中会把同服务器的其他进程流量一起放进来。
            if sa in local_ips:
                exact.add((sa, sp))
            else:
                peer.add(sa)
            if da in local_ips:
                exact.add((da, dp))
            else:
                peer.add(da)
        kept = []
        seen = set()
        peer_only = 0
        # 流式读, 512MB 的抓包也不会一次进内存
        for pkt in PcapReader(str(self._pcapng)):
            if IP not in pkt or not (TCP in pkt or UDP in pkt):
                continue
            l4 = pkt[TCP] if TCP in pkt else pkt[UDP]
            src, sport = pkt[IP].src, int(l4.sport)
            dst, dport = pkt[IP].dst, int(l4.dport)
            exact_hit = (src, sport) in exact or (dst, dport) in exact
            if not exact_hit:
                # 端点对不上, 退一步按对端 ip 匹配(NAT/VPN 改写端口时唯一的线索)
                if not (src in peer or dst in peer):
                    continue
                peer_only += 1
            # pktmon 会在协议栈每一层各记一份同一报文, 去重后再落盘
            if TCP in pkt:
                key = (src, sport, dst, dport, int(l4.seq), int(l4.ack),
                       str(l4.flags), len(bytes(l4.payload)))
            else:
                key = (src, sport, dst, dport, bytes(l4.payload))
            if key in seen:
                continue
            seen.add(key)
            kept.append(pkt)
        self._peer_only = peer_only
        wrpcap(str(self._filtered), kept)
        return self._filtered

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
            "attribution": ("etw" if self._etw_xml and self._etw_xml.exists()
                            else "port-sample"),
            # 走 VPN/NAT 时只能按对端 ip 匹配, 这一部分可能混入同服务器的其他进程流量
            "peer_only_packets": self._peer_only,
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
            f"- 归因方式: {stats['attribution']}",
            f"- L3/L4 连接数: {len(stats['connections'])}",
            f"- L7 HTTP 记录数: {self._count_http()}",
            "",
        ]
        if self._peer_only:
            lines += [
                f"> 其中 {self._peer_only} 个报文只按对端 IP 归因（本机走了 VPN/NAT，"
                "端口被改写）。这部分可能混入其他进程发往同一服务器的流量，"
                "需要精确归属时请让目标直连。",
                "",
            ]
        lines += [
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
            "attribution": stats["attribution"],
            "peer_only_packets": self._peer_only,
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
