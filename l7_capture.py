"""
l7_capture — mitmproxy addon: 按源端口->PID 过滤, 仅记录目标进程的 HTTP/HTTPS 明文

被两种方式使用:
  1) 主进程 import run_mitmproxy() 启动 mitmdump 子进程
  2) mitmdump -s l7_capture.py --set pids_file=... --set out_file=...
     加载本模块, 自动注册模块级 addon 实例

工作原理: 作为正向代理拦截流量; 对每个 flow 取其客户端源端口,
反查 psutil 得到所属 PID, 仅当属于目标 PID 集合时才记录明文 req/resp。
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import psutil
from mitmproxy import ctx


def run_mitmproxy(port: int = 8080, pids_file=None, out_file=None) -> subprocess.Popen:
    """启动 mitmdump 子进程, 作为正向代理, 按 pids_file 过滤目标进程 L7 流量。"""
    script = Path(__file__).resolve()
    cmd = [
        sys.executable, "-m", "mitmproxy.tools.main", "mitmdump",
        "-p", str(port),
        "-s", str(script),
        "--set", f"pids_file={pids_file}",
        "--set", f"out_file={out_file}",
        "--set", "termlog_verbosity=warn",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class ProcL7Addon:
    def __init__(self):
        self.pids: set[int] = set()
        self.out = None
        self._last_reload = 0.0

    def load(self, loader):
        loader.add_option("pids_file", str, "", "path to pids.txt")
        loader.add_option("out_file", str, "", "path to http_traffic.jsonl")

    def running(self):
        try:
            self.out = open(ctx.options.out_file, "a", encoding="utf-8")
        except Exception:
            self.out = None
        self._reload()

    def _reload(self):
        try:
            txt = Path(ctx.options.pids_file).read_text(encoding="utf-8").split()
            self.pids = {int(x) for x in txt if x.strip()}
        except Exception:
            pass

    def _belongs(self, flow) -> bool:
        now = time.time()
        if now - self._last_reload > 2:
            self._reload()
            self._last_reload = now
        try:
            port = flow.client_conn.peername[1]
        except Exception:
            return False
        for c in psutil.net_connections(kind="inet"):
            if c.laddr and c.laddr.port == port and c.pid in self.pids:
                return True
        return False

    def request(self, flow):
        if not self._belongs(flow):
            flow.metadata["skip"] = True
            return
        req = flow.request
        flow.metadata["rec"] = {
            "ts": time.time(),
            "type": "request",
            "method": req.method,
            "url": req.pretty_url,
            "req_headers": dict(req.headers),
            "req_body": req.get_text(strict=False),
        }

    def response(self, flow):
        if flow.metadata.get("skip"):
            return
        resp = flow.response
        rec = flow.metadata.get("rec", {})
        rec.update({
            "resp_status": resp.status_code if resp else None,
            "resp_headers": dict(resp.headers) if resp else {},
            "resp_body": resp.get_text(strict=False) if resp else None,
        })
        if self.out:
            self.out.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
            self.out.flush()

    def done(self):
        if self.out:
            try:
                self.out.close()
            except Exception:
                pass


addon = ProcL7Addon()
