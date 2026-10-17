"""
proc-sniffer-mcp — 将「按进程名抓本机报文」封装为 MCP Server (stdio)

供 Claude Desktop / Cursor / 任意支持 MCP 的客户端调用。
运行(需管理员): python server.py
"""
import psutil
from fastmcp import FastMCP
from proc_sniffer import ProcSniffer, L7_PROXY_PORT

mcp = FastMCP("proc-sniffer-mcp")
sniffer = ProcSniffer()


@mcp.tool
def list_monitorable_apps() -> list[str]:
    """列出当前有网络连接的进程名(可监控的软件列表)"""
    names: set[str] = set()
    for c in psutil.net_connections(kind="inet"):
        if c.pid:
            try:
                names.add(psutil.Process(c.pid).name())
            except Exception:
                pass
    return sorted(names)


@mcp.tool
def start_capture(app_name: str, duration: int = 30, layers: str = "full") -> str:
    """解析软件名对应 PID 并启动本机抓取。layers: l3(报文)/l7(HTTP明文,需走代理)/full(两者,默认)。需管理员。L7 需目标走代理 127.0.0.1:8080。"""
    pids = sniffer.resolve_pids(app_name)
    if not pids:
        return f"未找到匹配 '{app_name}' 的进程, 可用 list_monitorable_apps() 查看"
    sniffer.start_capture(pids, duration=duration, layers=layers)
    return f"已为 PID={pids} 启动抓取({layers}), {duration}s 后自动停止"


@mcp.tool
def stop_capture() -> str:
    """手动停止抓取(若未用 duration 自动停止), 转换+按进程过滤+L7落盘"""
    r = sniffer.stop_capture()
    return f"已停止并过滤: {r}" if r else "当前未处于抓取状态"


@mcp.tool
def export_last(app_name: str) -> dict:
    """导出最近一次结果为 requests.json / index.md / filtered.pcap / http_traffic.jsonl"""
    pids = sniffer.resolve_pids(app_name)
    return sniffer.export(app_name, pids)


if __name__ == "__main__":
    mcp.run()  # 默认 stdio 传输
