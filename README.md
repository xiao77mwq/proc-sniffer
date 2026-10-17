# proc-sniffer

Capture **one process's network traffic** on Windows — by process name, not by interface.

Wireshark on Windows cannot filter by process: capture happens below the socket layer, so packets carry no process semantics. `proc-sniffer` solves that by driving **`pktmon`** (built into Windows 10 1809+, records the PID natively at capture time), converting the ETL to pcapng, and filtering by PID — with an optional **mitmproxy** L7 layer that maps source port → PID to dump plaintext HTTP(S) for the target process only.

Ships as both a CLI and an **MCP server**, so an LLM agent can capture, stop and export traffic in one conversation.

```
process name --psutil--> PID / local ports
  L3/L4: pktmon (captures with PID) --> ETL --etl2pcapng--> pcapng --filter by PID--> filtered.pcap
  L7   : mitmproxy (proxy, filter by src port -> PID) --> http_traffic.jsonl
  export: requests.json / index.md / filtered.pcap / http_traffic.jsonl
```

## Two layers

| Layer | Tech | Output | Notes |
|-------|------|--------|-------|
| L3/L4 | `pktmon` full capture (PID-tagged) → `etl2pcapng` → filter by PID/port | `filtered.pcap` + `requests.json` (connection list) | Connection map + raw packets. No decryption. |
| L7 | `mitmproxy` forward proxy, filtered by src-port → PID | `http_traffic.jsonl` (plaintext HTTP req/resp) | Target must use the proxy and trust the mitmproxy CA. |

The `layers` argument picks a layer: `l3` / `l7` / `full` (default: both).

## Requirements

- Windows 10 1809+ (`pktmon` is built in)
- **Administrator** shell (packet capture + reading all processes' connections)
- Python 3.10+
- Optional: Wireshark, for exact PID filtering via `tshark`'s `_ws.process.id` metadata.
  Without it, filtering falls back to a port map sampled during capture.

## Install

```bash
pip install -r requirements.txt
```

Optionally drop `etl2pcapng.exe` at `C:\tools\etl2pcapng.exe`
(<https://github.com/microsoft/etl2pcapng/releases>) — otherwise the tool uses
`pktmon etl2pcap`, which is built in.

Configuration is by environment variable, so nothing is hardcoded to one machine:

| Variable | Default | Meaning |
|---|---|---|
| `PROC_SNIFFER_WORKDIR` | `~/proc_sniffer_caps` | Where captures and exports go |
| `PROC_SNIFFER_ETL2PCAPNG` | `C:\tools\etl2pcapng.exe` | Path to `etl2pcapng.exe` |
| `PROC_SNIFFER_TSHARK` | `C:\Program Files\Wireshark\tshark.exe` | Path to `tshark.exe` |
| `PROC_SNIFFER_L7_PORT` | `8080` | mitmproxy listen port |

## CLI

In an **administrator** terminal:

```bash
# L3/L4 + L7, capture "chrome" for 30 seconds
python proc_sniffer.py chrome 30 full

# L3/L4 only
python proc_sniffer.py chrome 30 l3

# L7 only (the target must use the 127.0.0.1:8080 proxy)
python proc_sniffer.py chrome 30 l7
```

Output lands in `%PROC_SNIFFER_WORKDIR%\exports\<app_name>\`:

- `requests.json` / `index.md` — L3/L4 connection list
- `filtered.pcap` — packets belonging to the process, openable in Wireshark
- `http_traffic.jsonl` — L7 plaintext, one `{method,url,req_*,resp_*}` per line

Start the capture first, then perform the action in the app you want to observe.

## L7 notes

1. **Route the target through the proxy** — set the system proxy to `127.0.0.1:8080`, or
   set `HTTP_PROXY` / `HTTPS_PROXY` before launching the process.
2. **Trust the mitmproxy CA** — the first run writes `~/.mitmproxy/mitmproxy-ca-cert.p12`;
   import it into *Trusted Root Certification Authorities* or HTTPS will be refused.
3. **Certificate pinning** — if the target pins its certificate, L7 decryption fails and
   mitmproxy cannot help. That needs a Frida hook, which is outside this tool's scope.

## As an MCP server

Run as administrator:

```bash
python server.py
```

Client config (stdio):

```json
{
  "mcpServers": {
    "proc-sniffer": {
      "command": "python",
      "args": ["C:/path/to/proc-sniffer/server.py"]
    }
  }
}
```

Tools:

| Tool | Purpose |
|------|---------|
| `list_monitorable_apps()` | Process names that currently have network connections |
| `start_capture(app_name, duration, layers)` | Resolve PIDs and start capture (`l3`/`l7`/`full`) |
| `stop_capture()` | Stop, convert, filter by process, flush L7 |
| `export_last(app_name)` | Export the last capture to JSON / pcap / index / jsonl |

Example prompt:
> "Capture `chrome` for 30 seconds in full mode, export every outbound request including
> plaintext HTTP, and list which domains/IPs it connected to."

## Need a custom capture?

If you need this adapted to a specific application — a connection inventory, an API
endpoint map, or a reproducible capture script for your team — I take paid custom work.

**Scope:** software you own or are authorized to analyze. I do not take work that
captures third-party traffic without permission.

**Contact:** open an issue with `[custom]` in the title, or email
[2515196022@qq.com](mailto:2515196022@qq.com?subject=%5Bcustom%20capture%5D).

## Limitations

- **L3/L4 does not decrypt HTTPS** — you get encrypted TLS bytes, not request bodies.
- **PID filter precision** — with Wireshark installed, filtering uses `_ws.process.id`
  metadata. Without it, a 1-second port sampler covers new connections; in rare cases
  short-lived connections can be missed.
- **L7 needs the proxy** — traffic that bypasses `127.0.0.1:8080` (direct QUIC/UDP, for
  example) is invisible to the L7 layer, though L3/L4 still sees it.
- **Pinning** — as above, requires Frida.
- **Private protocols** — if the app speaks QUIC or a binary protocol, L3/L4 gives you
  packets but you still need to reverse the format yourself.

## Legal / ethical use

This tool captures traffic from software running on **your own machine**. Use it on
software you own or are authorized to analyze, for interoperability, debugging, security
research or learning. Capturing other people's traffic, or the traffic of services you
have no right to inspect, may violate law and terms of service in your jurisdiction.
No warranty — see [LICENSE](LICENSE).

## License

MIT.
