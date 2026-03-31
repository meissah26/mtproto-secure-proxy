#!/usr/bin/env python3
"""
MTG Monitoring Dashboard
Access: http://host:9090/dashboard/<SECRET>
"""

import asyncio
import os
import re
import subprocess
import time
from pathlib import Path

from aiohttp import web, ClientSession

DASHBOARD_SECRET = os.environ.get("DASHBOARD_SECRET", "change-me")
MTG_STATS_URL = os.environ.get("MTG_STATS_URL", "http://10.77.0.20:3129/")
SERVER_PORT = int(os.environ.get("SERVER_PORT", "9090"))

geo_cache: dict[str, str] = {}


async def fetch_mtg_stats() -> dict:
    try:
        async with ClientSession() as session:
            async with session.get(MTG_STATS_URL, timeout=5) as resp:
                if resp.status == 200:
                    return parse_prometheus(await resp.text())
    except Exception as e:
        return {"error": str(e)}
    return {}


def parse_prometheus(text: str) -> dict:
    r = {
        "client_connections": 0, "telegram_connections": 0,
        "domain_fronting_count": 0, "domain_fronting_connections": 0,
        "replay_attacks": 0, "concurrency_limited": 0,
        "traffic_from_client": 0, "traffic_to_client": 0,
        "tg_traffic_from_client": 0, "tg_traffic_to_client": 0,
        "telegram_dcs": {},
    }
    for line in text.strip().split("\n"):
        if line.startswith("#"):
            continue
        m = re.match(r'mtg_client_connections\{.*\}\s+([\d.]+)', line)
        if m: r["client_connections"] += int(float(m.group(1))); continue
        m = re.match(r'mtg_telegram_connections\{dc="(\d+)".*\}\s+([\d.]+)', line)
        if m:
            dc, cnt = m.group(1), int(float(m.group(2)))
            r["telegram_connections"] += cnt
            r["telegram_dcs"][f"DC{dc}"] = r["telegram_dcs"].get(f"DC{dc}", 0) + cnt
            continue
        m = re.match(r'mtg_domain_fronting\s+([\d.]+)', line)
        if m: r["domain_fronting_count"] = int(float(m.group(1))); continue
        m = re.match(r'mtg_domain_fronting_connections\{.*\}\s+([\d.]+)', line)
        if m: r["domain_fronting_connections"] += int(float(m.group(1))); continue
        m = re.match(r'mtg_replay_attacks\s+([\d.]+)', line)
        if m: r["replay_attacks"] = int(float(m.group(1))); continue
        m = re.match(r'mtg_concurrency_limited\s+([\d.]+)', line)
        if m: r["concurrency_limited"] = int(float(m.group(1))); continue
        m = re.match(r'mtg_domain_fronting_traffic\{direction="from_client"\}\s+([\d.]+)', line)
        if m: r["traffic_from_client"] = int(float(m.group(1))); continue
        m = re.match(r'mtg_domain_fronting_traffic\{direction="to_client"\}\s+([\d.]+)', line)
        if m: r["traffic_to_client"] = int(float(m.group(1))); continue
        m = re.match(r'mtg_telegram_traffic\{.*direction="from_client".*\}\s+([\d.]+)', line)
        if m: r["tg_traffic_from_client"] += int(float(m.group(1))); continue
        m = re.match(r'mtg_telegram_traffic\{.*direction="to_client".*\}\s+([\d.]+)', line)
        if m: r["tg_traffic_to_client"] += int(float(m.group(1))); continue
    return r


async def get_system_stats() -> dict:
    s = {}
    try:
        with open("/proc/stat") as f:
            c = f.readline().split()
        total = sum(int(x) for x in c[1:])
        s["cpu_usage_pct"] = round((1 - int(c[4]) / max(total, 1)) * 100, 1)
    except: s["cpu_usage_pct"] = 0
    try:
        mi = {}
        with open("/proc/meminfo") as f:
            for l in f:
                p = l.split(":")
                if len(p) == 2: mi[p[0].strip()] = int(p[1].strip().split()[0])
        t, a = mi.get("MemTotal", 1), mi.get("MemAvailable", 0)
        s["mem_total_mb"] = round(t/1024)
        s["mem_used_mb"] = round((t-a)/1024)
        s["mem_usage_pct"] = round((t-a)/max(t,1)*100, 1)
    except: s["mem_total_mb"]=s["mem_used_mb"]=0; s["mem_usage_pct"]=0
    try:
        st = os.statvfs("/")
        tg = (st.f_blocks*st.f_frsize)/(1024**3)
        ug = tg - (st.f_bavail*st.f_frsize)/(1024**3)
        s["disk_total_gb"]=round(tg,1); s["disk_used_gb"]=round(ug,1)
        s["disk_usage_pct"]=round(ug/max(tg,.1)*100,1)
    except: s["disk_total_gb"]=s["disk_used_gb"]=0; s["disk_usage_pct"]=0
    try:
        with open("/proc/loadavg") as f: p=f.read().split()
        s["load_1m"]=float(p[0]); s["load_5m"]=float(p[1]); s["load_15m"]=float(p[2])
    except: s["load_1m"]=s["load_5m"]=s["load_15m"]=0
    try:
        with open("/proc/uptime") as f: u=float(f.read().split()[0])
        d,rem=divmod(int(u),86400); h,rem=divmod(rem,3600); m,_=divmod(rem,60)
        s["uptime"]=f"{d}d {h}h {m}m"
    except: s["uptime"]="N/A"
    return s


async def resolve_country(ip: str) -> str:
    if ip in geo_cache:
        return geo_cache[ip]
    try:
        async with ClientSession() as session:
            async with session.get(
                f"http://ip-api.com/json/{ip}?fields=country,countryCode",
                timeout=3
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    country = data.get("country", "Unknown")
                    geo_cache[ip] = country
                    return country
    except: pass
    geo_cache[ip] = "Unknown"
    return "Unknown"


async def get_connections_info() -> dict:
    """Get real client IPs from conntrack (sees through Docker NAT)."""
    countries: dict[str, int] = {}
    total = 0
    client_ips: list[str] = []

    try:
        # Parse conntrack for ESTABLISHED connections to port 443
        result = subprocess.run(
            ["conntrack", "-L", "-p", "tcp", "--dport", "443"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split("\n"):
            if not line or "ESTABLISHED" not in line:
                continue
            # Extract source IP: src=x.x.x.x before first dst=
            m = re.search(r'src=([\d.]+)\s+dst=', line)
            if not m:
                continue
            ip = m.group(1)
            # Skip internal IPs
            if ip.startswith(("127.", "10.", "172.", "192.168.", "0.")):
                continue
            total += 1
            client_ips.append(ip)
    except Exception:
        pass

    # Resolve unique IPs to countries (limit batch to avoid rate-limits)
    unique_ips = list(set(client_ips))

    # Batch resolve via ip-api.com (supports up to 100 per batch)
    unresolved = [ip for ip in unique_ips[:100] if ip not in geo_cache]
    if unresolved:
        try:
            async with ClientSession() as session:
                # ip-api.com batch endpoint
                async with session.post(
                    "http://ip-api.com/batch?fields=query,country",
                    json=[{"query": ip} for ip in unresolved[:100]],
                    timeout=5
                ) as resp:
                    if resp.status == 200:
                        results = await resp.json()
                        for r in results:
                            if isinstance(r, dict):
                                geo_cache[r.get("query", "")] = r.get("country", "Unknown")
        except Exception:
            # Fallback to individual lookups
            for ip in unresolved[:20]:
                await resolve_country(ip)

    # Count unique users (unique IPs) per country
    unique_client_ips = set(client_ips)
    for ip in unique_client_ips:
        country = geo_cache.get(ip, "Unknown")
        countries[country] = countries.get(country, 0) + 1

    return {
        "total_connections": total,
        "unique_users": len(unique_client_ips),
        "countries": dict(sorted(countries.items(), key=lambda x: -x[1]))
    }


async def handle_dashboard(request: web.Request) -> web.Response:
    if request.match_info.get("secret", "") != DASHBOARD_SECRET:
        return web.Response(text="404 Not Found", status=404)
    t = (Path(__file__).parent / "templates" / "dashboard.html").read_text()
    return web.Response(text=t.replace("{{DASHBOARD_SECRET}}", DASHBOARD_SECRET), content_type="text/html")


async def handle_api_stats(request: web.Request) -> web.Response:
    if request.match_info.get("secret", "") != DASHBOARD_SECRET:
        return web.json_response({"error": "forbidden"}, status=403)
    mtg, sys, conn = await asyncio.gather(
        fetch_mtg_stats(), get_system_stats(), get_connections_info()
    )
    return web.json_response({"timestamp": int(time.time()), "mtg": mtg, "system": sys, "connections": conn})


async def handle_rotate_secret(request: web.Request) -> web.Response:
    """Generate new mtg FakeTLS secret, update config, restart mtg."""
    if request.match_info.get("secret", "") != DASHBOARD_SECRET:
        return web.json_response({"error": "forbidden"}, status=403)

    try:
        # 1. Generate new secret
        gen = subprocess.run(
            ["docker", "run", "--rm", "nineseconds/mtg:2", "generate-secret", "www.microsoft.com"],
            capture_output=True, text=True, timeout=30
        )
        new_secret = gen.stdout.strip()
        if not new_secret or gen.returncode != 0:
            return web.json_response({"error": "Failed to generate secret", "details": gen.stderr}, status=500)

        # 2. Read current config, replace secret
        config_path = "/opt/mtproto-proxy/mtg-config.toml"
        with open(config_path) as f:
            config = f.read()

        old_secret_match = re.search(r'secret\s*=\s*"([^"]+)"', config)
        old_secret = old_secret_match.group(1) if old_secret_match else "unknown"
        config = re.sub(r'secret\s*=\s*"[^"]+"', f'secret = "{new_secret}"', config)

        with open(config_path, "w") as f:
            f.write(config)

        # 3. Restart mtg container
        restart = subprocess.run(
            ["docker", "compose", "-f", "/opt/mtproto-proxy/docker-compose.yml", "restart", "mtg"],
            capture_output=True, text=True, timeout=30
        )

        # 4. Compute hex link
        import base64
        s = new_secret.replace('-', '+').replace('_', '/')
        s += '=' * (4 - len(s) % 4)
        hex_secret = base64.b64decode(s).hex()

        server_ip = "138.124.4.34"
        tg_link = f"tg://proxy?server={server_ip}&port=443&secret={hex_secret}"

        return web.json_response({
            "success": True,
            "old_secret": old_secret[:12] + "...",
            "new_secret": new_secret[:12] + "...",
            "tg_link": tg_link,
            "restart_ok": restart.returncode == 0
        })
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


app = web.Application()
app.router.add_get("/dashboard/{secret}", handle_dashboard)
app.router.add_get("/api/stats/{secret}", handle_api_stats)
app.router.add_post("/api/rotate/{secret}", handle_rotate_secret)
app.router.add_get("/health", lambda r: web.Response(text="ok"))

if __name__ == "__main__":
    print(f"[*] Dashboard: http://localhost:{SERVER_PORT}/dashboard/{DASHBOARD_SECRET}")
    web.run_app(app, host="0.0.0.0", port=SERVER_PORT, print=None)
