#!/usr/bin/env python3

import asyncio
import re

service_plugins = {}

def register_plugin(port, plugin_func):
    service_plugins[port] = plugin_func

async def detect_http(reader, writer):
    try:
        http_request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        writer.write(http_request.encode())
        await writer.drain()

        data = await asyncio.wait_for(reader.read(4096), timeout=1)
        response = data.decode('utf-8', errors='ignore')

        match = re.search(r'Server: (.+)', response)
        if match:
            server_info = match.group(1).strip()
            return f"HTTP Server: {server_info}"
        else:
            return "HTTP Service Detected"
    except Exception:
        return "HTTP Service Detected (No detailed info)"

async def detect_ftp(reader, writer):
    try:
        data = await asyncio.wait_for(reader.read(4096), timeout=1)
        banner = data.decode('utf-8', errors='ignore').strip()
        return f"FTP Banner: {banner}"
    except Exception:
        return "FTP Service Detected (No banner)"

async def detect_ssh(reader, writer):
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=1)
        banner = data.decode('utf-8', errors='ignore').strip()
        return f"SSH Banner: {banner}"
    except Exception:
        return "SSH Service Detected (No banner)"

async def detect_smtp(reader, writer):
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=1)
        banner = data.decode('utf-8', errors='ignore').strip()
        return f"SMTP Banner: {banner}"
    except Exception:
        return "SMTP Service Detected (No banner)"

async def detect_rdp(reader, writer):
    try:

        rdp_request = b'\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00'
        writer.write(rdp_request)
        await writer.drain()

        data = await asyncio.wait_for(reader.read(1024), timeout=1)
        if data:
            return "RDP Service Detected"
        else:
            return "No response from RDP service"
    except Exception:
        return "RDP Service Detected (No detailed info)"

register_plugin(21, detect_ftp)
register_plugin(22, detect_ssh)
register_plugin(25, detect_smtp)
register_plugin(80, detect_http)
register_plugin(3389, detect_rdp)
