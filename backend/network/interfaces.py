"""
Network Interface Discovery & Capture Capability Detector for Windows.
Safely detects available physical, virtual, and loopback network adapters
and reports whether live packet capture (Npcap/Scapy) is available.
"""
import os
import socket
import logging
import psutil

# Suppress scapy warning when libpcap is not installed
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from backend.utils.logger import get_logger

logger = get_logger(__name__)


def check_capture_capability() -> dict:
    """
    Check if the current system environment can capture live packets.
    Returns:
        {
            "available": bool,
            "driver": "Npcap" | "WinPcap" | "RawSocket" | "None",
            "message": str,
            "install_guide": str or None
        }
    """
    # 1. Check for Npcap / WinPcap installation on Windows
    npcap_paths = [
        r"C:\Windows\System32\Npcap\wpcap.dll",
        r"C:\Program Files\Npcap\wpcap.dll",
        r"C:\Windows\System32\wpcap.dll",
    ]
    npcap_found = any(os.path.exists(p) for p in npcap_paths)

    # 2. Check Scapy capability
    scapy_pcap = False
    try:
        from scapy.config import conf
        scapy_pcap = getattr(conf, "use_pcap", False)
    except Exception:
        scapy_pcap = False

    if npcap_found or scapy_pcap:
        return {
            "available": True,
            "driver": "Npcap" if npcap_found else "WinPcap",
            "message": "Packet capture driver is ready and operational.",
            "install_guide": None,
        }

    # 3. Check if raw sockets work (e.g. if process is elevated as Administrator)
    raw_socket_works = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.close()
        raw_socket_works = True
    except Exception:
        raw_socket_works = False

    if raw_socket_works:
        return {
            "available": True,
            "driver": "RawSocket",
            "message": "Raw socket capture available (running with administrative privileges).",
            "install_guide": None,
        }

    # If neither Npcap nor Administrator raw sockets are available
    return {
        "available": False,
        "driver": "None",
        "message": (
            "Live packet capture is unavailable. On Windows, packet capture requires the "
            "Npcap driver or administrator privileges."
        ),
        "install_guide": (
            "Please download and install Npcap from https://npcap.com (choose 'Install Npcap "
            "in WinPcap API-compatible Mode') or run your terminal as Administrator, then restart."
        ),
    }


def get_network_interfaces() -> list:
    """
    Discover all network interfaces on the machine.
    Returns a list of clean interface dicts.
    """
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    # Try mapping friendly names to Scapy interfaces if available
    scapy_ifaces = {}
    try:
        from scapy.arch.windows import get_windows_if_list
        for item in get_windows_if_list():
            scapy_ifaces[item.get("name", "")] = item
            scapy_ifaces[item.get("description", "")] = item
    except Exception:
        pass

    for iface_name, addr_list in addrs.items():
        ipv4 = "N/A"
        mac = "N/A"
        netmask = "N/A"

        for addr in addr_list:
            # AF_INET = 2 (IPv4)
            if addr.family == socket.AF_INET or str(addr.family) in ("2", "AddressFamily.AF_INET"):
                ipv4 = addr.address
                netmask = addr.netmask or "N/A"
            # MAC address (family -1 or psutil.AF_LINK)
            elif str(addr.family) in ("-1", "AddressFamily.AF_LINK") and not mac != "N/A":
                mac = addr.address

        iface_stat = stats.get(iface_name)
        is_up = iface_stat.isup if iface_stat else False
        speed = iface_stat.speed if iface_stat else 0

        # Determine description
        scapy_match = scapy_ifaces.get(iface_name)
        description = scapy_match.get("description", iface_name) if scapy_match else iface_name
        guid = scapy_match.get("guid", "") if scapy_match else ""

        is_loopback = "loopback" in iface_name.lower() or ipv4.startswith("127.")

        interfaces.append({
            "id": iface_name,
            "name": iface_name,
            "description": description,
            "ip": ipv4,
            "mac": mac,
            "netmask": netmask,
            "status": "UP" if is_up else "DOWN",
            "is_up": is_up,
            "speed_mbps": speed,
            "is_loopback": is_loopback,
            "guid": guid,
        })

    # Sort UP interfaces first, then by name
    interfaces.sort(key=lambda x: (not x["is_up"], x["is_loopback"], x["name"]))
    return interfaces
