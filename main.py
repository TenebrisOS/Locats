#!/usr/bin/env python3
import os
import sys
import subprocess
import threading
import time
import json
from scapy.all import sniff, Dot11

# === CONFIG ===
IFACE = "wlan0"
CHANNELS = range(1, 14)
HOP_INTERVAL = 2
REFRESH_INTERVAL = 1
KNOWN_FILE = "known_devices.json"

# === GLOBAL DATA ===
access_points = {}   # bssid -> ssid
clients = {}         # client_mac -> ap_mac
known_clients = {}
known_aps = {}       # ssid -> [bssids]
lock = threading.Lock()

# === COLORS ===
COLOR_RESET = "\033[0m"
COLOR_CLIENT = "\033[92m"
COLOR_AP = "\033[96m"

# --- Normalize MAC for half-match ---
def mac_prefix(mac, half=True):
    mac = mac.lower()
    if half:
        return ":".join(mac.split(":")[:3])  # first 3 bytes (OUI)
    return mac

# --- Load known devices ---
def load_known():
    global known_clients, known_aps
    try:
        with open(KNOWN_FILE, "r") as f:
            data = json.load(f)

            known_clients.clear()
            known_aps.clear()

            # Load clients from AP groups
            for ap_name, entries in data.items():
                if ap_name == "aps":
                    continue
                if isinstance(entries, dict):  # client list under AP name
                    for client_mac, client_name in entries.items():
                        known_clients[client_mac.lower()] = client_name

            # Load APs with their BSSIDs
            for ap_name, macs in data.get("aps", {}).items():
                prefixes = [mac_prefix(m) for m in macs]
                known_aps[ap_name] = prefixes

        print(f"[+] Loaded {len(known_clients)} known clients and {len(known_aps)} APs (half-MAC prefixes)")

    except Exception as e:
        print(f"[!] Could not load {KNOWN_FILE}: {e}")


# --- Monitor mode helpers ---
def start_monitor_mode(iface):
    print(f"[+] Enabling monitor mode on {iface}...")
    subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["airmon-ng", "start", iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def stop_monitor_mode(iface):
    print(f"[+] Restoring {iface} to managed mode...")
    subprocess.run(["airmon-ng", "stop", iface + "mon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["service", "NetworkManager", "restart"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# --- Channel hopper ---
def channel_hopper(iface):
    while True:
        for ch in CHANNELS:
            subprocess.run(["iw", "dev", iface + "mon", "set", "channel", str(ch)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(HOP_INTERVAL)

# --- Packet handler ---
def packet_handler(pkt):
    if not pkt.haslayer(Dot11):
        return
    with lock:
        if pkt.type == 0 and pkt.subtype == 8:  # beacon
            bssid = pkt.addr2.lower()
            ssid = pkt.info.decode(errors="ignore") if pkt.info else "<hidden>"
            access_points[bssid] = ssid

        elif pkt.type == 0 and pkt.subtype == 4:  # probe
            client = pkt.addr2.lower()
            clients.setdefault(client, None)

        elif pkt.type == 0 and pkt.subtype in [0, 2, 11]:  # assoc/auth
            client = pkt.addr2.lower()
            ap = pkt.addr1.lower()
            if client and ap:
                clients[client] = ap

        elif pkt.type == 2:  # data
            to_ds = pkt.FCfield & 0x1 != 0
            from_ds = pkt.FCfield & 0x2 != 0
            if not to_ds and from_ds:
                ap = pkt.addr2.lower()
                client = pkt.addr1.lower()
            elif to_ds and not from_ds:
                client = pkt.addr2.lower()
                ap = pkt.addr1.lower()
            else:
                return
            if client and ap:
                clients[client] = ap

# --- Printer ---
def printer():
    while True:
        time.sleep(REFRESH_INTERVAL)
        with lock:
            os.system("clear")
            print("=== Detected Cat Owners ===")
            for bssid, ssid in access_points.items():
                tag = ""
                for ssid_name, prefix_list in known_aps.items():
                    if mac_prefix(bssid) in prefix_list:
                        tag = f"{COLOR_AP}[*{ssid_name}*]{COLOR_RESET}"
                        break
                print(f"{bssid} ({ssid}) {tag}")

            print("\n=== Detected Cats ===")
            for client, ap in clients.items():
                ctag = f"{COLOR_CLIENT}[*{known_clients[client]}*]{COLOR_RESET}" if client in known_clients else ""
                if ap in access_points:
                    ssid = access_points[ap]
                    atag = ""
                    for ssid_name, prefix_list in known_aps.items():
                        if mac_prefix(ap) in prefix_list:
                            atag = f"{COLOR_AP}[*{ssid_name}*]{COLOR_RESET}"
                            break
                    print(f"{client}{ctag} --> {ssid} ({ap}) {atag}")
                elif ap:
                    print(f"{client}{ctag} --> {ap}")
                else:
                    print(f"{client}{ctag} --> [Not associated]")

# --- Main ---
def main():
    try:
        load_known()
        start_monitor_mode(IFACE)
        threading.Thread(target=channel_hopper, args=(IFACE,), daemon=True).start()
        threading.Thread(target=printer, daemon=True).start()
        sniff(iface=IFACE+"mon", prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n[!] Stopping...")
    finally:
        stop_monitor_mode(IFACE)

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("[-] Run as root (sudo).")
    n = len(sys.argv)
    if n == 2:
        IFACE = sys.argv[1]
    elif n > 2:
        sys.exit(f"[-] Usage: {sys.argv[0]} [interface]")
    main()
