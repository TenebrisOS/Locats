#!/usr/bin/env python3
import os
import sys
import subprocess
import threading
import time
import json
from scapy.all import sniff, Dot11

# === CONFIG ===
IFACE = "wlan0"             # your wireless interface
CHANNELS = range(1, 14)     # 2.4 GHz channels
HOP_INTERVAL = 0.3          # seconds per channel
REFRESH_INTERVAL = 1        # seconds between table refresh
KNOWN_FILE = "known_devices.json"   # JSON file with known devices

# === GLOBAL DATA ===
access_points = {}       # bssid -> ssid
clients = {}             # client_mac -> ap_bssid
known_clients = {}
known_aps = {}
lock = threading.Lock()

# ANSI colors
COLOR_RESET = "\033[0m"
COLOR_CLIENT = "\033[92m"  # Green
COLOR_AP = "\033[96m"      # Cyan

# --- Load known devices from JSON ---
def load_known():
    global known_clients, known_aps
    try:
        with open(KNOWN_FILE, "r") as f:
            data = json.load(f)
            known_clients = {k.lower(): v for k, v in data.get("clients", {}).items()}
            known_aps = {k.lower(): v for k, v in data.get("aps", {}).items()}
        print(f"[+] Loaded {len(known_clients)} known clients and {len(known_aps)} known APs")
    except Exception as e:
        print(f"[!] Could not load {KNOWN_FILE}: {e}")

# --- Interface mode helpers ---
def start_monitor_mode(iface):
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"])
    subprocess.run(["sudo", "iw", iface, "set", "monitor", "control"])
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"])

def stop_monitor_mode(iface):
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"])
    subprocess.run(["sudo", "iw", iface, "set", "type", "managed"])
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"])

# --- Channel hopper ---
def channel_hopper():
    while True:
        for ch in CHANNELS:
            subprocess.run(["iw", "dev", IFACE, "set", "channel", str(ch)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(HOP_INTERVAL)

# --- Packet parser ---
def packet_handler(pkt):
    if not pkt.haslayer(Dot11):
        return
    with lock:
        # Access Points (Beacon frames)
        if pkt.type == 0 and pkt.subtype == 8:
            bssid = pkt.addr2.lower()
            ssid = pkt.info.decode(errors="ignore") if pkt.info else "<hidden>"
            access_points[bssid] = ssid

        # Clients (Probe requests — no AP yet)
        elif pkt.type == 0 and pkt.subtype == 4:
            client = pkt.addr2.lower()
            if client and client not in clients:
                clients[client] = None

        # Association / authentication requests
        elif pkt.type == 0 and pkt.subtype in [0, 2, 11]:
            client = pkt.addr2.lower()
            ap = pkt.addr1.lower()
            if client and ap:
                clients[client] = ap

        # Data frames (client <-> AP traffic)
        elif pkt.type == 2:
            client = pkt.addr2.lower()
            ap = pkt.addr1.lower()
            if client and ap:
                clients[client] = ap

# --- Printer thread ---
def printer():
    while True:
        time.sleep(REFRESH_INTERVAL)
        with lock:
            os.system("clear")
            print("=== Detected Access Points ===")
            for bssid, ssid in access_points.items():
                if bssid in known_aps:
                    tag = f"{COLOR_AP}[*{known_aps[bssid]}*]{COLOR_RESET}"
                else:
                    tag = ""
                print(f"SSID: {ssid:<20} BSSID: {bssid}{tag}")

            print("\n=== Detected Clients ===")
            for client, ap in clients.items():
                client_tag = f"{COLOR_CLIENT}[*{known_clients[client]}*]{COLOR_RESET}" if client in known_clients else ""
                if ap in access_points:
                    ap_name = access_points[ap]
                    ap_tag = f"{COLOR_AP}[*{known_aps[ap]}*]{COLOR_RESET}" if ap in known_aps else ""
                    print(f"Client: {client}{client_tag} --> AP: {ap_name} ({ap}){ap_tag}")
                elif ap:
                    ap_tag = f"{COLOR_AP}[*{known_aps[ap]}*]{COLOR_RESET}" if ap in known_aps else ""
                    print(f"Client: {client}{client_tag} --> AP: {ap}{ap_tag}")
                else:
                    print(f"Client: {client}{client_tag} --> [Not associated]")

# --- Main ---
def main():
    try:
        load_known()
        print("[+] Enabling monitor mode...")
        start_monitor_mode(IFACE)

        print("[+] Starting channel hopper...")
        threading.Thread(target=channel_hopper, daemon=True).start()

        print("[+] Starting printer...")
        threading.Thread(target=printer, daemon=True).start()

        print("[*] Sniffing... (Ctrl+C to stop)")
        sniff(iface=IFACE, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n[!] Stopping...")
    finally:
        print("[+] Restoring interface to managed mode...")
        stop_monitor_mode(IFACE)

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("[-] Run this script as root (sudo).")
    main()
