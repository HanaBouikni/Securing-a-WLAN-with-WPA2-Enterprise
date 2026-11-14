#!/usr/bin/env bash
# Kali (192.168.100.60): install and start hostapd as wired 802.1X authenticator
set -e
sudo apt update && sudo apt install -y hostapd tcpdump
sudo cp "$(dirname "$0")/../configs/hostapd.conf" /etc/hostapd/hostapd.conf

ping -c 2 192.168.100.30          # NPS must be reachable

sudo pkill hostapd || true
sudo hostapd -dd /etc/hostapd/hostapd.conf
# In another terminal:
#   sudo tcpdump -ni eth0 ether proto 0x888e -vv                 # EAPOL
#   sudo tcpdump -ni eth0 host 192.168.100.30 and udp port 1812  # RADIUS
