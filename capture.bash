#!/bin/bash

# Check if we're root and re-execute if we're not.
[ `whoami` = root ] || { sudo "$0" "$@"; exit $?; }

# Create capture file
> capture_file.pcap
chmod o=rw capture_file.pcap

# Clean up the installed files if present
rm -drf /home/ubuntu/wireshark/instdir

# Create install folder
mkdir /home/ubuntu/wireshark/instdir

# Start tshark in the background
tshark -i eth0 -w capture_file.pcap &

# Downloading using SteamCDM anonymous login
/usr/games/steamcmd +force_install_dir /home/ubuntu/wireshark/instdir +login anonymous +app_update 90 +quit

# Stop tshark
kill $(pgrep tshark)

# Compress network capture
# gzip capture_file.pcap
