# Rapid7 Linux BPFDoor Detection Script

A robust script designed to detect both "classic" and modern variants of the **BPFDoor** stealthy backdoor. 

BPFDoor is a sophisticated Linux malware that utilizes BPF (Berkeley Packet Filters) to sniff network traffic, bypass local firewalls, and execute commands without opening traditional bound ports. This script employs multiple heuristic, network, and memory-based checks to hunt down active infections and persistence mechanisms.

## 🎥 Video Demo



https://github.com/user-attachments/assets/27d2f688-12ed-4e30-8dc9-af3f6c3b5375





---

## Main Detection Techniques

This script runs a 12-step deep triage against the live system, looking for the specific operational quirks of BPFDoor:

* **Process Masquerading (Whitelist Verified):** BPFDoor hides by renaming itself to look like standard Linux daemons (e.g., `/sbin/agetty`, `/usr/sbin/smartd`). The script maps suspicious process names to their *actual* physical executable paths to catch spoofing.
* **BPF Filter & Socket Inspection:** Uses `ss -0pb` and `/proc/net/packet` forensics to hunt for raw/packet sockets (SOCK_RAW / SOCK_DGRAM) and specific Little-Endian BPF magic byte patterns used by the malware to filter traffic.
* **Kernel Stack Tracing:** Scans `/proc/*/stack` to find stealthy processes indefinitely blocking on `packet_recvmsg` or `wait_for_more_packets`—a classic indicator of a raw socket sniffer.
* **Environment Variable Signatures:** Checks `/proc/*/environ` for specific variables hardcoded into BPFDoor's interactive shells, such as `HOME=/tmp` combined with `HISTFILE=/dev/null`.
* **Memory-Resident (Fileless) Execution:** Inspects processes executing from deleted binaries (`(deleted)` tags in `/proc/*/exe`) to catch memory-loaded instances.
* **Lock/Mutex File Analysis:** Scans `/var/run` for zero-byte `.pid` or `.lock` files with `644` permissions matching known BPFDoor mutex lists.
* **Deep Binary Scanning:** Hexdumps mapped memory regions and candidate binaries to search for UPX packing, known C2 strings, and process-specific signatures (e.g., `66666666H`, `ttcompat`).
* **Active C2 & Historical Port Checks:** Looks for established connections to known malicious domains and checks for binds on historical BPFDoor ports (42391–43390, 8000).
* **Persistence Triage:** Scans `/etc/sysconfig`, `cron`, `systemd`, and `rc` scripts for suspicious auto-start hooks and `iptables` manipulation.

## Usage Instructions

The script requires `root` privileges to access raw sockets, process memory maps, and kernel stacks. 

```bash
# Make the script executable
chmod +x bpfdoor_detector.sh

# Run as root
sudo ./bpfdoor_detector.sh


