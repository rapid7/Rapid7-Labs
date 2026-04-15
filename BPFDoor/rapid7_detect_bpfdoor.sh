#!/usr/bin/env bash
#
# Rapid7 Labs / Enhanced – Linux BPFDoor Detection Script
#
# Detects both “classic” and newer BPFDoor variants using:
#   - Known hashes (optional, extendable)
#   - Suspicious mutex/lock files in /var/run
#   - Auto-start hooks in /etc/sysconfig
#   - BPF filter usage via ss -0pb and /proc/net/packet
#   - RAW / packet socket usage (Including SOCK_DGRAM Layer 2 Stripping)
#   - Suspicious env vars (HOME=/tmp, HISTFILE=/dev/null, MYSQL_HISTFILE=/dev/null)
#   - Known masqueraded process names + paths (Verified against Whitelist)
#   - Process-specific Binary Signatures (66666666H, ttcompat, etc.)
#   - Active C2 Reverse Shell Connections
#   - Memory-resident (deleted) binary execution
#   - Kernel Stack Tracing (packet_recvmsg blocking)
#   - Suspicious ports (42391–43390, 8000)
#   - Suspicious strings & UPX packing in candidate binaries
#   - Basic persistence checks (cron, systemd, rc scripts)
#
# Requires: bash, grep, awk, ps, readlink, stat, ss OR netstat, lsof (optional), strings, find, hexdump, dd, dig (optional)
#
# This script is best-effort and may produce false positives. Use results as
# triage input, not as a sole source of truth.

set -o pipefail

VERSION="1.2"
HOSTNAME="$(hostname)"
DATE="$(date +%Y-%m-%d_%H-%M-%S)"
LOGFILE="bpfdoor_report_${HOSTNAME}_${DATE}.log"

# Global script PIDs to exclude from our own checks
SCRIPT_PID=$$
SCRIPT_PPID=$PPID

# ---- Colours ---------------------------------------------------------------
#if [ -t 1 ]; then
RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[1;34m'
CYAN=$'\033[1;36m'
MAGENTA=$'\033[1;35m'
ORANGE=$'\033[38;5;208m'
NC=$'\033[0m'
#else
  #RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; MAGENTA=""; NC=""; ORANGE=""
#fi

# ---- Known malicious hashes (minimal baseline, extend as needed) -----------
declare -A MALWARE_SHA256=()
declare -A MALWARE_MD5=()

# ---- Suspicious names and patterns ----------------------------------------
SUSPICIOUS_MUTEX_FILES=(
  "/var/run/aepmonend.pid" "/var/run/auditd.lock" "/var/run/cma.lock"
  "/var/run/console-kit.pid" "/var/run/consolekit.pid" "/var/run/daemon.pid"
  "/var/run/hald-addon.pid" "/var/run/hald-smartd.pid" "/var/run/hp-health.pid"
  "/var/run/hpasmlit.lock" "/var/run/hpasmlited.pid" "/var/run/lldpad.lock"
  "/var/run/mcelog.pid" "/var/run/system.pid" "/var/run/uvp-srv.pid"
  "/var/run/vmtoolagt.pid" "/var/run/xinetd.lock"
)

# Command-line strings BPFDoor uses to hide
SUSPICIOUS_PROCS=(
  "/sbin/agetty" "/sbin/auditd" "/sbin/mingetty" "/sbin/sgaSolAgent" "/sbin/udevd"
  "/usr/bin/python -Es /usr/sbin/tuned" "/usr/bin/uvp-srv" "/usr/lib/polkit-1/polkitd"
  "/usr/lib/systemd/systemd-journald" "/usr/lib/systemd/systemd-machined"
  "/usr/libexec/hald-addon-volume" "/usr/libexec/postfix/master" "/usr/libexec/rtkit-daemon"
  "/usr/libexec/upowerd" "/usr/sbin/NetworkManager" "/usr/sbin/abrtd" "/usr/sbin/acpid"
  "/usr/sbin/atd" "/usr/sbin/chronyd" "/usr/sbin/console-kit" "/usr/sbin/console-kit-daemon"
  "/usr/sbin/crond" "/usr/sbin/mcelog" "/usr/sbin/rsyslogd" "/usr/sbin/smartd"
  "/usr/sbin/sshd" "[charger_manager]" "[kaluad_sync]" "[scsi_tmf_6]" "[watchdogd]"
  "[cpu/0]" "avahi-daemon: chroot helper" "cmathreshd" "dbus-daemon --system"
  "hald-addon-acpi" "hald-runner" "hpasmlited" "lldpad -d" "nginx: master process"
  "pickup -l -t fifo -u" "/sbin/ora_ppmond" "/usr/bin/pulse-helper"
)

# The ACTUAL physical paths of legitimate daemons. If a process masquerades as one of 
# the above but isn't running from one of these files, it gets flagged.
WHITELIST_EXES=(
  "/usr/sbin/agetty" "/usr/sbin/auditd" "/usr/sbin/mingetty" "/usr/sbin/udevd"
  "/usr/lib/systemd/systemd-journald" "/usr/lib/systemd/systemd-machined" "/sbin/agetty" "/sbin/auditd" "/sbin/mingetty" "/sbin/udevd"
  "/usr/bin/python" "/usr/bin/python2" "/usr/bin/python3"
  "/usr/sbin/tuned" "/usr/lib/polkit-1/polkitd" "/usr/libexec/postfix/pickup"
  "/usr/libexec/postfix/master" "/usr/sbin/NetworkManager"
  "/usr/sbin/console-kit-daemon" "/usr/sbin/crond" "/usr/sbin/mcelog"
  "/usr/sbin/rsyslogd" "/usr/sbin/smartd" "/usr/sbin/avahi-daemon"
  "/usr/bin/dbus-daemon" "/usr/libexec/hald-addon-acpi" "/usr/libexec/hald-runner"
  "/usr/sbin/lldpad" "/usr/sbin/nginx" "/usr/sbin/sshd" "/usr/sbin/acpid"
  "/usr/sbin/atd" "/usr/sbin/chronyd" "/usr/sbin/console-kit"
  "/usr/libexec/rtkit-daemon" "/usr/libexec/upowerd" "/usr/sbin/abrtd"
)

SUSPICIOUS_STRINGS=(
  "HISTFILE=/dev/null" "MYSQL_HISTFILE=/dev/null" "ttcompat" ":h:d:l:s:b:t:"
  ":f:wiunomc" ":f:x:wiuoc" "LibTomCrypt 1.17"
  "Private key does not match the public certificate"
  "I5*AYbs@LdaWbsO"
)

KNOWN_C2_HOSTS=(
  "ntpupdate.ddnsgeek.com" "ntpussl.instanthq.com" "ntpd.casacam.net" "ntpupdate.ygto.com"
)

SUSPICIOUS_PORTS_RANGE_START=42391
SUSPICIOUS_PORTS_RANGE_END=43390
SUSPICIOUS_PORT_SINGLE=8000

SUSPICIOUS_FILES_TMP=()

# ---- Logging helpers -------------------------------------------------------
log() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts="$(date +'%Y-%m-%d %H:%M:%S')"
  
  # Log cleanly to file
  echo "[$ts] [$level] $msg" >> "$LOGFILE"
  
  # Apply colors for terminal output
  local color="${NC}"
  case "$level" in
    "CRITICAL") color="${RED}" ;;
    "ALERT")    color="${YELLOW}" ;;
    "INFO")     color="${BLUE}" ;;
    "SUCCESS")  color="${GREEN}" ;;
    "WARN")     color="${MAGENTA}" ;;
  esac
  
  # Print colored output to terminal
  echo -e "${NC}[$ts] [${color}${level}${NC}] $msg"
}

banner() {
  local b=$(cat << "EOF"
██████╗  █████╗ ██████╗ ██╗██████╗ ███████╗
██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗╚════██║
██████╔╝███████║██████╔╝██║██║  ██║    ██╔╝
██╔══██╗██╔══██║██╔═══╝ ██║██║  ██║   ██╔╝ 
██║  ██║██║  ██║██║     ██║██████╔╝   ██║  
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═════╝    ╚═╝  
      M A L W A R E   L A B S              
==========================================================
Enhanced Linux BPFDoor Detection Script 
==========================================================
EOF
)
  echo -e "${ORANGE}${b}${NC}"
  echo "$b" >> "$LOGFILE"
  echo "Host   : ${HOSTNAME}" | tee -a "$LOGFILE"
  echo "Date   : ${DATE}" | tee -a "$LOGFILE"
  echo "Version: ${VERSION}" | tee -a "$LOGFILE"
  echo "==========================================================" | tee -a "$LOGFILE"
}

require_root() {
  if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] This script requires root privileges.${NC}"
    exit 1
  fi
}

cmd_exists() {
  command -v "$1" >/dev/null 2>&1
}

mark_suspicious_file() {
  local file="$1"
  SUSPICIOUS_FILES_TMP+=("$file")
}

is_self() {
  # Excludes the script itself from being flagged during execution
  local p="$1"
  if [ "$p" = "$SCRIPT_PID" ] || [ "$p" = "$SCRIPT_PPID" ]; then
    return 0
  fi
  return 1
}

# ---- Helper: Hash check ---------------------------------------------------
hash_matches_malware() {
  local file="$1"
  if cmd_exists sha256sum; then
    local h="$(sha256sum "$file" 2>/dev/null | awk '{print $1}')"
    [ -n "${MALWARE_SHA256[$h]}" ] && return 0
  fi
  if cmd_exists md5sum; then
    local h="$(md5sum "$file" 2>/dev/null | awk '{print $1}')"
    [ -n "${MALWARE_MD5[$h]}" ] && return 0
  fi
  return 1
}

# ---- Helper: Strings check ------------------------------------------------
scan_strings_for_bpfdoor() {
  local file="$1"
  cmd_exists strings || return 1
  local found=0
  local file_strings="$(strings "$file" 2>/dev/null)"
  for s in "${SUSPICIOUS_STRINGS[@]}"; do
    if echo "$file_strings" | grep -Fq "$s"; then
      log "ALERT" "String match '$s' found in $file"
      found=1
    fi
  done
  [ "$found" -eq 1 ] && return 0
  return 1
}

# ---- Helper: Hexdump Mapped Memory for Magic Bytes ------------------------
check_maps_hex() {
  local pid="$1"
  is_self "$pid" && return
  [ -r "/proc/$pid/maps" ] || return
  cmd_exists hexdump || return

  local maps_paths="$(awk '{ if ($6 ~ /^\//) print $6 }' "/proc/$pid/maps" 2>/dev/null | sort -u)"
  
  # Combined 32-bit Little-Endian hex strings of all magic bytes from BPF filters
  local magic_hex_regex="55720000|93520000|39393939|6c8d0000|4f9f0000|0f270000|48200000|55110000|33540000|82310000|51100000|21330000|adde0000"

  for path in $maps_paths; do
    [ -r "$path" ] || continue
    
    local size="$(stat -c '%s' "$path" 2>/dev/null || echo 0)"
    [ "$size" -gt 5242880 ] && continue

    # Create a single continuous string of hex characters
    local hexdata="$(hexdump -ve '1/1 "%02x"' "$path" 2>/dev/null)"
    
    if echo "$hexdata" | grep -qiE "$magic_hex_regex"; then
      log "CRITICAL" "Little-Endian Magic Bytes found in mapped file: $path (PID: $pid)"
      mark_suspicious_file "$path"

      # Extract the magic bytes along with ~16 bytes (32 hex characters) of context on either side
      local context="$(echo "$hexdata" | grep -ioE ".{0,32}($magic_hex_regex).{0,32}" | head -n 3)"

      if [ -n "$context" ]; then
        echo "------- HEXDUMP CONTEXT -------" >> "$LOGFILE"
        echo "$context" >> "$LOGFILE"
        echo "-------------------------------" >> "$LOGFILE"

        echo -e "${CYAN}------- HEXDUMP CONTEXT -------${NC}"
        echo "$context" | grep --color=always -iE "$magic_hex_regex"
        echo -e "${CYAN}-------------------------------${NC}"
      fi
    fi
  done
}

# ------ Helper: Check if it is Rapid 7 agent ----------------------------
is_rapid7_ir_agent() {
  local pid="$1"
  local pidprog="$2"

  [[ "$pidprog" == *"ir_agent"* ]] && return 0

  return 1
}

# ---- Check 1: Mutex / lock files ------------------------------------------
check_mutex_files() {
  log "INFO" "[1/12] Checking /var/run for suspicious zero-byte mutex/lock files"
  local found=0

  for f in /var/run/*.pid /var/run/*.lock; do
    [ -e "$f" ] || continue
    local size="$(stat -c '%s' "$f" 2>/dev/null || echo "")"
    local perm="$(stat -c '%a' "$f" 2>/dev/null || echo "")"
    if [ "$size" = "0" ] && [ "$perm" = "644" ]; then
      for known in "${SUSPICIOUS_MUTEX_FILES[@]}"; do
        if [ "$f" = "$known" ]; then
          log "ALERT" "Suspicious mutex/lock file: $f (size=0, perm=644)"
          found=1
        fi
      done
    fi
  done
  [ "$found" -eq 0 ] && log "SUCCESS" "[1/12] No known suspicious mutex/lock files found"
}

# ---- Check 2: Auto-exec / sysconfig hooks ---------------------------------
check_autostart_files() {
  log "INFO" "[2/12] Checking /etc/sysconfig for suspicious auto-start entries"
  local dir="/etc/sysconfig"
  local pat='\[[[:space:]]*-f[[:space:]]+/[^]]+\][[:space:]]*&&[[:space:]]*/'

  if [ ! -d "$dir" ]; then
    log "WARN" "[2/12] /etc/sysconfig not present; skipping"
    return
  fi

  local results="$(find "$dir" -type f -exec grep -EH "$pat" {} + 2>/dev/null || true)"
  if [ -z "$results" ]; then
    log "SUCCESS" "[2/12] No suspicious auto-start patterns found in /etc/sysconfig"
    return
  fi

  log "ALERT" "[2/12] Potential suspicious auto-start entries detected:"
  echo "$results" | tee -a "$LOGFILE"

  while IFS= read -r line; do
    local filepath="$(echo "$line" | sed -nE 's/.*\[ *-f *([^ ]+).*/\1/p')"
    if [ -n "$filepath" ] && [ -e "$filepath" ]; then
      log "ALERT" "Auto-start target candidate: $filepath"
      mark_suspicious_file "$filepath"
    fi
  done <<< "$results"
}

# ---- Check 3: BPF filter usage (old + new variants) -----------------------
check_bpf_filters() {
  log "INFO" "[3/12] Inspecting BPF filters via ss -0pb"
  if ! cmd_exists ss; then
    log "WARN" "[3/12] ss command not available; skipping BPF filter check"
    return
  fi

  local out="$(ss -0pb 2>/dev/null || true)"
  if [ -z "$out" ]; then
    log "INFO" "[3/12] No packet sockets reported by ss -0pb"
    return
  fi

  echo "$out" >> "$LOGFILE"

  local magic_regex='0x5293|21139|0x7255|29269|0x39393939|960051133|0x8D6C|36204|0x9F4F|40783|12674|13089|57005|4437|21555|4177|8264|0x270f|0x2048|0x1155|0x5433|0x3182|0x1051|0x3321|0xdead'
  local matches="$(echo "$out" | grep -EB1 "$magic_regex" || true)"

  if [ -n "$matches" ]; then
    log "CRITICAL" "[3/12] BPFDoor magic pattern found in BPF filter output!"
    
    echo "------- MATCH CONTEXT -------" >> "$LOGFILE"
    echo "$matches" >> "$LOGFILE"
    echo "-----------------------------" >> "$LOGFILE"

    echo -e "${CYAN}------- MATCH CONTEXT -------${NC}"
    echo "$matches" | grep --color=always -E "$magic_regex"
    echo -e "${CYAN}-----------------------------${NC}"

    local pids="$(echo "$matches" | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u)"
    
    if [ -n "$pids" ]; then
      for pid in $pids; do
        is_self "$pid" && continue
        [ -d "/proc/$pid" ] || continue
        local exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")"
        local cmd="$(ps -p "$pid" -o user=,pid=,cmd= 2>/dev/null || echo "")"
        log "ALERT" "  PID $pid -> $exe :: $cmd"
        [ -n "$exe" ] && mark_suspicious_file "$exe"
        
        check_maps_hex "$pid"
      done
    fi
  else
    log "SUCCESS" "[3/12] No obvious BPFDoor-like BPF filters found"
  fi
}

# ---- Check 4: RAW + packet socket usage (Enhanced) ------------------------
check_raw_and_packet_sockets() {
  log "INFO" "[4/12] Checking RAW and packet socket usage (SOCK_RAW / SOCK_DGRAM)"
  
  local pids_found=""
  local flagged=0

  # 1. Collect PIDs from 'ss'
  if cmd_exists ss; then
    pids_found+="$(ss -0 -w -n -p 2>/dev/null | grep -oP 'pid=\K[0-9]+')"
  fi

  # 2. Collect PIDs from /proc/net forensics
  # We combine all potential inodes first, then find their owners
  local all_inodes=""
  for netfile in /proc/net/packet /proc/net/raw /proc/net/raw6; do
    if [ -r "$netfile" ]; then
      all_inodes+=" $(awk 'NR>1 && $NF ~ /^[0-9]+$/ {print $NF}' "$netfile" 2>/dev/null)"
    fi
  done

  # Process each unique inode found
  for ino in $(echo "$all_inodes" | tr ' ' '\n' | sort -u); do
    [ -z "$ino" ] && continue
    [ "$ino" -eq 0 ] 2>/dev/null && continue

    # Find PIDs for this inode and add to our list
    local p=$(grep -rlE "ino(de)?:\s*$ino" /proc/[0-9]*/fdinfo 2>/dev/null | cut -d/ -f3)
    pids_found+=" $p"
  done

  # 3. Analyze the collected PIDs
  # Unique-sort the list of PIDs to avoid duplicate alerts
  local unique_pids=$(echo "$pids_found" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -u)

  for pid in $unique_pids; do
    # Self-exclusion
    [ "$pid" -eq "$SELF_PID" ] 2>/dev/null && continue
    [ -d "/proc/$pid" ] || continue

    local exe_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
    
    # Skip if it's this detection script
    [ "$exe_path" == "$SELF_EXE" ] && continue
 #exclude legitimate networking tools
    if [[ "$exe_path" == *"/NetworkManager"* ]] || [[ "$exe_path" == *"/dhclient"* ]] || [[ "$exe_path" == *"/systemd-networkd"* ]]; then
      continue
    fi
    local cmd_line=$(ps -p "$pid" -o args= 2>/dev/null | head -n1)
    
    # If we got here, we found something
    log "ALERT" "Suspicious Socket detected: PID $pid ($cmd_line) -> $exe_path"
    
    if [[ -n "$exe_path" && "$exe_path" != "unknown" && -e "$exe_path" ]]; then
      mark_suspicious_file "$exe_path"
    fi
    
    check_maps_hex "$pid"
    flagged=1
  done

  # 4. Final Status (Only Success if NO pids were ever flagged)
  if [ "$flagged" -eq 0 ]; then
    log "SUCCESS" "No suspicious RAW/packet socket usage detected"
  fi
}
# ---- Check 5: Env vars used by BPFDoor shells -----------------------------
check_env_vars() {
  log "INFO" "[5/12] Checking for suspicious environment variables"
  local hits=0

  for pid_dir in /proc/[0-9]*; do
    [ -r "$pid_dir/environ" ] || continue
    local pid="${pid_dir##*/}"
    is_self "$pid" && continue
    
    local env="$(tr '\0' '\n' < "$pid_dir/environ" 2>/dev/null || true)"
    [ -z "$env" ] && continue

    if echo "$env" | grep -qx "HOME=/tmp" \
       && echo "$env" | grep -qx "HISTFILE=/dev/null" \
       && echo "$env" | grep -qx "MYSQL_HISTFILE=/dev/null"; then
      
      local exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")"
      local cmd="$(ps -p "$pid" -o user=,pid=,cmd= 2>/dev/null || echo "")"
      local ppid="$(ps -p "$pid" -o ppid= 2>/dev/null | tr -d ' ' || echo "")"
      log "CRITICAL" "[5/12] Process with BPFDoor-like env vars: PID=$pid, PPID=$ppid, EXE=$exe, CMD=$cmd"
      [ -n "$exe" ] && mark_suspicious_file "$exe"
      if [ -n "$ppid" ] && [ -e "/proc/$ppid/exe" ]; then
        mark_suspicious_file "$(readlink -f "/proc/$ppid/exe" 2>/dev/null || true)"
      fi
      hits=$((hits+1))
    fi
  done

  [ "$hits" -eq 0 ] && log "SUCCESS" "[5/12] No processes with the full suspicious env var set found"
}

# ---- Check 6: Ports historically used by BPFDoor --------------------------
check_suspicious_ports() {
  log "INFO" "[6/12] Checking TCP ports ${SUSPICIOUS_PORTS_RANGE_START}-${SUSPICIOUS_PORTS_RANGE_END} and ${SUSPICIOUS_PORT_SINGLE}"
  local net_out=""

  if cmd_exists netstat; then
    net_out="$(netstat -antp 2>/dev/null || true)"
  elif cmd_exists ss; then
    net_out="$(ss -antp 2>/dev/null || true)"
  else
    log "WARN" "[6/12] Neither netstat nor ss available; skipping port check"
    return
  fi

  local matches=""
  while IFS= read -r line; do
    [[ "$line" =~ ^tcp ]] || continue
    local laddr raddr state pidprog
    read -r _ _ laddr raddr state pidprog <<<"$line"

    local pid="${pidprog%%/*}"
    [[ "$pid" =~ ^[0-9]+$ ]] || pid=""
    if is_rapid7_ir_agent "$pid" "$pidprog"; then
      continue
    fi

    local lport="${laddr##*:}"
    local rport="${raddr##*:}"

    [[ "$lport" =~ ^[0-9]+$ ]] || lport=0
    [[ "$rport" =~ ^[0-9]+$ ]] || rport=0

    if { [ "$lport" -ge "$SUSPICIOUS_PORTS_RANGE_START" ] && [ "$lport" -le "$SUSPICIOUS_PORTS_RANGE_END" ]; } \
       || { [ "$rport" -ge "$SUSPICIOUS_PORTS_RANGE_START" ] && [ "$rport" -le "$SUSPICIOUS_PORTS_RANGE_END" ]; } \
       || [ "$lport" -eq "$SUSPICIOUS_PORT_SINGLE" ] \
       || [ "$rport" -eq "$SUSPICIOUS_PORT_SINGLE" ]; then
      matches+="$line"$'\n'
    fi
  done <<< "$net_out"

  if [ -z "$matches" ]; then
    log "SUCCESS" "[6/12] No connections on known suspicious BPFDoor ports"
    return
  fi

  log "ALERT" "[6/12] Potentially suspicious connections on historical BPFDoor ports:"
  printf "%s\n" "$matches" | tee -a "$LOGFILE"

  local pids="$(printf "%s\n" "$matches" | awk '{print $7}' | cut -d/ -f1 | grep -E '^[0-9]+$' | sort -u)"
  for pid in $pids; do
    is_self "$pid" && continue
    [ -d "/proc/$pid" ] || continue
    local exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")"
    [ -n "$exe" ] && mark_suspicious_file "$exe"
  done
}

# ---- Check 7: Process masquerading (Whitelist Integration) ----------------
check_process_masquerade() {
  log "INFO" "[7/12] Checking for masqueraded processes (Verifying true execution paths)"
  local found=0

  # Grab all processes and their arguments
  local ps_output="$(ps -eo pid=,args= 2>/dev/null || true)"
  [ -z "$ps_output" ] && return

  while read -r pid args; do
    [ -z "$pid" ] && continue
    is_self "$pid" && continue

    # 1. Identify if the process claims to be a suspect
    local is_suspect=0
    for pat in "${SUSPICIOUS_PROCS[@]}"; do
      if echo "$args" | grep -Fq "$pat"; then
        is_suspect=1
        break
      fi
    done

   # 2. Unmask and Verify the suspect against the Whitelist
    if [ "$is_suspect" -eq 1 ]; then
      # Read the exact execution path from the kernel
      local raw_exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")"
      
      # FIX 1: Strip the " (deleted)" suffix caused by legitimate package updates
      local exe="${raw_exe%" (deleted)"}"
      
      # Skip real kernel threads
      if [[ -z "$exe" ]] || [[ "$raw_exe" == "/proc/$pid/exe" ]]; then
        if [ ! -s "/proc/$pid/cmdline" ]; then
          continue 
        fi
      fi

      local is_whitelisted=0
      for wl in "${WHITELIST_EXES[@]}"; do
        # FIX 2: Canonicalize the whitelist path to account for merged-/usr symlinks
        local canonical_wl="$(readlink -m "$wl" 2>/dev/null || echo "$wl")"
        
        if [ "$exe" = "$canonical_wl" ]; then
          is_whitelisted=1
          break
        fi
      done

      # 3. Trap: It's a suspect name, but not running from a whitelisted binary file
      if [ "$is_whitelisted" -eq 0 ]; then
        log "CRITICAL" "[7/12] Process Masquerading Detected! PID=$pid claims to be '$args' but is actually executing '$raw_exe'"
        mark_suspicious_file "$exe"
        found=1
      fi
    fi
  done <<< "$ps_output"

  [ "$found" -eq 0 ] && log "SUCCESS" "[7/12] No process masquerading detected"
}

# ---- Check 8: Memory-Resident / Deleted Binaries --------------------------
check_deleted_binaries() {
  log "INFO" "[8/12] Checking for processes executing deleted binaries (Fileless execution)"
  local found=0
  local deleted_pids="$(ls -l /proc/*/exe 2>/dev/null | grep " (deleted)" | awk -F'/proc/' '{print $2}' | cut -d'/' -f1 || true)"

  if [ -n "$deleted_pids" ]; then
    for d_pid in $deleted_pids; do
      is_self "$d_pid" && continue
      [ -d "/proc/$d_pid" ] || continue
      local d_name="$(ps -p "$d_pid" -o comm= 2>/dev/null || echo "")"
      local d_exe="$(readlink -f "/proc/$d_pid/exe" 2>/dev/null || echo "")"
      
      local is_bpf_candidate=0
      for pat in "${SUSPICIOUS_PROCS[@]}"; do
        if [[ "$pat" == *"$d_name"* ]]; then
          is_bpf_candidate=1
          break
        fi
      done

      if [ "$is_bpf_candidate" -eq 1 ]; then
        log "CRITICAL" "PID: $d_pid masquerading as '$d_name' running from a deleted file: $d_exe"
        mark_suspicious_file "$d_exe"
        found=1
      else
        log "WARN" "PID: $d_pid, ProcessName: $d_name, Exec: $d_exe (Deleted Binary)"
      fi
    done
  fi

  [ "$found" -eq 0 ] && log "SUCCESS" "[8/12] No critical memory-resident/deleted binary execution found"
}

# ---- Check 9: Kernel Stack Tracing ----------------------------------------
check_kernel_stack() {
  log "INFO" "[9/12] Checking kernel stacks for raw socket blocking (packet_recvmsg/wait_for_more_packets)"
  local found=0
  local pids="$(grep -lE "packet_recvmsg|wait_for_more_packets" /proc/*/stack 2>/dev/null | awk -F/ '{print $3}' || true)"
  
  for pid in $pids; do
    is_self "$pid" && continue
    [ -d "/proc/$pid" ] || continue
    local exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")"
    local cmd="$(ps -p "$pid" -o user=,pid=,cmd= 2>/dev/null || echo "")"
    log "CRITICAL" "Process hanging on packet_recvmsg: PID=$pid EXE=$exe CMD=$cmd"
    [ -n "$exe" ] && mark_suspicious_file "$exe"
    found=1
    
    check_maps_hex "$pid"
  done

  [ "$found" -eq 0 ] && log "SUCCESS" "[9/12] No processes blocking on suspicious packet socket kernel functions"
}

# ---- Check 12: Deep scan suspicious files (hash, strings, UPX packer) -----
deep_scan_suspicious_files() {
  log "INFO" "[12/12] Deep scanning candidate binaries (hash, strings, UPX packing)"
  local uniq_files=($(printf "%s\n" "${SUSPICIOUS_FILES_TMP[@]}" | sort -u))

  if [ "${#uniq_files[@]}" -eq 0 ]; then
    log "INFO" "[12/12] No candidate binaries collected for deep scan"
    return
  fi

  for f in "${uniq_files[@]}"; do
    [ -e "$f" ] || continue
    log "INFO" ">>> Analyzing candidate binary: $f"
    
    if hash_matches_malware "$f"; then
      log "CRITICAL" "Known BPFDoor hash match for $f"
      continue
    fi
    
    if cmd_exists dd; then
      local dd_out="$(dd if="$f" bs=1 count=256 2>/dev/null | grep -o 'UPX!' || true)"
      if [ -n "$dd_out" ]; then
        log "ALERT" "Binary is UPX packed (Common for BPFdoor): $f"
      fi
    fi

    if scan_strings_for_bpfdoor "$f"; then
      log "CRITICAL" "BPFDoor-like string pattern(s) found in $f"
    fi
  done
}

# ---- Helper: Check if IP is a globally routable address -------------------
is_global_ip() {
  local ip="$1"

  # 1. IPv6 FAST-PATH (Regex Bypass for performance and Bash compatibility)
  if [[ "$ip" == *":"* ]]; then
    # Filter common IPv6 sinkholes/local: ::1, ::, fc00::/7, fe80::/10
    if [[ "$ip" == "::1" ]] || [[ "$ip" == "::" ]] || \
       [[ "$ip" =~ ^[fF][cCdD] ]] || [[ "$ip" =~ ^[fF][eE][89aAbB] ]]; then
      return 1
    fi
    return 0
  fi

  # 2. IPv4 CIDR MATH PATH
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

  local IFS='.' nums
  read -r -a nums <<< "$ip"
  for o in "${nums[@]}"; do (( o > 255 )) && return 1; done
  local ipnum=$(( (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3] ))

  in_cidr() {
    local IFS='/' parts
    read -r -a parts <<< "$1"
    local IFS='.' net
    read -r -a net <<< "${parts[0]}"
    local netnum=$(( (net[0] << 24) | (net[1] << 16) | (net[2] << 8) | net[3] ))
    local mask=$(( 0xFFFFFFFF << (32 - parts[1]) & 0xFFFFFFFF ))
    (( (ipnum & mask) == (netnum & mask) ))
  }

  # Non-global ranges per IANA
  local non_global=(
    0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16
    172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16
    198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4
  )

  for cidr in "${non_global[@]}"; do
    in_cidr "$cidr" && return 1
  done

  return 0
}

# ---- Check 10: C2 Connections (DNS Resolving & SS Tracking) ---------------
check_c2_connections() {
  log "INFO" "[10/12] Checking for active connections to known BPFDoor C2 domains"
  local found=0
  
  if ! cmd_exists dig || ! cmd_exists ss; then
    log "WARN" "[10/12] 'dig' or 'ss' missing; skipping C2 connection checks."
    return
  fi

  for host in "${KNOWN_C2_HOSTS[@]}"; do
    local ips
    ips="$(dig +short "$host" A "$host" AAAA 2>/dev/null | grep -E '^[0-9a-fA-F:.]+$' | grep -E '\.|\:'|| true)"
    
    for ip in $ips; do
      if ! is_global_ip "$ip"; then
        log "INFO" "Skipping non-global IP for $host: $ip (likely sinkhole/private)"
        continue
      fi

      local ss_output
      ss_output="$(ss -H -tnp state established dst "$ip" 2>/dev/null || true)"
      
      if [ -n "$ss_output" ]; then
        log "CRITICAL" "Active connection to known BPFDoor C2: $host ($ip)"
        echo "$ss_output" | tee -a "$LOGFILE"
        
        local c2_pids
        c2_pids="$(echo "$ss_output" | grep -oP 'pid=\K[0-9]+' | sort -u)"
        for c2pid in $c2_pids; do
          is_self "$c2pid" && continue
          [ -d "/proc/$c2pid" ] || continue
          local exe
          exe="$(readlink -f "/proc/$c2pid/exe" 2>/dev/null || echo "")"
          [ -n "$exe" ] && mark_suspicious_file "$exe"
        done
        found=1
      fi
    done
  done
  [ "$found" -eq 0 ] && log "SUCCESS" "[10/12] No active connections to known C2 domains found"
}
# ---- Check 11: Process-Specific Signatures --------------------------------
check_process_signatures() {
  log "INFO" "[11/12] Checking specific processes for hardcoded BPFDoor file signatures"
  local found=0

  local sig_checks=(
    "sshd::66666666H"
    "abrtd|atd|pickup:::h:d:l:s:b:t"
    "sgaSolAgent|cmathreshd|udevd|agetty|hpasmlited|\.sshd::ttcompat::127.0.0.1"
  )

  for check in "${sig_checks[@]}"; do
    local proc_pat="${check%%::*}"
    local remainder="${check#*::}"
    local sig1="${remainder%%::*}"
    local sig2="${remainder#*::}"

    local pids="$(pgrep -E "$proc_pat" 2>/dev/null || true)"
    
    for pid in $pids; do
      is_self "$pid" && continue
      [ -d "/proc/$pid" ] || continue
      local exe_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
      local path="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")"
      [ -z "$path" ] && continue

      if grep -a -q "$sig1" "$path" 2>/dev/null; then
        if [ -n "$sig2" ] && [ "$sig1" != "$sig2" ]; then
          if ! grep -a -q "$sig2" "$path" 2>/dev/null; then
            continue
          fi
        fi
        
        local cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "")"
        log "CRITICAL" "Process Signature Match: PID=$pid, Path=$path, Cmd=$cmdline matched pattern '$proc_pat'"
        mark_suspicious_file "$path"
        found=1
      fi
    done
  done

  [ "$found" -eq 0 ] && log "SUCCESS" "[11/12] No hardcoded process signatures detected"
}
# ---- Optional: Basic persistence checks -----------------------------------
check_persistence() {
  log "INFO" "[-] Basic persistence triage (cron, systemd, rc scripts)"

  # 1. Define the regex ONCE (Safely removed the generic 'bpf' trap)
  local persist_regex="bpfdoor|dbus-srv|hpasmmld|smartadm|hald-addon-volume"

  # 2. Check Cron
  for file in /etc/crontab /var/spool/cron/* /var/spool/cron/crontabs/*; do
    [ -f "$file" ] || continue
    if grep -E "$persist_regex" "$file" 2>/dev/null | grep -q .; then
      log "CRITICAL" "Suspicious persistence entry in cron: $file"
      grep -HnE "$persist_regex" "$file" >> "$LOGFILE"
    fi
  done

  # 3. Check Systemd
  for dir in /etc/systemd/system /usr/lib/systemd/system /run/systemd/system; do
    [ -d "$dir" ] || continue
    # Grab the exact files that match, instead of blindly alerting on the directory
    local matches="$(grep -rlE "$persist_regex" "$dir" 2>/dev/null || true)"
    if [ -n "$matches" ]; then
      for m in $matches; do
        log "CRITICAL" "Suspicious persistence pattern found in systemd unit: $m"
        # Log the exact line of code that triggered it to the report
        grep -HnE "$persist_regex" "$m" >> "$LOGFILE"
      done
    fi
  done

  # 4. Check RC / Init scripts
  for rc in /etc/rc.local /etc/init.d/*; do
    [ -f "$rc" ] || continue
    if grep -E "$persist_regex" "$rc" 2>/dev/null | grep -q .; then
      log "CRITICAL" "Suspicious persistence pattern in rc script: $rc"
      grep -HnE "$persist_regex" "$rc" >> "$LOGFILE"
    fi
  done
}

# ---- Main ------------------------------------------------------------------
main() {
  require_root
  : > "$LOGFILE"
  banner

  echo -e "\n${CYAN}[*] Running Ultimate BPFDoor triage…${NC}"
  check_mutex_files
  check_autostart_files
  check_bpf_filters
  check_raw_and_packet_sockets
  check_env_vars
  check_suspicious_ports
  check_process_masquerade
  check_deleted_binaries
  check_kernel_stack
  check_c2_connections
  check_process_signatures
  deep_scan_suspicious_files
  check_persistence

  echo
  echo -e "${CYAN}[*] Scan complete. Report written to: ${LOGFILE}${NC}"
  echo -e "${YELLOW}[!] Any CRITICAL or ALERT entries should be investigated, considering there could be an acceptable rate of false positives depending on the execution environment.${NC}"
}

main "$@"
