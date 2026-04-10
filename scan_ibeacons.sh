#!/usr/bin/env bash
# =============================================================================
# scan_ibeacons.sh — Scan for iBeacon advertisements via hcitool + hcidump
#
# Usage:
#   ./scan_ibeacons.sh [OPTIONS]
#
# Options:
#   -u UUID     Filter by Proximity UUID (case-insensitive)
#   -M MAJOR    Filter by Major value (decimal integer)
#   -m MINOR    Filter by Minor value (decimal integer)
#   -o FILE     Log file path (default: ibeacons.log)
#   -i IFACE    HCI interface to use (default: hci0)
#   -h          Show this help
#
# Examples:
#   Scan ALL iBeacons:
#     sudo ./scan_ibeacons.sh
#
#   Filter by UUID only:
#     sudo ./scan_ibeacons.sh -u 7848C789-EB6A-45F3-A54F-32F327ACCA7D
#
#   Filter by UUID + Major + Minor:
#     sudo ./scan_ibeacons.sh -u 7848C789-EB6A-45F3-A54F-32F327ACCA7D -M 914 -m 111
#
# Requirements:
#   sudo apt install bluez bluez-hcidump
# =============================================================================

# ── Defaults ──────────────────────────────────────────────────────────────────
FILTER_UUID=""
FILTER_MAJOR=""
FILTER_MINOR=""
LOG_FILE="ibeacons.log"
HCI_IFACE="hci0"

# ── Help ──────────────────────────────────────────────────────────────────────
usage() {
  grep '^#' "$0" | grep -v '#!/' | sed 's/^# \?//'
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────────
while getopts "u:M:m:o:i:h" opt; do
  case "$opt" in
    u) FILTER_UUID="${OPTARG^^}"  ;;
    M) FILTER_MAJOR="$OPTARG"    ;;
    m) FILTER_MINOR="$OPTARG"    ;;
    o) LOG_FILE="$OPTARG"        ;;
    i) HCI_IFACE="$OPTARG"       ;;
    h) usage                     ;;
    *) echo "Unknown option -$OPTARG" >&2; exit 1 ;;
  esac
done

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "Error: this script must be run as root (use sudo)." >&2
  exit 1
fi

# ── Dependency check ──────────────────────────────────────────────────────────
for cmd in hcitool hcidump; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: '$cmd' not found. Install with: sudo apt install bluez bluez-hcidump" >&2
    exit 1
  fi
done

# ── Print active filters ──────────────────────────────────────────────────────
echo "=========================================="
echo "  iBeacon Scanner"
echo "=========================================="
echo "  Interface : $HCI_IFACE"
echo "  Log file  : $LOG_FILE"
[[ -n "$FILTER_UUID"  ]] && echo "  UUID      : $FILTER_UUID"  || echo "  UUID      : (any)"
[[ -n "$FILTER_MAJOR" ]] && echo "  Major     : $FILTER_MAJOR" || echo "  Major     : (any)"
[[ -n "$FILTER_MINOR" ]] && echo "  Minor     : $FILTER_MINOR" || echo "  Minor     : (any)"
echo "=========================================="
echo "Scanning… (Ctrl+C to stop)"
echo ""

# ── Bring interface up ────────────────────────────────────────────────────────
hciconfig "$HCI_IFACE" up 2>/dev/null || true

# ── Start BLE passive scan ────────────────────────────────────────────────────
hcitool -i "$HCI_IFACE" lescan --passive --duplicates >/dev/null 2>&1 &
LESCAN_PID=$!

cleanup() {
  kill "$LESCAN_PID" 2>/dev/null || true
  echo ""
  echo "Scan stopped. Log file: $LOG_FILE"
}
trap cleanup INT TERM EXIT

# ── Packet processor function ─────────────────────────────────────────────────
#
# iBeacon packet (hex, no spaces):
#   043E...  HCI LE meta event header
#   ...XXYYZZ XXYYZZ  MAC (6 bytes, little-endian, at offset bytes 7-12)
#   ...FF4C000215      Apple iBeacon signature
#   UU×32             UUID (16 bytes)
#   MMMM              Major (2 bytes big-endian)
#   mmmm              Minor (2 bytes big-endian)
#   PP                TX Power (1 byte signed)
#
process_packet() {
  local hex="$1"
  local sig="FF4C000215"

  [[ "$hex" != *"$sig"* ]] && return

  local after="${hex##*$sig}"

  # Need 42+ hex chars after signature: 32 UUID + 4 Major + 4 Minor + 2 TX
  [[ ${#after} -lt 42 ]] && return

  # UUID
  local raw="${after:0:32}"
  local uuid
  uuid=$(printf '%s-%s-%s-%s-%s' \
    "${raw:0:8}" "${raw:8:4}" "${raw:12:4}" "${raw:16:4}" "${raw:20:12}")
  uuid="${uuid^^}"

  # Major (big-endian)
  local major=$(( 16#${after:32:4} ))

  # Minor (big-endian)
  local minor=$(( 16#${after:36:4} ))

  # TX Power (signed byte)
  local tx=$(( 16#${after:40:2} ))
  (( tx > 127 )) && tx=$(( tx - 256 ))

  # Apply filters
  [[ -n "$FILTER_UUID"  && "$uuid"  != "$FILTER_UUID"  ]] && return
  [[ -n "$FILTER_MAJOR" && "$major" != "$FILTER_MAJOR" ]] && return
  [[ -n "$FILTER_MINOR" && "$minor" != "$FILTER_MINOR" ]] && return

  # MAC address: bytes 7-12 of HCI event = hex offset 14..25, reversed
  local mac="??:??:??:??:??:??"
  if [[ ${#hex} -ge 26 ]]; then
    local b0="${hex:14:2}" b1="${hex:16:2}" b2="${hex:18:2}"
    local b3="${hex:20:2}" b4="${hex:22:2}" b5="${hex:24:2}"
    mac="${b5^^}:${b4^^}:${b3^^}:${b2^^}:${b1^^}:${b0^^}"
  fi

  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  local out
  out=$(printf "[%s] MAC=%-17s  UUID=%s  Major=%-5d  Minor=%-5d  TxPow=%ddBm" \
    "$ts" "$mac" "$uuid" "$major" "$minor" "$tx")

  echo "$out"
  echo "$out" >> "$LOG_FILE"
}

# ── Main read loop ────────────────────────────────────────────────────────────
# Use process substitution so the while loop runs in the main shell
# (not a subshell), keeping LESCAN_PID and trap in scope.
PACKET=""

while IFS= read -r raw; do
  if [[ "$raw" == ">"* ]]; then
    # New HCI event — process previous packet first
    if [[ -n "$PACKET" ]]; then
      process_packet "$PACKET"
    fi
    # Strip ">" prefix, remove spaces, uppercase
    PACKET="${raw:1}"
    PACKET="${PACKET//[[:space:]]/}"
    PACKET="${PACKET^^}"
  else
    # Continuation — strip spaces, append
    local_part="${raw//[[:space:]]/}"
    PACKET="${PACKET}${local_part^^}"
  fi
done < <(hcidump -i "$HCI_IFACE" -R 2>/dev/null)
