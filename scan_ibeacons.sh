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
#   Filter by UUID + Major + Minor:
#     sudo ./scan_ibeacons.sh -u 7848C789-EB6A-45F3-A54F-32F327ACCA7D -M 914 -m 111
#
# Requirements:
#   sudo apt install bluez bluez-hcidump
# =============================================================================

FILTER_UUID=""
FILTER_MAJOR=""
FILTER_MINOR=""
LOG_FILE="ibeacons.log"
HCI_IFACE="hci0"

usage() {
  grep '^#' "$0" | grep -v '#!/' | sed 's/^# \?//'
  exit 0
}

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

if [[ $EUID -ne 0 ]]; then
  echo "Error: this script must be run as root (use sudo)." >&2
  exit 1
fi

for cmd in hcitool hcidump; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: '$cmd' not found. Install with: sudo apt install bluez bluez-hcidump" >&2
    exit 1
  fi
done

echo "=========================================="
echo "  iBeacon Scanner"
echo "=========================================="
echo "  Interface : $HCI_IFACE"
echo "  Log file  : $LOG_FILE"
[[ -n "$FILTER_UUID"  ]] && echo "  UUID      : $FILTER_UUID"  || echo "  UUID      : (any)"
[[ -n "$FILTER_MAJOR" ]] && echo "  Major     : $FILTER_MAJOR" || echo "  Major     : (any)"
[[ -n "$FILTER_MINOR" ]] && echo "  Minor     : $FILTER_MINOR" || echo "  Minor     : (any)"
echo "=========================================="
echo "  RSSI guide: -50 dBm = very close (~1m)"
echo "              -70 dBm = nearby    (~3m)"
echo "              -90 dBm = far away  (~10m+)"
echo "=========================================="
echo "Scanning… (Ctrl+C to stop)"
echo ""

hciconfig "$HCI_IFACE" up 2>/dev/null || true
hcitool -i "$HCI_IFACE" lescan --passive --duplicates >/dev/null 2>&1 &
LESCAN_PID=$!

cleanup() {
  kill "$LESCAN_PID" 2>/dev/null || true
  echo ""
  echo "Scan stopped. Log file: $LOG_FILE"
}
trap cleanup INT TERM EXIT

# ── RSSI bar helper ───────────────────────────────────────────────────────────
# Prints a visual bar: rssi_bar <rssi_value>
# Range mapped: -100 dBm (0 bars) to -40 dBm (20 bars)
rssi_bar() {
  local rssi=$1
  local min=-100 max=-40 width=20
  local val=$(( rssi < min ? min : rssi > max ? max : rssi ))
  local filled=$(( (val - min) * width / (max - min) ))
  local empty=$(( width - filled ))
  local bar=""
  local i
  for (( i=0; i<filled; i++ )); do bar+="█"; done
  for (( i=0; i<empty;  i++ )); do bar+="░"; done
  echo "$bar"
}

# ── Packet processor ──────────────────────────────────────────────────────────
#
# HCI LE Advertising Report event layout (hex string, no spaces):
#
#   Offset  Bytes  Field
#   00      1      HCI packet type        (04)
#   01      1      Event code             (3E = LE Meta)
#   02      1      Parameter total length
#   03      1      Subevent code          (02 = LE Advertising Report)
#   04      1      Num reports            (01)
#   05      1      Event type
#   06      1      Address type
#   07      6      BD_ADDR (MAC, little-endian)  → hex offset 14..25
#   13      1      Data length                   → hex offset 26..27
#   14      N      Advertising data              → hex offset 28..
#   14+N    1      RSSI (signed byte)            → last 2 hex chars
#
process_packet() {
  local hex="$1"
  local sig="FF4C000215"

  [[ "$hex" != *"$sig"* ]] && return

  local after="${hex##*$sig}"
  [[ ${#after} -lt 42 ]] && return

  # UUID
  local raw="${after:0:32}"
  local uuid
  uuid=$(printf '%s-%s-%s-%s-%s' \
    "${raw:0:8}" "${raw:8:4}" "${raw:12:4}" "${raw:16:4}" "${raw:20:12}")
  uuid="${uuid^^}"

  # Major / Minor
  local major=$(( 16#${after:32:4} ))
  local minor=$(( 16#${after:36:4} ))

  # TX Power (signed)
  local tx=$(( 16#${after:40:2} ))
  (( tx > 127 )) && tx=$(( tx - 256 ))

  # Apply filters
  [[ -n "$FILTER_UUID"  && "$uuid"  != "$FILTER_UUID"  ]] && return
  [[ -n "$FILTER_MAJOR" && "$major" != "$FILTER_MAJOR" ]] && return
  [[ -n "$FILTER_MINOR" && "$minor" != "$FILTER_MINOR" ]] && return

  # MAC (bytes 7-12, little-endian → reverse for display)
  local mac="??:??:??:??:??:??"
  if [[ ${#hex} -ge 26 ]]; then
    local b0="${hex:14:2}" b1="${hex:16:2}" b2="${hex:18:2}"
    local b3="${hex:20:2}" b4="${hex:22:2}" b5="${hex:24:2}"
    mac="${b5^^}:${b4^^}:${b3^^}:${b2^^}:${b1^^}:${b0^^}"
  fi

  # RSSI: last byte of the full HCI event (signed)
  local rssi=0
  if [[ ${#hex} -ge 2 ]]; then
    local rssi_hex="${hex: -2}"
    rssi=$(( 16#$rssi_hex ))
    (( rssi > 127 )) && rssi=$(( rssi - 256 ))
  fi

  # Distance estimate from RSSI and TX power (log-distance path loss model)
  # distance = 10 ^ ((TxPow - RSSI) / (10 * n))  where n=2 (free space)
  local dist_str="?m"
  if (( tx != 0 )); then
    local diff=$(( tx - rssi ))
    # Use awk for floating point
    dist_str=$(awk -v diff="$diff" 'BEGIN {
      d = 10 ^ (diff / 20.0)
      if      (d <  1)   printf "~%.1fm", d
      else if (d < 10)   printf "~%.1fm", d
      else if (d < 100)  printf "~%.0fm", d
      else               printf ">100m"
    }')
  fi

  local bar
  bar=$(rssi_bar "$rssi")

  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')

  # Console output (with bar)
  printf "[%s] MAC=%-17s  UUID=%s  Major=%-5d  Minor=%-5d  TxPow=%-4ddBm  RSSI=%-4ddBm  Dist=%-6s  [%s]\n" \
    "$ts" "$mac" "$uuid" "$major" "$minor" "$tx" "$rssi" "$dist_str" "$bar"

  # Log output (no bar, easier to parse)
  printf "[%s] MAC=%-17s  UUID=%s  Major=%-5d  Minor=%-5d  TxPow=%-4ddBm  RSSI=%-4ddBm  Dist=%s\n" \
    "$ts" "$mac" "$uuid" "$major" "$minor" "$tx" "$rssi" "$dist_str" >> "$LOG_FILE"
}

# ── Main read loop ────────────────────────────────────────────────────────────
PACKET=""

while IFS= read -r raw; do
  if [[ "$raw" == ">"* ]]; then
    if [[ -n "$PACKET" ]]; then
      process_packet "$PACKET"
    fi
    PACKET="${raw:1}"
    PACKET="${PACKET//[[:space:]]/}"
    PACKET="${PACKET^^}"
  else
    local_part="${raw//[[:space:]]/}"
    PACKET="${PACKET}${local_part^^}"
  fi
done < <(hcidump -i "$HCI_IFACE" -R 2>/dev/null)

if [[ -n "$PACKET" ]]; then
  process_packet "$PACKET"
fi
