#!/usr/bin/env bash
set -euo pipefail

ROOT="/mnt/8T/xgr/zhuyijia/MA_MemIDS"
PCAP="/mnt/8T/xgr/zhuyijia/GRIDAI/samples/xss_sample.pcap"

if [[ ! -f "$PCAP" ]]; then
  echo "PCAP not found: $PCAP" >&2
  exit 1
fi

cd "$ROOT"
python main.py process \
  --pcap "$PCAP" \
  --attack-pcaps "$PCAP"

python main.py export --output ./output/rules.rules

echo "Done. Exported rules to ./output/rules.rules"
