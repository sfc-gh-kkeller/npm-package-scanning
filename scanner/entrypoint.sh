#!/bin/sh
set -eu
# /work itself is not writable in SPCS (mount parent); write only into the stage mounts.
python3 /app/scan.py --packages /config/packages.txt --out /work \
  --results /work/quarantine/_results \
  --cooldown-days "${COOLDOWN_DAYS:-7}" --allow-scripts "${ALLOW_SCRIPTS:-}"
