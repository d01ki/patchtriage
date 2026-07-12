#!/usr/bin/env bash
# One command to launch PatchTriage: build + start the GUI in Docker and open
# the console in your browser. Nothing but Docker required.
#
#   ./run.sh              # build, start, open http://localhost:8765
#   ./run.sh --stop       # stop the console
#   PORT=9000 ./run.sh    # use a different host port
set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-8765}"
URL="http://localhost:${PORT}"

# docker compose (v2) or docker-compose (v1)?
if docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  echo "ERROR: Docker Compose not found. Install Docker Desktop or the" >&2
  echo "       docker-compose-plugin, then re-run ./run.sh" >&2
  exit 1
fi

if [[ "${1:-}" == "--stop" ]]; then
  "${DC[@]}" down
  echo "PatchTriage console stopped."
  exit 0
fi

echo "==> building and starting the PatchTriage console (Docker)…"
PATCHTRIAGE_PORT="${PORT}" "${DC[@]}" up -d --build gui

echo "==> waiting for the console to become ready…"
for i in $(seq 1 60); do
  if curl -fsS "${URL}/api/config" >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done

if [[ "${ready:-}" != "1" ]]; then
  echo "The console did not become ready in time. Check logs with:" >&2
  echo "    ${DC[*]} logs gui" >&2
  exit 1
fi

echo
echo "  PatchTriage console is live:  ${URL}"
echo "  Stop it with:                 ./run.sh --stop"
echo

# Try to open a browser (ignored on headless servers).
if command -v xdg-open >/dev/null 2>&1; then xdg-open "${URL}" >/dev/null 2>&1 || true
elif command -v open   >/dev/null 2>&1; then open "${URL}"   >/dev/null 2>&1 || true
elif command -v powershell.exe >/dev/null 2>&1; then powershell.exe -NoProfile Start "${URL}" >/dev/null 2>&1 || true
else echo "Open ${URL} in your browser."; fi
