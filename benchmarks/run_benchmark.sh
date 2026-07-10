#!/usr/bin/env bash
# Reproducible benchmark: PatchTriage vs CVSS-ordering on widely used
# open-source container images.
#
# Targets are pinned to specific tags so results are reproducible and findings
# are guaranteed to exist. All targets are public images with millions of
# pulls -- not systems we built ourselves.
#
# Requirements: patchtriage installed (pip install -e .) and EITHER
#   * trivy (+ optionally grype) binaries on PATH, OR
#   * docker (the script falls back to pinned aquasec/trivy and
#     anchore/grype container images -- no local scanner install needed)
# Optional: NVD_API_KEY for full NVD enrichment (else run stays EPSS/KEV)
#
# Usage:
#   ./benchmarks/run_benchmark.sh                      # default 5-image set
#   TARGETS_FILE=benchmarks/targets_eol.txt \
#     SCANNERS=trivy ./benchmarks/run_benchmark.sh     # 20 EOL images, fast
#
# Env knobs:
#   TARGETS_FILE  file with one image per line (# comments ok). Overrides the
#                 built-in list below.
#   SCANNERS      comma list: "trivy", "grype", or "trivy,grype" (default).
#                 trivy-only roughly halves runtime.
#   PRUNE         "1" to `docker image rm` each target after scanning, to
#                 reclaim disk on large runs (default off).
#
# Output: benchmarks/out/<image>__{trivy,grype,report}.json + BENCHMARKS.md

set -uo pipefail

# Resolve TARGETS_FILE against the caller's CWD *before* we cd into the
# script directory, so both absolute and repo-root-relative paths work.
if [[ -n "${TARGETS_FILE:-}" && "${TARGETS_FILE}" != /* ]]; then
  TARGETS_FILE="$(cd "$(dirname "${TARGETS_FILE}")" && pwd)/$(basename "${TARGETS_FILE}")"
fi

cd "$(dirname "$0")"
mkdir -p out

SCANNERS="${SCANNERS:-trivy,grype}"
PRUNE="${PRUNE:-0}"

# Resolve the patchtriage entry point: console script if on PATH, otherwise
# the module (pip on Windows/user installs often doesn't put scripts on PATH).
PY="python"; command -v python >/dev/null 2>&1 || PY="python3"
if command -v patchtriage >/dev/null 2>&1; then
  PT=(patchtriage)
elif "$PY" -c "import patchtriage" >/dev/null 2>&1; then
  PT=("$PY" -m patchtriage.cli)
else
  echo "ERROR: patchtriage is not installed. Run: pip install -e ." >&2
  exit 1
fi

# Pinned scanner versions for the docker fallback (reproducibility)
TRIVY_IMAGE="aquasec/trivy:0.58.1"
GRYPE_IMAGE="anchore/grype:v0.87.0"

scan_trivy() {  # $1 = target image, $2 = output path
  if command -v trivy >/dev/null 2>&1; then
    trivy image --quiet --format json --output "$2" "$1"
  else
    docker run --rm \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$PWD/out:/out" \
      "$TRIVY_IMAGE" image --quiet --format json \
      --output "/out/$(basename "$2")" "$1"
  fi
}

scan_grype() {  # $1 = target image, $2 = output path
  if command -v grype >/dev/null 2>&1; then
    grype -q "$1" -o json > "$2"
  else
    docker run --rm \
      -v /var/run/docker.sock:/var/run/docker.sock \
      "$GRYPE_IMAGE" -q "$1" -o json > "$2"
  fi
}

# Targets: from TARGETS_FILE if given, else the default reproducible set.
if [[ -n "${TARGETS_FILE:-}" ]]; then
  mapfile -t TARGETS < <(grep -vE '^\s*(#|$)' "$TARGETS_FILE")
else
  TARGETS=(
    "nginx:1.24"
    "redis:7.0"
    "postgres:15.2"
    "node:18.16-bullseye"
    "python:3.10-bullseye"
  )
fi

echo "Scanning ${#TARGETS[@]} targets with: ${SCANNERS}"
ok=0; fail=0
for image in "${TARGETS[@]}"; do
  safe="${image//[:\/]/_}"
  reports=()
  echo "==> scanning ${image}"

  if [[ ",${SCANNERS}," == *",trivy,"* ]]; then
    if scan_trivy "${image}" "out/${safe}__trivy.json"; then
      reports+=("out/${safe}__trivy.json")
    else
      echo "    [warn] trivy failed on ${image}, skipping"
    fi
  fi
  if [[ ",${SCANNERS}," == *",grype,"* ]]; then
    if scan_grype "${image}" "out/${safe}__grype.json"; then
      reports+=("out/${safe}__grype.json")
    else
      echo "    [warn] grype failed on ${image}, skipping"
    fi
  fi

  if [[ ${#reports[@]} -eq 0 ]]; then
    echo "    [warn] no scans produced for ${image}, skipping triage"
    fail=$((fail + 1))
    continue
  fi

  echo "==> triaging ${image}"
  if "${PT[@]}" run "${reports[@]}" \
      --exposed --criticality high \
      --triage rules \
      --no-nvd \
      -o "out/${safe}__report.json" \
      --html "out/${safe}__report.html"; then
    ok=$((ok + 1))
  else
    echo "    [warn] triage failed on ${image}"
    fail=$((fail + 1))
  fi

  if [[ "${PRUNE}" == "1" ]]; then
    docker image rm -f "${image}" >/dev/null 2>&1 || true
  fi
done

echo
echo "scanned ok: ${ok}, skipped/failed: ${fail}"
echo "==> aggregating"
"$PY" aggregate.py out
echo
echo "Full table + plain-language verdict: benchmarks/out/BENCHMARKS.md"
echo "Per-image dashboards:                benchmarks/out/*__report.html"
