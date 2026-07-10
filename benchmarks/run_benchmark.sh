#!/usr/bin/env bash
# Reproducible benchmark: PatchTriage vs CVSS-ordering on widely used
# open-source container images.
#
# Targets are pinned to specific, slightly-dated tags so results are
# reproducible and findings are guaranteed to exist. All targets are public
# images with millions of pulls — not systems we built ourselves.
#
# Requirements: patchtriage installed (pip install -e .) and EITHER
#   * trivy + grype binaries on PATH, OR
#   * docker (the script falls back to pinned aquasec/trivy and
#     anchore/grype container images — no local scanner install needed)
# Optional: NVD_API_KEY for full NVD enrichment (else run stays EPSS/KEV)
#
# Usage:  ./benchmarks/run_benchmark.sh
# Output: benchmarks/out/<image>__{trivy,grype,report}.json + BENCHMARKS.md

set -euo pipefail
cd "$(dirname "$0")"
mkdir -p out

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

# Pinned public targets (edit freely; keep tags pinned for reproducibility)
TARGETS=(
  "nginx:1.24"
  "redis:7.0"
  "postgres:15.2"
  "node:18.16-bullseye"
  "python:3.10-bullseye"
)

for image in "${TARGETS[@]}"; do
  safe="${image//[:\/]/_}"
  echo "==> scanning ${image}"
  scan_trivy "${image}" "out/${safe}__trivy.json"
  scan_grype "${image}" "out/${safe}__grype.json"

  echo "==> triaging ${image}"
  "${PT[@]}" run "out/${safe}__trivy.json" "out/${safe}__grype.json" \
    --exposed --criticality high \
    --triage rules \
    --no-nvd \
    -o "out/${safe}__report.json" \
    --html "out/${safe}__report.html"
done

echo
echo "==> aggregating"
"$PY" aggregate.py out
echo
echo "Full table + plain-language verdict: benchmarks/out/BENCHMARKS.md"
echo "Per-image dashboards:                benchmarks/out/*__report.html"
