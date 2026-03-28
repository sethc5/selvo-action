#!/usr/bin/env bash
# selvo GitHub Action — scan via API, no local CLI or source code needed.
# Requires: curl, jq (both pre-installed on ubuntu-latest).
set -euo pipefail

API="${SELVO_API_URL}/api/v1"
POLL_INTERVAL=5
POLL_TIMEOUT=600  # 10 minutes
SCAN_MODE="${SELVO_SCAN_MODE:-auto}"

# ── Detect scan method ──────────────────────────────────────────────────
# "auto" tries to collect real packages from the runner first (most accurate),
# falls back to reference scan if no package manager is found.

submit_scan() {
  if [ "$SCAN_MODE" = "reference" ]; then
    echo "Using reference scan (common packages, not runner-specific)"
    RESPONSE=$(curl -sf -X POST "${API}/analyze" \
      -H "Content-Type: application/json" \
      -H "X-API-Key: ${SELVO_API_KEY}" \
      -d "{\"ecosystem\": \"${SELVO_ECOSYSTEM}\", \"limit\": ${SELVO_LIMIT}}")
    echo "$RESPONSE"
    return
  fi

  # Try to collect real packages from the CI runner
  PKGS=""
  ECO="${SELVO_ECOSYSTEM}"
  if command -v dpkg-query >/dev/null 2>&1; then
    PKGS=$(dpkg-query -W -f='${db:Status-Abbrev}  ${Package}  ${Version}\n' 2>/dev/null || true)
    [ "$ECO" = "all" ] && ECO="ubuntu"
  elif command -v rpm >/dev/null 2>&1; then
    PKGS=$(rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null || true)
    [ "$ECO" = "all" ] && ECO="fedora"
  elif command -v apk >/dev/null 2>&1; then
    PKGS=$(apk info -v 2>/dev/null || true)
    [ "$ECO" = "all" ] && ECO="alpine"
  fi

  if [ -n "$PKGS" ]; then
    PKG_COUNT=$(echo "$PKGS" | wc -l)
    echo "Scanning ${PKG_COUNT} real packages from runner (${ECO})"
    PAYLOAD=$(python3 -c "import json,sys; print(json.dumps({'packages': sys.stdin.read(), 'ecosystem': '${ECO}'}))" <<< "$PKGS")
    RESPONSE=$(curl -sf -X POST "${API}/scan/packages" \
      -H "Content-Type: application/json" \
      -H "X-API-Key: ${SELVO_API_KEY}" \
      -d "$PAYLOAD")
    echo "$RESPONSE"
  else
    echo "No package manager found on runner — falling back to reference scan"
    RESPONSE=$(curl -sf -X POST "${API}/analyze" \
      -H "Content-Type: application/json" \
      -H "X-API-Key: ${SELVO_API_KEY}" \
      -d "{\"ecosystem\": \"${SELVO_ECOSYSTEM}\", \"limit\": ${SELVO_LIMIT}}")
    echo "$RESPONSE"
  fi
}

# ── Submit ──────────────────────────────────────────────────────────────

echo "::group::Submitting scan to selvo API"
SUBMIT_RESULT=$(submit_scan)
JOB_ID=$(echo "$SUBMIT_RESULT" | tail -1 | jq -r '.job_id // empty')
if [ -z "$JOB_ID" ]; then
  echo "::error::Failed to start scan. Response: $SUBMIT_RESULT"
  exit 1
fi
echo "Job submitted: $JOB_ID"
echo "::endgroup::"

# ── Poll for results ────────────────────────────────────────────────────

echo "::group::Waiting for results"
ELAPSED=0
while [ "$ELAPSED" -lt "$POLL_TIMEOUT" ]; do
  RESULT=$(curl -sf "${API}/jobs/${JOB_ID}" \
    -H "X-API-Key: ${SELVO_API_KEY}" || echo '{"status":"poll_error"}')

  STATUS=$(echo "$RESULT" | jq -r '.status')
  echo "  Status: $STATUS (${ELAPSED}s)"

  if [ "$STATUS" = "done" ]; then break; fi
  if [ "$STATUS" = "error" ]; then
    ERROR=$(echo "$RESULT" | jq -r '.error // "unknown error"')
    echo "::error::Scan failed: $ERROR"
    exit 1
  fi

  sleep "$POLL_INTERVAL"
  ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

if [ "$STATUS" != "done" ]; then
  echo "::error::Scan timed out after ${POLL_TIMEOUT}s"
  exit 1
fi
echo "::endgroup::"

# ── Parse results ───────────────────────────────────────────────────────
# Handle both analyze (top_5) and scan/packages (top_10) response formats

INNER=$(echo "$RESULT" | jq '.result')
TOTAL=$(echo "$INNER" | jq -r '.total_packages // 0')
WITH_CVES=$(echo "$INNER" | jq -r '.with_cves // 0')
KEV_COUNT=$(echo "$INNER" | jq -r '.kev_count // 0')

# top_10 from scan/packages, top_5 from analyze
TOP=$(echo "$INNER" | jq '.top_10 // .top_5 // []')
WEAPONIZED=$(echo "$TOP" | jq '[.[] | select(.exploit_maturity == "weaponized")] | length')
MAX_SCORE=$(echo "$TOP" | jq '[.[].score // 0] | max // 0')

# ── Set outputs ─────────────────────────────────────────────────────────

echo "total-packages=${TOTAL}" >> "$GITHUB_OUTPUT"
echo "packages-with-cves=${WITH_CVES}" >> "$GITHUB_OUTPUT"
echo "kev-count=${KEV_COUNT}" >> "$GITHUB_OUTPUT"
echo "weaponized-count=${WEAPONIZED}" >> "$GITHUB_OUTPUT"
echo "max-score=${MAX_SCORE}" >> "$GITHUB_OUTPUT"

# ── Write summary ──────────────────────────────────────────────────────

SOURCE=$(echo "$INNER" | jq -r '.source // "reference"')
SOURCE_LABEL="Reference scan"
[ "$SOURCE" = "your_system" ] && SOURCE_LABEL="Runner system packages"

cat >> "$GITHUB_STEP_SUMMARY" <<SUMMARY
## selvo Security Scan

> ${SOURCE_LABEL}

| Metric | Count |
|--------|-------|
| Packages scanned | **${TOTAL}** |
| With open CVEs | **${WITH_CVES}** |
| CISA KEV | **${KEV_COUNT}** |
| Weaponized exploits | **${WEAPONIZED}** |
| Max risk score | **${MAX_SCORE}** |

SUMMARY

# Top packages table
TOP_COUNT=$(echo "$TOP" | jq 'length')
if [ "$TOP_COUNT" -gt 0 ]; then
  cat >> "$GITHUB_STEP_SUMMARY" <<'TABLE_HEADER'
### Highest-risk packages

| # | Package | Score | CVEs | CVSS | EPSS |
|---|---------|-------|------|------|------|
TABLE_HEADER

  echo "$TOP" | jq -r '
    sort_by(-.score) | to_entries[] |
    "| \(.key + 1) | \(.value.name) | \(.value.score) | \(.value.cve_count // 0) | \(.value.max_cvss // 0) | \(.value.max_epss // 0) |"
  ' >> "$GITHUB_STEP_SUMMARY"
fi

echo "" >> "$GITHUB_STEP_SUMMARY"
echo "*Powered by [selvo](https://selvo.dev) — Linux dependency risk scanner*" >> "$GITHUB_STEP_SUMMARY"

# ── Gate checks ─────────────────────────────────────────────────────────

PASSED=true

if [ "${SELVO_FAIL_ON_KEV}" = "true" ] && [ "$KEV_COUNT" -gt 0 ]; then
  echo "::error::Gate failed: ${KEV_COUNT} CISA KEV package(s) found"
  PASSED=false
fi

if [ "${SELVO_FAIL_ON_WEAPONIZED}" = "true" ] && [ "$WEAPONIZED" -gt 0 ]; then
  echo "::error::Gate failed: ${WEAPONIZED} package(s) with weaponized exploits"
  PASSED=false
fi

SCORE_THRESHOLD="${SELVO_MIN_SCORE}"
if [ "$SCORE_THRESHOLD" != "0" ]; then
  OVER=$(echo "$TOP" | jq --argjson t "$SCORE_THRESHOLD" '[.[] | select(.score > $t)] | length')
  if [ "$OVER" -gt 0 ]; then
    echo "::error::Gate failed: ${OVER} package(s) scored above threshold ${SCORE_THRESHOLD}"
    PASSED=false
  fi
fi

echo "passed=${PASSED}" >> "$GITHUB_OUTPUT"

if [ "$PASSED" = "false" ]; then exit 1; fi
echo "All gates passed."
