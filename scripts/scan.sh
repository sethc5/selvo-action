#!/usr/bin/env bash
# selvo GitHub Action — scan via API, no local CLI or source code needed.
# Requires: curl, jq (both pre-installed on ubuntu-latest).
set -euo pipefail

API="${SELVO_API_URL}/api/v1"
POLL_INTERVAL=5
POLL_TIMEOUT=600  # 10 minutes

# ── Submit analysis job ─────────────────────────────────────────────────

echo "::group::Submitting analysis to selvo API"
RESPONSE=$(curl -sf -X POST "${API}/analyze" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${SELVO_API_KEY}" \
  -d "{\"ecosystem\": \"${SELVO_ECOSYSTEM}\", \"limit\": ${SELVO_LIMIT}}")

JOB_ID=$(echo "$RESPONSE" | jq -r '.job_id')
if [ -z "$JOB_ID" ] || [ "$JOB_ID" = "null" ]; then
  echo "::error::Failed to start analysis job. Response: $RESPONSE"
  exit 1
fi
echo "Job submitted: $JOB_ID"
echo "::endgroup::"

# ── Poll for results ────────────────────────────────────────────────────

echo "::group::Waiting for results"
ELAPSED=0
while [ "$ELAPSED" -lt "$POLL_TIMEOUT" ]; do
  RESULT=$(curl -sf "${API}/jobs/${JOB_ID}" \
    -H "X-API-Key: ${SELVO_API_KEY}")

  STATUS=$(echo "$RESULT" | jq -r '.status')
  echo "  Status: $STATUS (${ELAPSED}s)"

  if [ "$STATUS" = "done" ]; then
    break
  fi
  if [ "$STATUS" = "error" ]; then
    ERROR=$(echo "$RESULT" | jq -r '.error // "unknown error"')
    echo "::error::Analysis failed: $ERROR"
    exit 1
  fi

  sleep "$POLL_INTERVAL"
  ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

if [ "$STATUS" != "done" ]; then
  echo "::error::Analysis timed out after ${POLL_TIMEOUT}s"
  exit 1
fi
echo "::endgroup::"

# ── Parse results ───────────────────────────────────────────────────────

PACKAGES=$(echo "$RESULT" | jq -r '.result.packages // []')
TOTAL=$(echo "$PACKAGES" | jq 'length')
WITH_CVES=$(echo "$PACKAGES" | jq '[.[] | select((.cve_ids // []) | length > 0)] | length')
KEV_COUNT=$(echo "$PACKAGES" | jq '[.[] | select(.in_cisa_kev == true)] | length')
WEAPONIZED=$(echo "$PACKAGES" | jq '[.[] | select(.exploit_maturity == "weaponized")] | length')
MAX_SCORE=$(echo "$PACKAGES" | jq '[.[].score // 0] | max // 0')
OUTDATED=$(echo "$PACKAGES" | jq '[.[] | select(.is_outdated == true)] | length')
SLA_BREACH=$(echo "$PACKAGES" | jq '[.[] | select(.sla_band == "breach" or .sla_band == "critical")] | length')

# ── Set outputs ─────────────────────────────────────────────────────────

echo "total-packages=${TOTAL}" >> "$GITHUB_OUTPUT"
echo "packages-with-cves=${WITH_CVES}" >> "$GITHUB_OUTPUT"
echo "kev-count=${KEV_COUNT}" >> "$GITHUB_OUTPUT"
echo "weaponized-count=${WEAPONIZED}" >> "$GITHUB_OUTPUT"
echo "max-score=${MAX_SCORE}" >> "$GITHUB_OUTPUT"

# ── Write summary ──────────────────────────────────────────────────────

cat >> "$GITHUB_STEP_SUMMARY" <<SUMMARY
## selvo Security Scan

| Metric | Count |
|--------|-------|
| Packages analyzed | **${TOTAL}** |
| With CVEs | **${WITH_CVES}** |
| CISA KEV | **${KEV_COUNT}** |
| Weaponized exploits | **${WEAPONIZED}** |
| Outdated | **${OUTDATED}** |
| SLA breaches | **${SLA_BREACH}** |
| Max risk score | **${MAX_SCORE}** |

SUMMARY

# Top 10 riskiest packages
if [ "$TOTAL" -gt 0 ]; then
  cat >> "$GITHUB_STEP_SUMMARY" <<'TABLE_HEADER'
### Top packages by risk score

| # | Package | Score | CVEs | KEV | Exploit |
|---|---------|-------|------|-----|---------|
TABLE_HEADER

  echo "$PACKAGES" | jq -r '
    sort_by(-.score) | .[0:10] | to_entries[] |
    "| \(.key + 1) | \(.value.name) | \(.value.score) | \((.value.cve_ids // []) | length) | \(if .value.in_cisa_kev then "YES" else "-" end) | \(.value.exploit_maturity // "-") |"
  ' >> "$GITHUB_STEP_SUMMARY"
fi

echo "" >> "$GITHUB_STEP_SUMMARY"
echo "*Powered by [selvo](https://selvo.fly.dev) — Linux dependency risk scanner*" >> "$GITHUB_STEP_SUMMARY"

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
  OVER=$(echo "$PACKAGES" | jq --argjson t "$SCORE_THRESHOLD" '[.[] | select(.score > $t)] | length')
  if [ "$OVER" -gt 0 ]; then
    echo "::error::Gate failed: ${OVER} package(s) scored above threshold ${SCORE_THRESHOLD}"
    PASSED=false
  fi
fi

echo "passed=${PASSED}" >> "$GITHUB_OUTPUT"

if [ "$PASSED" = "false" ]; then
  exit 1
fi

echo "All gates passed."
