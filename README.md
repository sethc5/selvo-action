# selvo Security Scan Action

Scan your Linux infrastructure packages for CVEs, exploit maturity, CISA KEV status, and SLA breaches — directly in your CI pipeline.

No local CLI install required. This action calls the [selvo API](https://selvo.fly.dev) using `curl` + `jq`.

## Usage

```yaml
- uses: sethc5/selvo-action@v1
  with:
    api-key: ${{ secrets.SELVO_API_KEY }}
    ecosystem: debian
    limit: 50
```

### Fail on critical findings

```yaml
- uses: sethc5/selvo-action@v1
  with:
    api-key: ${{ secrets.SELVO_API_KEY }}
    ecosystem: debian
    fail-on-kev: "true"
    fail-on-weaponized: "true"
    min-score: 60
```

### Use outputs in later steps

```yaml
- uses: sethc5/selvo-action@v1
  id: selvo
  with:
    api-key: ${{ secrets.SELVO_API_KEY }}

- run: echo "Found ${{ steps.selvo.outputs.kev-count }} KEV packages"
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api-key` | Yes | — | selvo API key |
| `ecosystem` | No | `all` | Ecosystem to scan |
| `limit` | No | `50` | Max packages to return |
| `fail-on-kev` | No | `false` | Fail if CISA KEV packages found |
| `fail-on-weaponized` | No | `false` | Fail if weaponized exploits found |
| `min-score` | No | `0` | Fail if any score exceeds this (0 = disabled) |
| `api-url` | No | `https://selvo.fly.dev` | API base URL |

## Outputs

| Output | Description |
|--------|-------------|
| `total-packages` | Total packages analyzed |
| `packages-with-cves` | Packages with CVEs |
| `kev-count` | CISA KEV packages |
| `weaponized-count` | Packages with weaponized exploits |
| `max-score` | Highest risk score |
| `passed` | `true` if all gates passed |

## How it works

1. POSTs to the selvo API to start an analysis
2. Polls for results (5s interval, 10min timeout)
3. Parses results with `jq`
4. Writes a summary table to `$GITHUB_STEP_SUMMARY`
5. Checks gates (KEV, weaponized, score threshold)
6. Exits non-zero if any gate fails

No Python, no pip install, no source code — just `curl` and `jq` on `ubuntu-latest`.

## Get an API key

1. Go to [selvo.fly.dev](https://selvo.fly.dev)
2. Sign up for a free account
3. Add your API key as a repository secret named `SELVO_API_KEY`

## License

MIT
