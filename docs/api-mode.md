# api mode

use sif's json output for automation and integration.

## enabling api mode

```bash
./sif -u https://example.com -api
```

## output format

api mode outputs json to stdout:

```json
{
  "url": "https://example.com",
  "results": [
    {
      "id": "module-id",
      "data": {
        "module_id": "module-id",
        "target": "https://example.com",
        "findings": [
          {
            "url": "https://example.com/.git/HEAD",
            "severity": "high",
            "evidence": "ref: refs/heads/main",
            "extracted": {
              "branch": "main"
            }
          }
        ]
      }
    }
  ]
}
```

## fields

### url

the target url that was scanned.

### results

array of module results.

### results[].id

module identifier.

### results[].data.findings

array of security findings from the module.

### findings[].url

the specific url where the finding was detected.

### findings[].severity

severity level: `info`, `low`, `medium`, `high`, `critical`

### findings[].evidence

evidence that triggered the finding (matched content, etc).

### findings[].extracted

extracted data from the response (versions, keys, etc).

## examples

### save to file

```bash
./sif -u https://example.com -api -am > results.json
```

### pipe to jq

```bash
./sif -u https://example.com -api -am | jq '.results[].data.findings[]'
```

### filter high severity

```bash
./sif -u https://example.com -api -am | jq '.results[].data.findings[] | select(.severity == "high")'
```

### extract urls

```bash
./sif -u https://example.com -api -am | jq -r '.results[].data.findings[].url'
```

## ci/cd integration

### github actions

```yaml
- name: run sif scan
  run: |
    ./sif -u ${{ env.TARGET_URL }} -api -am > sif-results.json

- name: check for high severity findings
  run: |
    HIGH_COUNT=$(jq '[.results[].data.findings[] | select(.severity == "high" or .severity == "critical")] | length' sif-results.json)
    if [ "$HIGH_COUNT" -gt 0 ]; then
      echo "Found $HIGH_COUNT high/critical severity findings"
      exit 1
    fi
```

### gitlab ci

```yaml
security_scan:
  script:
    - ./sif -u $TARGET_URL -api -am > sif-results.json
    - |
      if jq -e '.results[].data.findings[] | select(.severity == "critical")' sif-results.json > /dev/null; then
        echo "Critical findings detected"
        exit 1
      fi
  artifacts:
    paths:
      - sif-results.json
```

## multiple targets

when scanning multiple urls, each target outputs a separate json object:

```bash
./sif -u https://site1.com,https://site2.com -api
```

outputs:

```json
{"url":"https://site1.com","results":[...]}
{"url":"https://site2.com","results":[...]}
```

use `jq -s` to combine into an array:

```bash
./sif -u https://site1.com,https://site2.com -api | jq -s '.'
```

## notes

- api mode suppresses banner and interactive output
- all output goes to stdout
- errors and warnings still go to stderr
- combine with `-l` flag to also save detailed logs
