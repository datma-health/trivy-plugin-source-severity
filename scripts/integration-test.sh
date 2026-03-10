#!/usr/bin/env bash
# Integration test: build test images, scan with Trivy, pipe JSON through the
# plugin, and verify the plugin handles both the vulnerable and patched cases.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VULNERABLE_IMAGE="source-severity-vulnerable:local"
PATCHED_IMAGE="source-severity-patched:local"

cleanup() {
    docker rmi "$VULNERABLE_IMAGE" "$PATCHED_IMAGE" 2>/dev/null || true
}
trap cleanup EXIT

cd "$REPO_ROOT"

echo "==> Building plugin binary"
go build -o source-severity .

echo "==> Building test images"
docker build -f Dockerfile.vulnerable -t "$VULNERABLE_IMAGE" .
docker build -f Dockerfile.patched    -t "$PATCHED_IMAGE"    .

# ---------------------------------------------------------------------------
# Helper: scan an image with Trivy, run the plugin, and assert the outcome.
#   $1 - docker image name
#   $2 - "expect_findings"   → plugin must exit non-zero with a table (vulns found)
#        "expect_clean"      → plugin must exit 0 (no HIGH/CRITICAL findings)
# ---------------------------------------------------------------------------
run_plugin_test() {
    local image="$1"
    local expectation="$2"

    local scan_json
    scan_json="$(mktemp)"

    echo ""
    echo "==> Scanning $image"
    trivy image \
        --format json \
        --quiet \
        --exit-code 0 \
        --timeout 10m \
        "$image" > "$scan_json"

    if [ ! -s "$scan_json" ]; then
        rm -f "$scan_json"
        echo "FAIL [$image]: Trivy produced no output — scan may have failed silently"
        return 1
    fi

    local plugin_out
    plugin_out="$(mktemp)"
    set +e
    ./source-severity --severity-sources nvd < "$scan_json" > "$plugin_out" 2>&1
    local plugin_exit=$?
    set -e
    rm -f "$scan_json"

    local output
    output="$(cat "$plugin_out")"
    rm -f "$plugin_out"

    echo "$output"

    if [ "$expectation" = "expect_findings" ]; then
        if [ "$plugin_exit" -eq 0 ]; then
            echo "FAIL [$image]: plugin found no HIGH/CRITICAL vulnerabilities — image may have"
            echo "      been patched or the DB is stale. Vulnerabilities are expected."
            return 1
        fi
        if echo "$output" | grep -q "Total:"; then
            echo "PASS [$image]: plugin correctly detected and reported vulnerabilities"
            return 0
        fi
        echo "FAIL [$image]: plugin exited $plugin_exit but produced no vulnerability table —"
        echo "      it may have crashed before writing output."
        return 1
    fi

    if [ "$expectation" = "expect_clean" ]; then
        if [ "$plugin_exit" -eq 0 ]; then
            echo "PASS [$image]: plugin correctly found no HIGH/CRITICAL vulnerabilities after patching"
            return 0
        fi
        echo "FAIL [$image]: plugin exited $plugin_exit — unexpected vulnerabilities found in patched image:"
        echo "$output"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Test 1 — unpatched alpine:3.23.3: plugin MUST find HIGH/CRITICAL findings.
# ---------------------------------------------------------------------------
run_plugin_test "$VULNERABLE_IMAGE" "expect_findings"

# ---------------------------------------------------------------------------
# Test 2 — patched alpine:3.23.3 (apk upgrade): plugin MUST find nothing.
# ---------------------------------------------------------------------------
run_plugin_test "$PATCHED_IMAGE" "expect_clean"

# ---------------------------------------------------------------------------
# Test 3 — empty stdin (simulates Trivy scan failure / EOF).
# The plugin must exit 0 and not crash the pipeline.
# ---------------------------------------------------------------------------
echo ""
echo "==> Test: empty stdin (Trivy scan failure / EOF)"
plugin_out="$(mktemp)"
set +e
./source-severity --severity-sources nvd < /dev/null > "$plugin_out" 2>&1
eof_exit=$?
set -e
eof_output="$(cat "$plugin_out")"
rm -f "$plugin_out"

if [ $eof_exit -ne 0 ]; then
    echo "FAIL [empty stdin]: plugin crashed with exit $eof_exit — pipeline would have been killed:"
    echo "$eof_output"
    exit 1
fi
echo "PASS [empty stdin]: plugin handled EOF from Trivy gracefully (exit 0, no crash)"

echo ""
echo "==> All integration tests passed"
