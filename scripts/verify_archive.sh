#!/usr/bin/env bash
#
# verify_archive.sh — Verify the integrity of a patent archival preservation.
#
# Usage: ./scripts/verify_archive.sh [archive_directory]
#
# Defaults to ~/Documents/Archives/edr-graph-patent/2026-02-25/

set -euo pipefail

ARCHIVE_DIR="${1:-$HOME/Documents/Archives/edr-graph-patent/2026-02-25}"
PASS=0
FAIL=0
CHECKS=()

pass() {
    PASS=$((PASS + 1))
    CHECKS+=("PASS  $1")
    printf "  PASS  %s\n" "$1"
}

fail() {
    FAIL=$((FAIL + 1))
    CHECKS+=("FAIL  $1")
    printf "  FAIL  %s\n" "$1"
}

header() {
    printf "\n=== %s ===\n" "$1"
}

# --- Preflight ---
printf "Archive directory: %s\n" "$ARCHIVE_DIR"

if [ ! -d "$ARCHIVE_DIR" ]; then
    printf "ERROR: Archive directory does not exist: %s\n" "$ARCHIVE_DIR"
    exit 2
fi

# --- 1. SHA-256 Checksum Verification ---
header "SHA-256 Checksum Verification"

if [ ! -f "$ARCHIVE_DIR/SHA256SUMS.txt" ]; then
    fail "SHA256SUMS.txt exists"
else
    pass "SHA256SUMS.txt exists"

    # shasum -c requires paths relative to where the file references them,
    # so we verify each entry individually
    checksum_ok=true
    while IFS= read -r line; do
        # Skip comments and blank lines
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue

        hash=$(echo "$line" | awk '{print $1}')
        filepath=$(echo "$line" | awk '{$1=""; print substr($0,2)}')

        if [ ! -f "$filepath" ]; then
            fail "Checksum target exists: $(basename "$filepath")"
            checksum_ok=false
            continue
        fi

        actual_hash=$(shasum -a 256 "$filepath" | awk '{print $1}')
        if [ "$hash" = "$actual_hash" ]; then
            pass "SHA-256 OK: $(basename "$filepath")"
        else
            fail "SHA-256 MISMATCH: $(basename "$filepath")"
            checksum_ok=false
        fi
    done < "$ARCHIVE_DIR/SHA256SUMS.txt"

    if $checksum_ok; then
        pass "All checksums verified"
    fi
fi

# --- 2. GPG Signature Verification ---
header "GPG Signature Verification"

GPG=$(command -v gpg 2>/dev/null || echo "/opt/homebrew/bin/gpg")
if ! command -v "$GPG" &>/dev/null; then
    fail "GPG binary found"
    printf "  (install gnupg to verify signatures)\n"
else
    pass "GPG binary found: $GPG"

    # Import public key if present and not already in keyring
    if [ -f "$ARCHIVE_DIR/public-key.asc" ]; then
        $GPG --import "$ARCHIVE_DIR/public-key.asc" 2>/dev/null || true
    fi

    for ascfile in "$ARCHIVE_DIR"/*.asc; do
        [ -f "$ascfile" ] || continue
        basename_asc=$(basename "$ascfile")

        # public-key.asc is not a detached signature
        if [ "$basename_asc" = "public-key.asc" ]; then
            continue
        fi

        # Derive the signed file path (strip .asc)
        signed_file="${ascfile%.asc}"
        if [ ! -f "$signed_file" ]; then
            fail "Signed file exists for $basename_asc"
            continue
        fi

        gpg_output=$($GPG --verify "$ascfile" "$signed_file" 2>&1 || true)
        if echo "$gpg_output" | grep -q "Good signature"; then
            pass "GPG signature valid: $basename_asc"
        else
            fail "GPG signature invalid: $basename_asc"
        fi
    done
fi

# --- 3. Git Tag Verification ---
header "Git Tag Verification"

TAG_NAME="patent/provisional-filing-2026-02-25"
EXPECTED_COMMIT="8fc0bbad"

if git tag -l "$TAG_NAME" 2>/dev/null | grep -q "$TAG_NAME"; then
    pass "Git tag exists: $TAG_NAME"

    tag_commit=$(git rev-list -n 1 "$TAG_NAME" 2>/dev/null | cut -c1-8)
    if [ "$tag_commit" = "$EXPECTED_COMMIT" ]; then
        pass "Tag points to expected commit: $EXPECTED_COMMIT"
    else
        fail "Tag commit mismatch: expected $EXPECTED_COMMIT, got $tag_commit"
    fi

    tag_verify_output=$(git -c gpg.program="$GPG" tag -v "$TAG_NAME" 2>&1 || true)
    if echo "$tag_verify_output" | grep -q "Good signature"; then
        pass "Git tag signature valid"
    else
        fail "Git tag signature invalid (key may not be in keyring)"
    fi
else
    fail "Git tag exists: $TAG_NAME"
fi

# --- 4. Archive Contents Check ---
header "Archive Contents Check"

expected_files=(
    "ARCHIVE_MANIFEST.md"
    "SHA256SUMS.txt"
    "SHA256SUMS.txt.asc"
    "edr-graph-repo-2026-02-25.zip"
    "edr-graph-repo-2026-02-25.zip.asc"
    "uspto-filing-documents-2026-02-25.zip"
    "uspto-filing-documents-2026-02-25.zip.asc"
    "public-key.asc"
)

for f in "${expected_files[@]}"; do
    if [ -f "$ARCHIVE_DIR/$f" ]; then
        pass "File present: $f"
    else
        fail "File missing: $f"
    fi
done

# --- Summary ---
header "Summary"
TOTAL=$((PASS + FAIL))
printf "\n  %d/%d checks passed\n" "$PASS" "$TOTAL"

if [ "$FAIL" -gt 0 ]; then
    printf "  %d FAILED:\n" "$FAIL"
    for c in "${CHECKS[@]}"; do
        if [[ "$c" == FAIL* ]]; then
            printf "    - %s\n" "${c#FAIL  }"
        fi
    done
    printf "\nRESULT: FAIL\n"
    exit 1
else
    printf "\nRESULT: ALL CHECKS PASSED\n"
    exit 0
fi
