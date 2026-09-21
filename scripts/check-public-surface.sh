#!/usr/bin/env bash
# Pre-publication gate: this repository is public, so every tracked byte is
# published. The gate fails when a file that must stay internal is tracked,
# when tracked text carries a credential shape, a personal path, an account
# id or a reference to internal material, or when a built distribution would
# ship any of those.
#
# The rules written here are generic. The words that would themselves reveal
# internal material — names of private repositories, directories, documents
# and data — are the private patterns: one extended regular expression per
# line, read from $PUBLIC_SURFACE_PRIVATE_PATTERNS or from the gitignored file
# scripts/public-surface-private-patterns.txt, and applied to every tracked
# path, every tracked file's content and every distribution listing. In CI
# they come from a repository secret; a run in CI without them fails unless
# PUBLIC_SURFACE_PRIVATE_PATTERNS_OPTIONAL=1 (a fork's pull request, which
# cannot read secrets).
#
# Usage: scripts/check-public-surface.sh [dist-dir]
#   With a dist directory, the sdist and pure-Python wheel listings are checked too.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
failures=0

fail() {
  echo "gate: $*" >&2
  failures=$((failures + 1))
}

tracked() {
  git ls-files -z
}

# 0. Private patterns.
private_file="scripts/public-surface-private-patterns.txt"
private_patterns=()
if [[ -n "${PUBLIC_SURFACE_PRIVATE_PATTERNS:-}" ]]; then
  source_name="\$PUBLIC_SURFACE_PRIVATE_PATTERNS"
  private_text="$PUBLIC_SURFACE_PRIVATE_PATTERNS"
elif [[ -f "$private_file" ]]; then
  source_name="$private_file"
  private_text=$(cat "$private_file")
else
  source_name=""
  private_text=""
fi
while IFS= read -r line; do
  [[ -z "$line" || "$line" == \#* ]] && continue
  private_patterns+=("$line")
done <<<"$private_text"
if (( ${#private_patterns[@]} == 0 )); then
  if [[ -n "${GITHUB_ACTIONS:-}" && "${PUBLIC_SURFACE_PRIVATE_PATTERNS_OPTIONAL:-}" != 1 ]]; then
    fail "no private patterns: set the PUBLIC_SURFACE_PRIVATE_PATTERNS secret"
  else
    echo "gate: no private patterns loaded; generic rules only" >&2
  fi
else
  echo "gate: ${#private_patterns[@]} private pattern(s) from $source_name" >&2
fi

# 1. Every tracked path must be one the repository is allowed to publish, and
#    no tracked path may be the private pattern file, a credential file, a
#    private-pattern match, or a policy file outside the test fixtures.
allowed_paths='^(src/iltero_schemas/|tests/|docs/|scripts/|\.github/|pyproject\.toml$|pdm\.lock$|README\.md$|CHANGELOG\.md$|CONTRIBUTING\.md$|CODE_OF_CONDUCT\.md$|SECURITY\.md$|LICENSE$|\.gitignore$|\.gitattributes$|\.markdownlint-cli2\.jsonc$|\.pre-commit-config\.yaml$)'
credential_files='(^|/)(\.env[^/]*|[^/]*\.(pem|key|p12|pfx)|id_(rsa|ed25519|ecdsa)[^/]*)$'
while IFS= read -r -d '' path; do
  if ! [[ "$path" =~ $allowed_paths ]]; then
    fail "tracked path is not on the allowlist: $path"
  fi
  if [[ "$path" == "$private_file" ]]; then
    fail "the private pattern file is tracked: $path"
  fi
  if [[ "$path" =~ $credential_files ]]; then
    fail "credential file is tracked: $path"
  fi
  for pattern in "${private_patterns[@]+"${private_patterns[@]}"}"; do
    if [[ "$path" =~ $pattern ]]; then fail "tracked path matches a private pattern: $path"; fi
  done
  # A policy file outside the test fixtures is a hand-maintained policy library.
  if [[ "$path" == *.rego && "$path" != tests/fixtures/* ]]; then
    fail "tracked Rego outside tests/fixtures/: $path"
  fi
done < <(tracked)

# 2. No tracked binary images or oversized files (the vendored evaluator is never tracked).
while IFS= read -r -d '' path; do
  [[ -f "$path" ]] || continue
  size=$(wc -c < "$path")
  if (( size > 1048576 )) && [[ "$path" != tests/fixtures/* ]]; then
    fail "tracked file larger than 1 MiB: $path"
  fi
  # Captured tool output is text; an executable image is never a fixture.
  magic=$(head -c 4 "$path" | od -An -tx1 | tr -d ' \n')
  case "$magic" in
    7f454c46|4d5a????|feedface|feedfacf|cffaedfe|cefaedfe) fail "tracked executable image: $path" ;;
  esac
done < <(tracked)

# 3. Forbidden content in tracked text: credential shapes, personal paths,
#    cloud account ids, a local service address, references to internal documents
#    (section signs), and the private patterns. A matched token listed in the
#    allowlist file is exempt from the generic rules only, and every
#    allowlisted token must occur in a tracked file under src/ or tests/ (a
#    documented constant), so the allowlist cannot carry anything on its own.
allowlist_file="scripts/public-surface-allowlist.txt"
generic_patterns=(
  '/Users/[^/[:space:]"'"'"']+'
  '/home/[^/[:space:]"'"'"']+'
  'C:\\Users\\[^\\[:space:]"'"'"']+'
  '\b[0-9]{12}\b'
  'arn:aws[a-z-]*:'
  'AKIA[0-9A-Z]{16}'
  'ASIA[0-9A-Z]{16}'
  'gh[pousr]_[A-Za-z0-9]{20,}'
  'ilt_[a-z][A-Za-z0-9_-]{8,}'
  '-----BEGIN [A-Z ]*PRIVATE KEY-----'
  'eyJ[A-Za-z0-9_-]{10,}\.eyJ'
  'localhost:[0-9]{4,5}'
  '§'
)
# The files that keep internal material out of the tree may name it.
private_exempt='^(\.gitignore|\.markdownlint-cli2\.jsonc|pyproject\.toml)$'
allowlisted() {  # $1 = matched token
  [[ -f "$allowlist_file" ]] && grep -qxF -- "$1" "$allowlist_file"
}
check_content() {  # $1 = path, $2 = pattern, $3 = exempt-through-allowlist (yes|no)
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    token="${hit#*:}"
    if [[ "$3" == yes ]] && allowlisted "$token"; then continue; fi
    fail "forbidden content in $1 (pattern $2): line ${hit%%:*}: ${token:0:80}"
  done < <(grep -noE -- "$2" "$1" 2>/dev/null || true)
}
while IFS= read -r -d '' path; do
  [[ -f "$path" ]] || continue
  [[ "$path" == scripts/check-public-surface.sh || "$path" == "$allowlist_file" ]] && continue
  case "$path" in *.png|*.jpg|*.gif|*.ico|*.woff*) continue ;; esac
  for pattern in "${generic_patterns[@]}"; do check_content "$path" "$pattern" yes; done
  if ! [[ "$path" =~ $private_exempt ]]; then
    for pattern in "${private_patterns[@]+"${private_patterns[@]}"}"; do check_content "$path" "$pattern" no; done
  fi
done < <(tracked)
if [[ -f "$allowlist_file" ]]; then
  while IFS= read -r token; do
    [[ -z "$token" || "$token" == \#* ]] && continue
    if ! git grep -qF -- "$token" -- src tests; then
      fail "allowlisted token is not a constant in src/ or tests/: ${token:0:80}"
    fi
  done < "$allowlist_file"
fi

# 4. Fixtures must be listed in the manifest with their source.
if [[ -d tests/fixtures ]]; then
  manifest="tests/fixtures/MANIFEST.json"
  [[ -f "$manifest" ]] || fail "tests/fixtures exists without $manifest"
  while IFS= read -r -d '' path; do
    [[ "$path" == "$manifest" ]] && continue
    if [[ -f "$manifest" ]] && ! grep -qF -- "\"${path#tests/fixtures/}\"" "$manifest"; then
      fail "fixture not listed in $manifest: $path"
    fi
  done < <(git ls-files -z tests/fixtures)
fi

# 5. What the CLI writes never carries a compliance-framework mapping: no
#    golden output file has a key that names one.
if [[ -d tests/golden ]]; then
  framework_keys='"(framework[a-z_]*|control_id|controls)"[[:space:]]*:'
  while IFS= read -r -d '' path; do
    if grep -qE -- "$framework_keys" "$path"; then fail "golden file carries a framework key: $path"; fi
  done < <(git ls-files -z tests/golden)
fi

# 6. No committed document links to a gitignored location or outside the tree.
while IFS= read -r -d '' path; do
  [[ "$path" == *.md ]] || continue
  while IFS= read -r target; do
    [[ -z "$target" ]] && continue
    case "$target" in http://*|https://*|mailto:*|\#*) continue ;; esac
    resolved=$(python3 -c 'import os, sys; print(os.path.normpath(os.path.join(sys.argv[1], sys.argv[2])))' "$(dirname "$path")" "${target%%#*}")
    if [[ "$resolved" == ../* ]] || git check-ignore -q "$resolved"; then
      fail "$path links to an internal location: $target"
    fi
  done < <(grep -oE '\]\([^)]+\)' "$path" | sed -E 's/^\]\(//; s/\)$//' || true)
done < <(tracked)

# 7. A built distribution must not carry anything the tree may not: a path
#    that is not on the allowlist, is gitignored, or matches a private pattern.
if [[ $# -ge 1 && -d "$1" ]]; then
  for archive in "$1"/*.tar.gz; do
    [[ -f "$archive" ]] || continue
    while IFS= read -r member; do
      rel="${member#*/}"
      [[ -z "$rel" || "$rel" == */ ]] && continue
      [[ "$rel" == PKG-INFO ]] && continue
      if ! [[ "$rel" =~ $allowed_paths ]] || [[ "$rel" == tests/* || "$rel" == scripts/* || "$rel" == docs/* ]]; then
        fail "$(basename "$archive") contains $rel"
        continue
      fi
      if git check-ignore -q "$rel"; then fail "$(basename "$archive") contains gitignored $rel"; fi
      for pattern in "${private_patterns[@]+"${private_patterns[@]}"}"; do
        if [[ "$rel" =~ $pattern ]]; then fail "$(basename "$archive") contains a private-pattern match: $rel"; fi
      done
    done < <(tar tzf "$archive")
  done
  for wheel in "$1"/*-none-any.whl; do
    [[ -f "$wheel" ]] || continue
    if unzip -l "$wheel" | grep -q _vendor; then fail "$wheel contains a vendored binary"; fi
  done
fi

if (( failures > 0 )); then
  echo "gate: $failures problem(s)" >&2
  exit 1
fi
echo "gate: ok"
