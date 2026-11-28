#!/usr/bin/env bash
# Fails when a workflow uses a GitHub Action or a container image that is not
# pinned immutably:
#   - actions and reusable workflows must use a full 40-character commit SHA;
#   - docker:// actions and container/service images must use @sha256:<digest>.
# Local actions (./path) are skipped.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workflows_dir="$repo_root/.github/workflows"
status=0

normalize() {
  local value="$1"
  value="${value%%[[:space:]]#*}"
  value="${value//\"/}"
  value="${value//\'/}"
  value="${value//[[:space:]]/}"
  printf '%s' "$value"
}

while IFS= read -r entry; do
  file="${entry%%:*}"
  value="$(normalize "${entry#*:}")"

  case "$value" in
    ./*) continue ;;
    docker://*)
      if [[ ! "$value" =~ ^docker://[^@[:space:]]+@sha256:[0-9a-f]{64}$ ]]; then
        printf 'Container action not pinned by digest: %s: %s\n' "$file" "$value" >&2
        status=1
      fi
      continue
      ;;
  esac

  if [[ ! "$value" =~ ^[^/@]+/[^/@]+(/[^@]+)?@[0-9a-f]{40}$ ]]; then
    printf 'Mutable or invalid GitHub Action reference: %s: %s\n' "$file" "$value" >&2
    status=1
  fi
done < <(
  grep -RHE '^[[:space:]-]*uses:[[:space:]]*' "$workflows_dir" |
    sed -E 's/^([^:]+):[[:space:]-]*uses:[[:space:]]*/\1:/'
)

# Job containers and service containers: `image: ...` or `container: <image>`.
while IFS= read -r entry; do
  file="${entry%%:*}"
  value="$(normalize "${entry#*:}")"
  [[ -z "$value" ]] && continue

  if [[ ! "$value" =~ ^[^@[:space:]]+@sha256:[0-9a-f]{64}$ ]]; then
    printf 'Container image not pinned by digest: %s: %s\n' "$file" "$value" >&2
    status=1
  fi
done < <(
  grep -RHE '^[[:space:]-]*(image|container):[[:space:]]*[^[:space:]#]' "$workflows_dir" |
    sed -E 's/^([^:]+):[[:space:]-]*(image|container):[[:space:]]*/\1:/'
)

exit "$status"
