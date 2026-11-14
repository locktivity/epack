#!/usr/bin/env bash
# Prints the packages whose build differs under -tags components: those with
# files or imports the tag selects, and every package whose code or tests
# depend on one. The components test pass runs on these; the core pass has
# covered the rest with the same compiled code.
set -euo pipefail

cd "$(dirname "$0")/.."

shape='{{.ImportPath}} {{.GoFiles}} {{.CgoFiles}} {{.EmbedFiles}} {{.TestGoFiles}} {{.XTestGoFiles}} {{.Imports}} {{.TestImports}} {{.XTestImports}}'
tagged=$(comm -13 <(go list -f "$shape" ./... | sort) <(go list -tags components -f "$shape" ./... | sort) | cut -d' ' -f1 | sort -u | tr '\n' ' ')

packages=$(go list -tags components -test -f '{{.ImportPath}}|{{.ForTest}}|{{join .Deps ","}}' ./... \
  | awk -F'|' -v tagged="$tagged" '
    BEGIN { n = split(tagged, t, " "); for (i = 1; i <= n; i++) if (t[i] != "") is[t[i]] = 1 }
    {
      pkg = ($2 != "") ? $2 : $1
      sub(/ .*$/, "", pkg)
      sub(/\.test$/, "", pkg)
      if (pkg in is) { out[pkg] = 1; next }
      m = split($3, deps, ",")
      for (i = 1; i <= m; i++) { d = deps[i]; sub(/ .*$/, "", d); if (d in is) { out[pkg] = 1; break } }
    }
    END { for (p in out) print p }' | sort)

if [ -z "$packages" ]; then
  echo "no package differs under -tags components, which cannot be right: cmd/epack always does" >&2
  exit 1
fi
printf '%s\n' "$packages"
