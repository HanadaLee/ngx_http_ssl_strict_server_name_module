#!/usr/bin/env bash

set -euo pipefail

nginx_source="$(cd "${1:?Usage: apply-nginx-patches.sh <nginx-source>}" && pwd)"
module_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

while read -r patch_file; do
    patch_file="$module_root/patches/$patch_file"

    if patch --dry-run --batch --reverse --force --fuzz=0 \
        -d "$nginx_source" -p1 < "$patch_file" > /dev/null 2>&1
    then
        continue
    fi

    patch --dry-run --batch --forward --fuzz=0 \
        -d "$nginx_source" -p1 < "$patch_file"
    patch --batch --forward --fuzz=0 \
        -d "$nginx_source" -p1 < "$patch_file"
done < "$module_root/patches/series"
