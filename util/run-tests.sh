#!/usr/bin/env bash

set -euo pipefail

module_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
nginx_source="${TEST_NGINX_SOURCE:-$module_root/.ci/nginx}"
nginx_tests="${TEST_NGINX_TESTS:-$module_root/.ci/nginx-tests}"
expr_source="${TEST_EXPR_SOURCE:-$module_root/.ci/ngx_expr_module}"
test_output="$module_root/.ci/test-output"
mkdir -p "$test_output"
exec > >(tee "$test_output/run.log") 2>&1

export TEST_NGINX_SSL_STRICT_CORE=0
if [[ "${TEST_CORE_PATCH:-enabled}" == enabled ]]; then
    bash "$module_root/util/apply-nginx-patches.sh" "$nginx_source"
    export TEST_NGINX_SSL_STRICT_CORE=1
fi

cd "$nginx_source"
configure=./configure
[[ -f "$configure" ]] || configure=auto/configure

module_arg="--add-module=$module_root"

if sh "$configure" "$module_arg" > "$test_output/no-ssl.log" 2>&1; then
    echo 'configure unexpectedly accepted a build without HTTP SSL'
    exit 1
fi
grep -F 'requires --with-http_ssl_module' "$test_output/no-ssl.log"

configure_args=(
    --with-debug
    --with-http_ssl_module
    --with-http_realip_module
    --with-http_v2_module
    --with-http_v3_module
)
[[ -z "${TEST_CC_OPT:-}" ]] || configure_args+=("--with-cc-opt=$TEST_CC_OPT")
[[ -z "${TEST_LD_OPT:-}" ]] || configure_args+=("--with-ld-opt=$TEST_LD_OPT")
if [[ "${TEST_EXPR:-disabled}" == enabled ]]; then
    configure_args+=(--with-http_json_module "--add-module=$expr_source")
fi
if sh "$configure" "${configure_args[@]}" "--add-dynamic-module=$module_root" \
    > "$test_output/dynamic-rejected.log" 2>&1
then
    echo 'configure unexpectedly accepted a dynamic module'
    exit 1
fi
grep -F 'must be built with --add-module' "$test_output/dynamic-rejected.log"

sh "$configure" "${configure_args[@]}" "$module_arg"
make -j"${TEST_BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN)}"

export TEST_NGINX_BINARY="$nginx_source/objs/nginx"
export PERL5LIB="$nginx_tests/lib${PERL5LIB:+:$PERL5LIB}"
export TMPDIR="$(mktemp -d /tmp/nginx-ssl-strict.XXXXXX)"
export TEST_NGINX_LEAVE=1
if [[ "$(id -u)" == 0 ]]; then
    export TEST_NGINX_GLOBALS="${TEST_NGINX_GLOBALS:-} user root;"
fi
trap 'find "$TMPDIR" -type f -name "*.log" -exec cp --parents {} "$test_output/" \;' EXIT

cd "$module_root"
prove -v t/*.t
