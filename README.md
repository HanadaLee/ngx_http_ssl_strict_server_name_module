# ngx_http_ssl_strict_server_name_module

Controls nginx's check for a difference between the negotiated TLS Server Name Indication (SNI) and the HTTP request host. Supports HTTP/1.x, HTTP/2, and HTTP/3.

## Table of Contents

- [Synopsis](#synopsis)
- [Installation](#installation)
- [Conditional configuration](#conditional-configuration)
- [Directives](#directives)
  - [ssl_strict_server_name](#ssl_strict_server_name)
- [Tests](#tests)
- [Author and license](#author-and-license)

## Synopsis

```nginx
http {
    ssl_strict_server_name on;

    server {
        listen 443 ssl default_server;
        server_name example.com www.example.com;

        ssl_certificate example.com.crt;
        ssl_certificate_key example.com.key;

        location / {
            root /srv/www/example.com;
        }
    }

    server {
        listen 443 ssl;
        server_name example.org;

        ssl_certificate example.org.crt;
        ssl_certificate_key example.org.key;

        location / {
            root /srv/www/example.org;
        }
    }
}
```

Both servers inherit `ssl_strict_server_name on;`:

| SNI | Request Host | Result |
| :--- | :--- | :--- |
| `example.com` | `example.com` | Pass |
| `example.org` | `example.org` | Pass |
| `example.com` | `example.org` | 421 |
| `example.com` | `www.example.com` | 421 |
| Absent | `example.com` | Pass |
| `unknown.example` | `example.com` | Pass |

Different aliases in the same server, such as `example.com` and `www.example.com`, are still considered different names.

## Installation

Requires nginx with `--with-http_ssl_module`. Configuration fails if HTTP SSL support is disabled.

To let this module control nginx's built-in SNI check, apply the bundled core patch:

```sh
bash /path/to/ngx_http_ssl_strict_server_name_module/util/apply-nginx-patches.sh /path/to/nginx
```

For a static build, run from the nginx source directory:

```sh
./configure \
    --with-http_ssl_module \
    --add-module=/path/to/ngx_http_ssl_strict_server_name_module
make
```

Dynamic modules are not supported.

Add `--with-http_realip_module` when using real-IP configuration. HTTP/2 and HTTP/3 require their corresponding nginx modules.

## Conditional configuration

Build `ngx_expr_module` statically in the same nginx configuration to enable `when` conditions. The check runs after realip, so conditions can use the restored client address in `$remote_addr`.

For example, exempt a client behind a trusted local proxy:

```nginx
set_real_ip_from 127.0.0.1;
real_ip_header X-Real-IP;

expr exempt_client str_eq $remote_addr 192.0.2.10;
when exempt_client {
    ssl_strict_server_name off;
}

ssl_strict_server_name on;
```

Conditions are evaluated for each request, including requests that reuse an HTTP/2 or HTTP/3 connection.

## Directives

### ssl_strict_server_name

| Syntax: | **ssl_strict_server_name** `on` \| `off` \| `auto`; |
| :--- | :--- |
| Default: | `ssl_strict_server_name auto;` |
| Context: | `http`, `server`, `when` |

Controls SNI validation for the request server:

- `on`: returns 421 (Misdirected Request) when the request host differs from the SNI recorded by nginx, regardless of `ssl_verify_client`.
- `off`: disables the module's check.
- `auto`: retains nginx's default SNI policy. When SNI selected a virtual server, a differing request host is rejected if the request server's `ssl_verify_client` is not `off`.

If nginx has not recorded an SNI match, this check is skipped, as in nginx itself. This includes missing or unmatched SNI and single-server listeners where nginx omits name lookup.

Names are compared after normalization: case, a trailing dot, and the request host's port do not affect the comparison. Wildcard and regular-expression server names are supported; different names matching the same pattern are still considered different.

Validation runs in `post_read`, after request headers have been read and before rewrite processing. Plain HTTP requests are unaffected.

> On unmodified nginx, the built-in SNI check remains active. Disabling it with `off` requires the bundled [core patch](patches/nginx-1.31.8+.patch).

## Tests

The tests use the nginx-tests framework. They cover directive contexts, inheritance, conditional configuration, realip ordering, TLS 1.2 and TLS 1.3, HTTP/1.x, HTTP/2, HTTP/3, and connection reuse.

Place the nginx and nginx-tests source trees in `.ci/nginx` and `.ci/nginx-tests`, then run:

```sh
bash util/run-tests.sh
```

For conditional configuration tests, also place `ngx_expr_module` in `.ci/ngx_expr_module` and enable expression support:

```sh
TEST_EXPR=enabled bash util/run-tests.sh
TEST_CORE_PATCH=disabled TEST_EXPR=enabled bash util/run-tests.sh
```

The runner requires a C build toolchain, PCRE2, OpenSSL, zlib, Perl, and IO::Socket::SSL. HTTP/3 tests additionally require CryptX. Failure logs are saved in `.ci/test-output`.

## Author and license

Copyright (C) Hanada

Licensed under the [BSD 2-Clause License](LICENSE).
