#!/usr/bin/perl

# Strict matching of TLS SNI and the HTTP request server name.

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http http_ssl rewrite socket_ssl_sni/)
	->has_daemon('openssl');
my $d = $t->testdir();
my $h2 = $t->has_module('http_v2') && $t->has_feature('socket_ssl_alpn');
my $h3 = $t->has_module('http_v3') && $t->has_feature('cryptx');
my $expr = $t->has_module('ngx_expr_module');
my $ext = $ENV{TEST_NGINX_EXT} // 0;

if ($h2) { require Test::Nginx::HTTP2; }
if ($h3) { require Test::Nginx::HTTP3; }

my $listen = 'listen 127.0.0.1:8080; listen 127.0.0.1:8443 ssl;';
$listen .= ' listen 127.0.0.1:%%PORT_8980_UDP%% quic;' if $h3;
my $single = 'listen 127.0.0.1:8445 ssl;';
$single .= ' listen 127.0.0.1:%%PORT_8981_UDP%% quic;' if $h3;
my $http2 = $h2 ? 'http2 on;' : '';
my ($policies, $servers) = ('', '');
my $verify_policy = $expr ? 'when skip_strict { ssl_strict_server_name off; }' : '';

if ($expr) {
	$policies = <<'EOF';
    expr skip_strict str_eq $http_x_strict off;
    when skip_strict {
        ssl_strict_server_name off;
    }
EOF
	$servers = <<'EOF';
    server {
        LISTEN
        server_name conditional.test;

        expr policy_host str_eq $host conditional.test;
        expr policy_uri str_eq $uri /check;
        expr policy_header str_eq $http_x_strict on;
        expr policy and policy_host policy_uri policy_header;
        when policy {
            ssl_strict_server_name on;
        }
        ssl_strict_server_name off;

        return 200 ok;
    }

    server {
        LISTEN
        server_name scoped.test;
        expr skip_strict str_eq $http_x_strict skip;

        return 200 ok;
    }

    server {
        LISTEN
        server_name realip.test;
        set_real_ip_from 127.0.0.1;
        real_ip_header X-Real-IP;
        expr allowed_client str_eq $remote_addr 192.0.2.10;
        when allowed_client { ssl_strict_server_name off; }
        ssl_strict_server_name on;

        return 200 ok;
    }

    server {
        LISTEN
        server_name first.test;
        expr first bool true;
        expr second bool true;
        when first { ssl_strict_server_name off; }
        when second { ssl_strict_server_name on; }

        return 200 ok;
    }
EOF
	$servers =~ s/LISTEN/$listen/g;
}

$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    $http2
    ssl_certificate cert.pem;
    ssl_certificate_key key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    $policies
    ssl_strict_server_name on;

    server {
        $listen
        server_name strict.test alias.test *.wild.test ~^regex[0-9]+[.]test\$;

        return 200 ok;
    }

    server {
        $listen
        server_name off.test;
        ssl_strict_server_name off;

        return 200 ok;
    }

    server {
        $listen
        server_name off-verify.test;
        ssl_strict_server_name off;
        ssl_verify_client optional_no_ca;

        return 200 ok;
    }

    server {
        $listen
        server_name auto.test;
        ssl_strict_server_name auto;

        return 200 ok;
    }

    server {
        $listen
        server_name optional.test;
        $verify_policy
        ssl_strict_server_name auto;
        ssl_verify_client optional;
        ssl_client_certificate cert.pem;

        return 200 ok;
    }

    server {
        $listen
        server_name no-ca.test;
        ssl_strict_server_name auto;
        ssl_verify_client optional_no_ca;

        return 200 ok;
    }

    server {
        $listen
        server_name required.test;
        ssl_verify_client on;
        ssl_client_certificate cert.pem;

        return 200 ok;
    }

    server {
        $single
        server_name single.test *.single.test ~^single[0-9]+[.]test\$;

        return 200 ok;
    }

    $servers
}
EOF

$t->write_file('openssl.conf', "[req]\ndistinguished_name = dn\n[dn]\n");
system('openssl req -x509 -newkey rsa:2048 -nodes -days 2 '
	. "-config $d/openssl.conf -subj /CN=strict.test -out $d/cert.pem "
	. "-keyout $d/key.pem >>$d/openssl.out 2>&1") == 0
	or die "openssl: $?";

$t->run();

my @cases = (
	['strict.test', 'strict.test', 200, 'matching SNI'],
	['strict.test', 'STRICT.TEST.:443', 200, 'normalized host'],
	['STRICT.TEST.', 'strict.test', 200, 'normalized SNI'],
	['strict.test', 'alias.test', 421, 'different alias in same server'],
	['off.test', 'strict.test', 421, 'request server enables strict mode'],
	[undef, 'strict.test', 200, 'missing SNI preserves native behavior'],
	['unknown.test', 'strict.test', 200, 'unmatched SNI preserves native behavior'],
	[undef, 'unknown.test', 200, 'missing SNI and default server'],
	['unknown.test', 'unknown.test', 200, 'equal unmatched names'],
	['strict.test', 'unknown.test', 421, 'unmatched request host'],
	['a.wild.test', 'a.wild.test', 200, 'matching wildcard name'],
	['a.wild.test', 'b.wild.test', 421, 'different wildcard name in same server'],
	['regex1.test', 'regex1.test', 200, 'matching regex name'],
	['off.test', 'off.test', 200, 'off matching SNI'],
	['strict.test', 'off.test', 200, 'request server disables strict mode'],
	[undef, 'off.test', 200, 'off missing SNI'],
	['unknown.test', 'off.test', 200, 'off unmatched SNI'],
	['strict.test', 'off-verify.test', $ext ? 200 : 421,
		'off with client verification'],
	['auto.test', 'auto.test', 200, 'auto matching SNI'],
	['strict.test', 'auto.test', 200, 'auto verification disabled'],
	[undef, 'auto.test', 200, 'auto missing SNI'],
	['unknown.test', 'auto.test', 200, 'auto unmatched SNI'],
	['strict.test', 'optional.test', 421, 'optional verification mismatch'],
	[undef, 'optional.test', 200, 'optional verification missing SNI'],
	['unknown.test', 'optional.test', 200, 'optional verification unmatched SNI'],
	['strict.test', 'no-ca.test', 421, 'optional_no_ca mismatch'],
	[undef, 'no-ca.test', 200, 'optional_no_ca missing SNI'],
	['unknown.test', 'no-ca.test', 200, 'optional_no_ca unmatched SNI'],
	[undef, 'required.test', 400, 'client certificate check precedes post_read'],
	['single.test', 'single.test', 200, 'single server matching SNI', 8445],
	['a.single.test', 'a.single.test', 200, 'single server wildcard SNI', 8445],
	['single1.test', 'single1.test', 200, 'single server regex SNI', 8445],
	['unknown.test', 'unknown.test', 200, 'single server equal unknown names', 8445],
	[undef, 'single.test', 200, 'single server missing SNI', 8445],
	['unknown.test', 'single.test', 200, 'single server unmatched SNI', 8445],
	['single.test', 'unknown.test', 200, 'single server omits name lookup', 8445],
);

if ($expr) {
	push @cases,
		['off.test', 'strict.test', 200, 'inherited condition skips mismatch',
			undef, { header => 'off' }],
		['alias.test', 'strict.test', 200, 'inherited condition skips different alias',
			undef, { header => 'off' }],
		[undef, 'single.test', 200, 'single server conditional exception',
			8445, { header => 'off' }],
		['off.test', 'conditional.test', 421, 'host URI and late header select on',
			undef, { path => '/check', header => 'on' }],
		['off.test', 'conditional.test', 421, 'request server condition',
			undef, { path => '/check', header => 'on' }],
		['off.test', 'conditional.test', 200, 'URI condition falls back to off',
			undef, { path => '/other', header => 'on' }],
		['off.test', 'conditional.test', 200, 'header condition falls back to off',
			undef, { path => '/check', header => 'off' }],
		['off.test', 'scoped.test', 200, 'inherited condition uses request server expression',
			undef, { header => 'skip' }],
		['off.test', 'scoped.test', 421, 'request server expression replaces parent expression',
			undef, { header => 'off' }],
		['strict.test', 'optional.test', 200, 'conditional off with client verification',
			undef, { header => 'off' }],
		['off.test', 'realip.test', 200, 'realip runs before condition evaluation',
			undef, { realip => '192.0.2.10' }],
		['off.test', 'realip.test', 421, 'realip address does not match condition',
			undef, { realip => '192.0.2.11' }],
		['off.test', 'realip.test', 421, 'socket address does not match condition'],
		['off.test', 'first.test', 200, 'first matching entry wins'];
}

$t->plan(4 * @cases + 9 + ($expr ? 6 : 0));

for my $tls (qw/TLSv1_2 TLSv1_3/) {
	for my $case (@cases) {
		my ($sni, $host, $status, $label, $port, $options) = @$case;
		like(get1($sni, $host, $tls, $port, $options), qr/HTTP\/1\.1 $status /,
			"HTTP/1 $tls: $label");
	}
	like(get1(undef, undef, $tls), qr/HTTP\/1\.1 200 /,
		"HTTP/1 $tls: missing SNI and Host");
	like(get1('strict.test', undef, $tls), qr/HTTP\/1\.1 421 /,
		"HTTP/1 $tls: recorded SNI with missing Host");
}

for my $host (qw/strict.test unknown.test off.test auto.test/) {
	like(http("GET / HTTP/1.0\r\nHost: $host\r\n\r\n"),
		qr/HTTP\/1\.1 200 /, "plain HTTP: $host");
}

like(http("GET / HTTP/1.0\r\nHost: strict.test\r\n\r\n",
	PeerAddr => '127.0.0.1:' . port(8443)), qr/HTTP\/1\.1 400 /,
	'plain HTTP to HTTPS port retains 400');

SKIP: {
	skip 'requires HTTP/2 and ALPN', scalar @cases unless $h2;
	for my $case (@cases) {
		my ($sni, $host, $status, $label, $port, $options) = @$case;
		my $sock = http('', start => 1, SSL => 1,
			PeerAddr => '127.0.0.1:' . port($port || 8443),
			SSL_hostname => $sni, SSL_alpn_protocols => ['h2']);
		my $s = Test::Nginx::HTTP2->new(undef, socket => $sock);
		is(get_status($s, $host, $options), $status, "HTTP/2: $label");
	}
}

SKIP: {
	skip 'requires HTTP/3 and CryptX', scalar @cases unless $h3;
	for my $case (@cases) {
		my ($sni, $host, $status, $label, $port, $options) = @$case;
		my $s = Test::Nginx::HTTP3->new($port ? 8981 : 8980, sni => $sni);
		is(get_status($s, $host, $options), $status, "HTTP/3: $label");
	}
}

if ($expr) {
	for my $protocol (2, 3) {
		SKIP: {
			skip "requires HTTP/$protocol", 3
				unless $protocol == 2 ? $h2 : $h3;
			my $s;
			if ($protocol == 2) {
				my $sock = http('', start => 1, SSL => 1,
					SSL_hostname => 'off.test', SSL_alpn_protocols => ['h2']);
				$s = Test::Nginx::HTTP2->new(undef, socket => $sock);
			} else {
				$s = Test::Nginx::HTTP3->new(8980, sni => 'off.test');
			}
			for my $value (qw/off on off/) {
				is(get_status($s, 'conditional.test',
					{ path => '/check', header => $value }),
					$value eq 'on' ? 421 : 200,
					"HTTP/$protocol: reevaluate $value on reused connection");
			}
		}
	}
}

$t->stop();

sub get1 {
	my ($sni, $host, $tls, $port, $options) = @_;
	$options //= {};
	my $header = defined $host ? "Host: $host\r\n" : '';
	$header .= "X-Strict: $options->{header}\r\n" if exists $options->{header};
	$header .= "X-Real-IP: $options->{realip}\r\n" if exists $options->{realip};
	my $path = $options->{path} || '/';

	return http("GET $path HTTP/1.0\r\n$header\r\n", SSL => 1,
		PeerAddr => '127.0.0.1:' . port($port || 8443),
		SSL_hostname => $sni, SSL_version => $tls);
}

sub get_status {
	my ($s, $host, $options) = @_;
	$options //= {};
	my $headers = [
		{ name => ':method', value => 'GET' },
		{ name => ':scheme', value => 'https' },
		{ name => ':path', value => $options->{path} || '/' },
		{ name => ':authority', value => $host },
	];
	push @$headers, { name => 'x-strict', value => $options->{header}, mode => 4 }
		if exists $options->{header};
	push @$headers, { name => 'x-real-ip', value => $options->{realip}, mode => 4 }
		if exists $options->{realip};
	my $sid = $s->new_stream({ headers => $headers });
	my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
	my ($frame) = grep { $_->{type} eq 'HEADERS' } @$frames;

	return $frame->{headers}{':status'};
}
