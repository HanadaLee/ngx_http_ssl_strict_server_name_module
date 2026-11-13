#!/usr/bin/perl

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http http_ssl/);
my $expr = $t->has_module('ngx_expr_module');

my @cases = (
	['ssl_strict_server_name auto;', 1, 'auto in http'],
	['server { ssl_strict_server_name on; }', 1, 'on in server'],
	['server { ssl_strict_server_name off; }', 1, 'off in server'],
	['ssl_strict_server_name mtls_only;', 0, 'unknown value'],
	['ssl_strict_server_name on; ssl_strict_server_name off;', 0,
		'duplicate unconditional directive'],
	['server { location / { ssl_strict_server_name on; } }', 0,
		'location is not allowed'],
);

if ($expr) {
	push @cases,
		['expr test bool true; when test { ssl_strict_server_name off; }',
			1, 'when in http'],
		['server { expr test bool true; when test { ssl_strict_server_name off; } }',
			1, 'when in server'],
		['server { expr test bool true; location / { when test { ssl_strict_server_name off; } } }',
			0, 'when in location is not allowed'];
}

$t->plan(scalar @cases);

for my $case (@cases) {
	my ($directive, $valid, $label) = @$case;
	$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    $directive
}
EOF

	my $output = $t->dump_config();
	is($output =~ /test is successful/ ? 1 : 0, $valid, $label)
		or diag $output;
}
