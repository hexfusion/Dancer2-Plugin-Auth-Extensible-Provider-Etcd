#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Dancer2::Plugin::Auth::Extensible::Provider::Etcd' ) || print "Bail out!
";
}

diag( "Testing Dancer2::Plugin::Auth::Extensible::Provider::Etcd $Dancer2::Plugin::Auth::Extensible::Provider::Etcd::VERSION, Perl $], $^X" );
