use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME          => 'Dancer2::Plugin::Auth::Extensible::Provider::Etcd',
    AUTHOR        => q{Sam Batschelet <sbatschelet@mac.com>},
    VERSION_FROM  => 'lib/Dancer2/Plugin/Auth/Extensible/Provider/Etcd.pm',
    ABSTRACT_FROM => 'lib/Dancer2/Plugin/Auth/Extensible/Provider/Etcd.pm',
    ( $ExtUtils::MakeMaker::VERSION >= 6.48
        ? ( 'LICENSE' => 'perl' )
        : () ),
    PL_FILES       => {},
    BUILD_REQUIRES => {
        'Path::Tiny'                              => '0.016',
        'Test::More'                              => 0,
        'Dancer2::Plugin::Auth::Extensible::Test' => 0,
        'DBD::SQLite'                             => 0,
    },
    PREREQ_PM => {
        'Carp'                              => 0,
        'Dancer2'                           => '0.200000',
        'Dancer2::Plugin::Auth::Extensible' => '0.600',
        'Dancer2::Plugin::Etcd'             => 0,
        'Moo'                               => '2.000000',
        'namespace::clean'                  => 0,
        'YAML' => 0,    # for config files and tests
    },
    EXE_FILES => [],
    dist      => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Dancer2-Plugin-Auth-Extensible-Provider-Etcd-*' },
    META_MERGE => {
        resources => {
            repository =>
'https://github.com/sbatschelet/Dancer2-Plugin-Auth-Extensible-Provider-Etcd',
            bugtracker =>
'https://github.com/sbatschelet/Dancer2-Plugin-Auth-Extensible-Provider-Etcd/issues',
            homepage =>
'https://github.com/sbatschelet/Dancer2-Plugin-Auth-Extensible-Provider-Etcd/',
            IRC => 'irc://irc.perl.org/#dancer',
        },
    },

);
