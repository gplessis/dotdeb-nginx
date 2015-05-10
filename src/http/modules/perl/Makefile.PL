
# Copyright (C) Igor Sysoev
# Copyright (C) Nginx, Inc.

use 5.006001;
use Config;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'nginx',
    VERSION_FROM      => 'nginx.pm',     # finds $VERSION
    PREREQ_PM         => {},             # e.g., Module::Name => 1.1

    ABSTRACT_FROM     => 'nginx.pm',     # retrieve abstract from module
    AUTHOR            => 'Igor Sysoev',

    CCFLAGS           => "$ENV{NGX_PM_CFLAGS}",
    # Pass link hardening flags
    # $Config{lddlflags} is the default
    LDDLFLAGS         => "$Config{lddlflags} $ENV{DEBIAN_NGINX_PERL_LDFLAGS}",
    OPTIMIZE          => '-O',

    INC               => join(" ", map {
                             m#^/# ? "-I $_" : "-I ../../../../../$_"
                         } (split /\s+/, $ENV{NGX_INCS})),

    depend => {
        'nginx.c'     => join(" ", map {
                             m#^/# ? $_ : "../../../../../$_"
                         } (split(/\s+/, $ENV{NGX_DEPS}),
                            "src/http/modules/perl/ngx_http_perl_module.h"))
    },

    PM => {
        'nginx.pm'    => '$(INST_LIBDIR)/nginx.pm'
    }
);
