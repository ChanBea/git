#! /usr/bin/env perl
# Copyright 2020-2020 The OpenSSL Project Authors. All Rights Reserved.
#
#  Licensed under the Apache License 2.0 (the "License").  You may not use
#  this file except in compliance with the License.  You can obtain a copy
#  in the file LICENSE in the source distribution or at
#  https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test::Simple;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils qw(alldisabled available_protocols);

setup("test_method");

plan skip_all => "No TLS/SSL protocols are supported by this OpenSSL build"
    if alldisabled(grep { $_ ne "ssl3" } available_protocols("tls"));

plan tests => 1;

ok(run(test(["method_test", srctop_file("apps", "server.pem"), srctop_file("apps", "server.pem")])), "running method_test");
