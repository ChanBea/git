#! /usr/bin/env perl
# Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use POSIX;
use OpenSSL::Test qw/:DEFAULT data_file/;
use File::Copy;

setup('test_ca_updatedb');

my @tests = (
    { 
        filename => 'index.txt',
        copydb => 1,
        testdate => '990101000000Z',
        expirelist => []
    },
    { 
        filename => 'index.txt',
        copydb => 0,
        testdate => '991201000000Z',
        expirelist => [ '1000' ]
    },
    { 
        filename => 'index.txt',
        copydb => 0,
        testdate => '211201000000Z',
        expirelist => [ '1001' ]
    },
    { 
        filename => 'index.txt',
        copydb => 0,
        testdate => '491201000000Z',
        expirelist => [ '1002' ]
    },
    { 
        filename => 'index.txt',
        copydb => 0,
        testdate => '20500101000000Z',
        expirelist => [ ]
    },
    { 
        filename => 'index.txt',
        copydb => 0,
        testdate => '20501201000000Z',
        expirelist => [ '1003' ]
    },
    { 
        filename => 'index.txt',
        copydb => 1,
        testdate => '20501201000000Z',
        expirelist => [ '1000', 
                        '1001',
                        '1002',
                        '1003' ]
    }
);

# every "test_updatedb" makes 3 checks
plan tests => 3 * scalar(@tests);

foreach my $test (@tests) {
    test_updatedb($test);
}


sub test_updatedb {
    my ($opts) = @_;
    my $amt = scalar(@{$opts->{expirelist}});
    my @output;
    my $expirelistcorrect = 1;
    my $cert;

    if ($opts->{copydb}) {
        copy(data_file('index.txt'), 'index.txt');
    }

    @output = run(
        test(['ca_updatedb',
            $opts->{filename},
            $opts->{testdate}
        ]),
        capture => 1,
        statusvar => \my $exit
    );

    foreach my $tmp (@output) {
        ($cert)=$tmp=~/^([0-9A-F]+)=Expired/;
        my $expirefound = 0;
        foreach my $expire (@{$opts->{expirelist}}) {
            if ($expire eq $cert) {
                $expirefound = 1;
            }
        }
        if ($expirefound != 1) {
            $expirelistcorrect = 0;
        }
    }

    is($exit, 1, "ca_updatedb: returned EXIT_FAILURE");
    is($amt, scalar(@output), "ca_updatedb: amount of expired certificated differs from expected amount");
    is($expirelistcorrect, 1, "ca_updatedb: list of expired certificated differs from expected list");
}

