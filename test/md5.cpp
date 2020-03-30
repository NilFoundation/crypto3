//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE md5_test

#include <iostream>
#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/hash/md5.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

using namespace nil::crypto3::hash;
using namespace nil::crypto3::accumulators;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream&, P<K, V> const&) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

BOOST_TEST_DONT_PRINT_LOG_VALUE(md5::construction::type::digest_type)

class fixture {
public:
    accumulator_set<md5> acc;
    virtual ~fixture() {
    }
};


BOOST_AUTO_TEST_SUITE(md5_test_suite)

BOOST_FIXTURE_TEST_CASE(md5_accumulator1, fixture) {
    // 0-length input: echo -n | md5sum

    // A single 1 bit after the (empty) message,
    // then pad with 0s,
    // then add the length, which is also 0
    md5::construction::type::block_type m = {{0x80000000u}};
    acc(m);

    md5::digest_type s = extract::hash<md5>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("d41d8cd98f00b204e9800998ecf8427e", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(md5_accumulator2, fixture) {
    // echo -n "abc" | md5sum
    md5::construction::type::block_type m = {{}};
    m[0] = 0x00636261;
    acc(m, nil::crypto3::accumulators::bits = 24);
    md5::construction::type::digest_type s = extract::hash<md5>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("900150983cd24fb0d6963f7d28e17f72", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(md5_preprocessor1) {
    accumulator_set<md5> acc;
    md5::construction::type::digest_type s = extract::hash<md5>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("d41d8cd98f00b204e9800998ecf8427e", std::to_string(s));
}

BOOST_AUTO_TEST_CASE(md5_preprocessor2) {
    accumulator_set<md5> acc;
    acc(0x00000061, nil::crypto3::accumulators::bits = 8);
    acc(0x00000062, nil::crypto3::accumulators::bits = 8);
    acc(0x00000063, nil::crypto3::accumulators::bits = 8);

    md5::construction::type::digest_type s = extract::hash<md5>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("900150983cd24fb0d6963f7d28e17f72", std::to_string(s));
}

BOOST_AUTO_TEST_CASE(md5_preprocessor3) {
    // perl -e 'for (1..1000000) { print "a"; }' | md5sum
    accumulator_set<md5> acc;
    for (unsigned i = 0; i < 1000000; ++i) {
        acc(0x00000061, nil::crypto3::accumulators::bits = 8);
    }
    md5::construction::type::digest_type s = extract::hash<md5>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("7707d6ae4e027c70eea2a935c2296f21", std::to_string(s));
}


BOOST_AUTO_TEST_CASE(md5_preprocessor4) {
    //  perl -e 'for (1..8) { print "1234567890"; }' | md5sum
    accumulator_set<md5> acc;
    for (unsigned i = 0; i < 8; ++i) {
        acc(0x00000031, nil::crypto3::accumulators::bits = 8);
        acc(0x00000032, nil::crypto3::accumulators::bits = 8);
        acc(0x00000033, nil::crypto3::accumulators::bits = 8);
        acc(0x00000034, nil::crypto3::accumulators::bits = 8);
        acc(0x00000035, nil::crypto3::accumulators::bits = 8);
        acc(0x00000036, nil::crypto3::accumulators::bits = 8);
        acc(0x00000037, nil::crypto3::accumulators::bits = 8);
        acc(0x00000038, nil::crypto3::accumulators::bits = 8);
        acc(0x00000039, nil::crypto3::accumulators::bits = 8);
        acc(0x00000030, nil::crypto3::accumulators::bits = 8);
    }
    md5::construction::type::digest_type s = extract::hash<md5>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("57edf4a22be3c955ac49da2e2107b67a", std::to_string(s));
}


BOOST_AUTO_TEST_SUITE_END()