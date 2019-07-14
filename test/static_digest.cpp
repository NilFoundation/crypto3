//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE digest_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/hash/detail/static_digest.hpp>

#include <iostream>
#include <sstream>

#include <cassert>

using namespace nil::crypto3::hash;

BOOST_AUTO_TEST_SUITE(digest_test_suite)

BOOST_AUTO_TEST_CASE(empty_digest) {
    std::stringstream ss;
    static_digest<160> d;
    d.fill(0);
    ss << d;

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::cout << ss.str() << "\n";
#endif

    // This test fails for the author in g++ 4.3.4
    // because of a bug in value-initialization
    BOOST_CHECK_EQUAL(ss.str(), std::string(160 / 4, '0'));
}

BOOST_AUTO_TEST_CASE(digest1) {
    std::stringstream ss("0123456789abcdef0123456789ABCDEF");
    static_digest<32 * 4> d;
    ss >> d;

    BOOST_CHECK(ss);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::cout << d << "\n";
#endif

    BOOST_CHECK_EQUAL(d, "0123456789abcdef0123456789abcdef");
}

BOOST_AUTO_TEST_CASE(digest2) {
    std::stringstream ss("0123456789abcdef0123456789ABCDEF");
    static_digest<32 * 4 + 8> d;

    ss >> d;
    BOOST_CHECK(!ss);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::cout << d << "\n";
#endif

    BOOST_CHECK_EQUAL(d, "0123456789abcdef0123456789abcdef00");
}

BOOST_AUTO_TEST_CASE(digest3) {
    std::stringstream ss("0123456789abcdeffedcba9876543210");
    static_digest<32 * 4> d;

    ss >> d;

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::cout << truncate<16 * 4>(d) << "\n";
#endif

    BOOST_CHECK_EQUAL(truncate<16 * 4>(d), "0123456789abcdef");

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::cout << resize<16 * 3 * 4>(d) << "\n";
#endif

    BOOST_CHECK_EQUAL(resize<16 * 3 * 4>(d), "0123456789abcdeffedcba98765432100000000000000000");
}

BOOST_AUTO_TEST_SUITE_END()