//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE skein_test

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/hash/skein.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/static_assert.hpp>

#include <iostream>
#include <string>
#include <unordered_map>

#include <cstdio>
#include <cstring>

using namespace nil::crypto3::hash;

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

BOOST_AUTO_TEST_SUITE(skein_test_suite)

BOOST_AUTO_TEST_CASE(skein_224_iterator_hash) {

	std::string input = std::string(1, char(204));	

	std::string out = hash<skein<224>>(input.begin(), input.end());

	BOOST_CHECK_EQUAL("23f031a6a4378039b66a5a178bad217eaec094b7fcba663a47ddcf33", out);
}

BOOST_AUTO_TEST_SUITE_END()