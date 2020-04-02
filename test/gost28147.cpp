//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
#define BOOST_TEST_MODULE gost_28147_cipher_test

#include <iostream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>

#include <nil/crypto3/block/gost28147.hpp>

using namespace nil::crypto3::block;

struct state_adder {
    template<typename T>
    void operator()(T &s1, T const &s2) {
        typedef typename T::size_type size_type;
        size_type n = (s2.size() < s1.size() ? s2.size() : s1.size());
        for (typename T::size_type i = 0; i < n; ++i) {
            s1[i] += s2[i];
        }
    }
};

BOOST_TEST_DONT_PRINT_LOG_VALUE(block::shacal1::block_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(block::shacal2<256>::block_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(block::shacal2<512>::block_type)

BOOST_AUTO_TEST_SUITE(gost28147_test_suite)

BOOST_AUTO_TEST_SUITE_END()