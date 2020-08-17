//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Functions to test the algorithms that route on Benes and AS-Waksman networks.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE routing_algorithms_test

#include <boost/test/unit_test.hpp>

#include <cassert>

#include <nil/crypto3/zk/snark/routing_algorithms/as_waksman_routing_algorithm.hpp>
#include <nil/crypto3/zk/snark/routing_algorithms/benes_routing_algorithm.hpp>

using namespace nil::crypto3::zk::snark;

/**
 * Test Benes network routing for all permutations on 2^static_cast<std::size_t>(std::ceil(std::log2(N))) elements.
 */
void test_benes(const size_t N) {
    integer_permutation permutation(1ul << static_cast<std::size_t>(std::ceil(std::log2(N))));

    do {
        const benes_routing routing = get_benes_routing(permutation);
        assert(valid_benes_routing(permutation, routing));
    } while (permutation.next_permutation());
}

/**
 * Test AS-Waksman network routing for all permutations on N elements.
 */
void test_as_waksman(const size_t N) {
    integer_permutation permutation(N);

    do {
        const as_waksman_routing routing = get_as_waksman_routing(permutation);
        assert(valid_as_waksman_routing(permutation, routing));
    } while (permutation.next_permutation());
}

BOOST_AUTO_TEST_SUITE(routing_algorithms_test_suite)

BOOST_AUTO_TEST_CASE(routing_algorithms_test) {
    size_t bn_size = 8;
    printf("* for all permutations on %zu elements\n", bn_size);
    test_benes(bn_size);

    size_t asw_max_size = 9;
    for (size_t i = 2; i <= asw_max_size; ++i) {
        test_as_waksman(i);
    }
}

BOOST_AUTO_TEST_SUITE_END()