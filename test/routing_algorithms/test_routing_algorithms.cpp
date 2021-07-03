//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//
// @file Functions to test the algorithms that route on Benes and AS-Waksman networks.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE routing_algorithms_test

#include <boost/test/unit_test.hpp>

#include <cassert>

#include <nil/crypto3/zk/snark/routing/as_waksman.hpp>
#include <nil/crypto3/zk/snark/routing/benes.hpp>

using namespace nil::crypto3::zk::snark;

/**
 * Test Benes network routing for all permutations on 2^static_cast<std::size_t>(std::ceil(std::log2(N))) elements.
 */
void test_benes(const std::size_t N) {
    integer_permutation permutation(1ul << static_cast<std::size_t>(std::ceil(std::log2(N))));

    do {
        const benes_routing routing = get_benes_routing(permutation);
        assert(valid_benes_routing(permutation, routing));
    } while (permutation.next_permutation());
}

/**
 * Test AS-Waksman network routing for all permutations on N elements.
 */
void test_as_waksman(const std::size_t N) {
    integer_permutation permutation(N);

    do {
        const as_waksman_routing routing = get_as_waksman_routing(permutation);
        assert(valid_as_waksman_routing(permutation, routing));
    } while (permutation.next_permutation());
}

BOOST_AUTO_TEST_SUITE(routing_algorithms_test_suite)

BOOST_AUTO_TEST_CASE(routing_algorithms_test) {
    std::size_t bn_size = 8;
    printf("* for all permutations on %zu elements\n", bn_size);
    test_benes(bn_size);

    std::size_t asw_max_size = 9;
    for (std::size_t i = 2; i <= asw_max_size; ++i) {
        test_as_waksman(i);
    }
}

BOOST_AUTO_TEST_SUITE_END()