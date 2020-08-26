//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Functions to profile the algorithms that route on Benes and AS-Waksman networks.
//---------------------------------------------------------------------------//

#include <algorithm>

#include <nil/crypto3/zk/snark/routing_algorithms/as_waksman_routing_algorithm.hpp>
#include <nil/crypto3/zk/snark/routing_algorithms/benes_routing_algorithm.hpp>

using namespace nil::crypto3::zk::snark;

void profile_benes_algorithm(const std::size_t n) {
    printf("* Size: %zu\n", n);

    assert(n == 1ul << static_cast<std::size_t>(std::ceil(std::log2(n))));

    integer_permutation permutation(n);
    permutation.random_shuffle();

    const benes_routing routing = get_benes_routing(permutation);
}

void profile_as_waksman_algorithm(const std::size_t n) {
    printf("* Size: %zu\n", n);

    integer_permutation permutation(n);
    permutation.random_shuffle();

    const as_waksman_routing routing = get_as_waksman_routing(permutation);
}

int main() {
    for (std::size_t n = 1ul << 10; n <= 1ul << 20; n <<= 1) {
        profile_benes_algorithm(n);
    }

    for (std::size_t n = 1ul << 10; n <= 1ul << 20; n <<= 1) {
        profile_as_waksman_algorithm(n);
    }
}
