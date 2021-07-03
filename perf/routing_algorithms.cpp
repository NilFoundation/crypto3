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
// @file Functions to profile the algorithms that route on Benes and AS-Waksman networks.
//---------------------------------------------------------------------------//

#include <algorithm>

#include <nil/crypto3/zk/snark/routing/as_waksman.hpp>
#include <nil/crypto3/zk/snark/routing/benes_routing_algorithm.hpp>

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
