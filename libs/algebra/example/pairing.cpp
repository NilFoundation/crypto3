//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#include <iostream>

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp3.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp4.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp6_2over3.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp6_3over2.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>
#include <nil/crypto3/algebra/pairing/edwards.hpp>

#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3::algebra;

template<typename CurveType>
void pairing_example() {
    using curve_type = CurveType;

    using g1_type = typename curve_type::template g1_type<>;
    using g2_type = typename curve_type::template g2_type<>;
    using g1_field_value_type = typename g1_type::field_type::value_type;
    using g2_field_value_type = typename g2_type::field_type::value_type;

    typename curve_type::template g1_type<>::value_type g1_el1 = random_element<typename curve_type::template g1_type<>>();
    std::cout << "g1_el1: " << g1_el1 << std::endl;

    typename pairing::pairing_policy<curve_type>::g1_precomputed_type
        g1_precomp_el1 = precompute_g1<curve_type>(g1_el1);
    // std::cout << "g1_precomp_el1: " << g1_precomp_el1 << std::endl;

    typename curve_type::template g1_type<>::value_type g1_el2 = g1_type::value_type::one();
    std::cout << "g1_el2: " << g1_el2 << std::endl;
    typename pairing::pairing_policy<curve_type>::g1_precomputed_type
        g1_precomp_el2 = precompute_g1<curve_type>(g1_el2);
    //  std::cout << "g1_precomp_el2: " << g1_precomp_el2 << std::endl;

    typename curve_type::template g2_type<>::value_type g2_el1 = random_element<typename curve_type::template g2_type<>>();
    std::cout << "g2_el1: " << g2_el1 << std::endl;
    typename pairing::pairing_policy<curve_type>::g2_precomputed_type
        g2_precomp_el1 = precompute_g2<curve_type>(g2_el1);
    // std::cout << "g2_precomp_el1: " << g2_precomp_el1 << std::endl;

    typename curve_type::template g2_type<>::value_type g2_el2 = g2_type::value_type::one();
    std::cout << "g2_el2: " << g2_el2 << std::endl;

    typename pairing::pairing_policy<curve_type>::g2_precomputed_type
        g2_precomp_el2 = precompute_g2<curve_type>(g2_el2);
    // std::cout << "g2_precomp_el2: " << g2_precomp_el2 << std::endl;

    typename curve_type::gt_type::value_type gt_el1 = pair_reduced<curve_type>(g1_el1, g2_el1);
    std::cout << "gt_el1: " << gt_el1 << std::endl;

    typename curve_type::gt_type::value_type gt_el2 = pair<curve_type>(g1_el1, g2_el1);
    std::cout << "gt_el2: " << gt_el2 << std::endl;

    typename curve_type::gt_type::value_type gt_el3 = miller_loop<curve_type>(g1_precomp_el1, g2_precomp_el1);
    std::cout << "gt_el3: " << gt_el3 << std::endl;

    typename curve_type::gt_type::value_type gt_el4 =
        double_miller_loop<curve_type>(g1_precomp_el1, g2_precomp_el1, g1_precomp_el2, g2_precomp_el2);
    std::cout << "gt_el4: " << gt_el4 << std::endl;

    typename curve_type::gt_type::value_type gt_el5 = final_exponentiation<curve_type>(gt_el4);
    std::cout << "gt_el5: " << gt_el5 << std::endl;
}

int main() {
    pairing_example<curves::bls12<381>>();

    pairing_example<curves::mnt4<298>>();

    pairing_example<curves::mnt6<298>>();

    pairing_example<curves::edwards<183>>();
}
