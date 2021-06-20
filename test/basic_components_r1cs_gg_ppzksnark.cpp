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

#define BOOST_TEST_MODULE basic_components_verification_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/mnt6.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/mnt6.hpp>

#include <nil/crypto3/zk/components/disjunction.hpp>
#include <nil/crypto3/zk/components/conjunction.hpp>
#include <nil/crypto3/zk/components/comparison.hpp>
#include <nil/crypto3/zk/components/inner_product.hpp>
#include <nil/crypto3/zk/components/loose_multiplexing.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>

#include "verify_r1cs_scheme.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

template<typename CurveType>
void test_disjunction_component(std::size_t w) {

    using field_type = typename CurveType::scalar_field_type;
    using curve_type = CurveType;

    std::size_t n = std::log2(w) + 
        ((w > (1ul << std::size_t(std::log2(w))))? 1 : 0);

    components::blueprint<field_type> bp;
    components::blueprint_variable<field_type> output;
    output.allocate(bp);

    bp.set_input_sizes(1);

    components::blueprint_variable_vector<field_type> inputs;
    inputs.allocate(bp, n);

    components::disjunction<field_type> d(bp, inputs, output);
    d.generate_r1cs_constraints();

    for (std::size_t j = 0; j < n; ++j) {
        bp.val(inputs[j]) = typename field_type::value_type((w & (1ul << j)) ? 1 : 0);
    }

    d.generate_r1cs_witness();

    BOOST_CHECK(bp.val(output) == (w ? field_type::value_type::one() : field_type::value_type::zero()));
    BOOST_CHECK(bp.is_satisfied());

    BOOST_CHECK(verify_component<curve_type>(bp));
}

template<typename CurveType>
void test_conjunction_component(std::size_t w) {

    using field_type = typename CurveType::scalar_field_type;
    using curve_type = CurveType;

    std::size_t n = std::log2(w) + 
        ((w > (1ul << std::size_t(std::log2(w))))? 1 : 0);

    components::blueprint<field_type> bp;

    components::blueprint_variable<field_type> output;
    output.allocate(bp);

    bp.set_input_sizes(1);

    components::blueprint_variable_vector<field_type> inputs;
    inputs.allocate(bp, n);

    components::conjunction<field_type> c(bp, inputs, output);
    c.generate_r1cs_constraints();

    for (std::size_t j = 0; j < n; ++j) {
        bp.val(inputs[j]) = (w & (1ul << j)) ? field_type::value_type::one() : field_type::value_type::zero();
    }

    c.generate_r1cs_witness();

    BOOST_CHECK(bp.val(output) ==
                (w == (1ul << n) - 1 ? field_type::value_type::one() : field_type::value_type::zero()));
    BOOST_CHECK(bp.is_satisfied());

    BOOST_CHECK(verify_component<curve_type>(bp));
}

template<typename CurveType>
void test_comparison_component(std::size_t a, std::size_t b) {
    
    using field_type = typename CurveType::scalar_field_type;
    using curve_type = CurveType;

    components::blueprint<field_type> bp;

    components::blueprint_variable<field_type> A, B, less, less_or_eq;
    A.allocate(bp);
    B.allocate(bp);
    less.allocate(bp);
    less_or_eq.allocate(bp);

    bp.set_input_sizes(1);
    std::size_t n = std::log2(std::max(a, b)) + 
        ((std::max(a, b) > (1ul << std::size_t(std::log2(std::max(a, b)))))? 1 : 0);

    components::comparison<field_type> cmp(bp, n, A, B, less, less_or_eq);
    cmp.generate_r1cs_constraints();
    
    bp.val(A) = typename field_type::value_type(a);
    bp.val(B) = typename field_type::value_type(b);

    cmp.generate_r1cs_witness();

    BOOST_CHECK(bp.val(less) == (a < b ? field_type::value_type::one() : field_type::value_type::zero()));
    BOOST_CHECK(bp.val(less_or_eq) == (a <= b ? field_type::value_type::one() : field_type::value_type::zero()));
    BOOST_CHECK(bp.is_satisfied());

    BOOST_CHECK(verify_component<curve_type>(bp));
}

BOOST_AUTO_TEST_SUITE(basic_components_test_suite)

BOOST_AUTO_TEST_CASE(basic_components_disjunction_r1cs_gg_ppzksnark_test) {
    std::cout << "Disjunction component test started" << std::endl;
    std::cout << "Started for bls12<381>" << std::endl;
    test_disjunction_component<curves::bls12<381>>(10);
    std::cout << "Started for mnt4<298>" << std::endl;
    test_disjunction_component<curves::mnt4<298>>(10);
    std::cout << "Started for mnt6<298>" << std::endl;
    test_disjunction_component<curves::mnt6<298>>(10);
}

BOOST_AUTO_TEST_CASE(basic_components_conjunction_r1cs_gg_ppzksnark_test) {
    std::cout << "Conjunction component test started" << std::endl;
    std::cout << "Started for bls12<381>" << std::endl;
    test_conjunction_component<curves::bls12<381>>(10);
    std::cout << "Started for mnt4<298>" << std::endl;
    test_conjunction_component<curves::mnt4<298>>(10);
    std::cout << "Started for mnt6<298>" << std::endl;
    test_conjunction_component<curves::mnt6<298>>(10);
}

BOOST_AUTO_TEST_CASE(basic_components_comparison_r1cs_gg_ppzksnark_test) {
    std::cout << "Comparison component r1cs_gg_ppzksnark test started" << std::endl;
    std::cout << "Started for bls12<381>" << std::endl;
    test_comparison_component<curves::bls12<381>>(1, 4);
    std::cout << "Started for mnt4<298>" << std::endl;
    test_comparison_component<curves::mnt4<298>>(1, 4);
    std::cout << "Started for mnt6<298>" << std::endl;
    test_comparison_component<curves::mnt6<298>>(1, 4);
}

BOOST_AUTO_TEST_SUITE_END()