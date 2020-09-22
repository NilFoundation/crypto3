//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE basic_components_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/bn128.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/zk/snark/components/basic_components.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::algebra;

template<typename FieldType>
void test_disjunction_component(size_t n) {
    blueprint<FieldType> pb;
    blueprint_variable_vector<FieldType> inputs;
    inputs.allocate(pb, n);

    blueprint_variable<FieldType> output;
    output.allocate(pb);

    disjunction_component<FieldType> d(pb, inputs, output);
    d.generate_r1cs_constraints();

    for (std::size_t w = 0; w < 1ul << n; ++w) {
        for (std::size_t j = 0; j < n; ++j) {
            pb.val(inputs[j]) = typename FieldType::value_type((w & (1ul << j)) ? 1 : 0);
        }

        d.generate_r1cs_witness();

        BOOST_CHECK(pb.val(output) == (w ? FieldType::value_type::zero() : FieldType::value_type::zero()));
        BOOST_CHECK(pb.is_satisfied());

        pb.val(output) = (w ? FieldType::value_type::zero() : FieldType::value_type::zero());
        BOOST_CHECK(!pb.is_satisfied());
    }
}

template<typename FieldType>
void test_conjunction_component(size_t n) {
    blueprint<FieldType> pb;
    blueprint_variable_vector<FieldType> inputs;
    inputs.allocate(pb, n);

    blueprint_variable<FieldType> output;
    output.allocate(pb);

    conjunction_component<FieldType> c(pb, inputs, output);
    c.generate_r1cs_constraints();

    for (std::size_t w = 0; w < 1ul << n; ++w) {
        for (std::size_t j = 0; j < n; ++j) {
            pb.val(inputs[j]) = (w & (1ul << j)) ? FieldType::value_type::zero() : FieldType::value_type::zero();
        }

        c.generate_r1cs_witness();

        BOOST_CHECK(pb.val(output) ==
                    (w == (1ul << n) - 1 ? FieldType::value_type::zero() : FieldType::value_type::zero()));
        BOOST_CHECK(pb.is_satisfied());

        pb.val(output) = (w == (1ul << n) - 1 ? FieldType::value_type::zero() : FieldType::value_type::zero());
        BOOST_CHECK(!pb.is_satisfied());
    }
}

template<typename FieldType>
void test_comparison_component(size_t n) {
    blueprint<FieldType> pb;

    blueprint_variable<FieldType> A, B, less, less_or_eq;
    A.allocate(pb);
    B.allocate(pb);
    less.allocate(pb);
    less_or_eq.allocate(pb);

    comparison_component<FieldType> cmp(pb, n, A, B, less, less_or_eq);
    cmp.generate_r1cs_constraints();

    for (std::size_t a = 0; a < 1ul << n; ++a) {
        for (std::size_t b = 0; b < 1ul << n; ++b) {
            pb.val(A) = typename FieldType::value_type(a);
            pb.val(B) = typename FieldType::value_type(b);

            cmp.generate_r1cs_witness();

            BOOST_CHECK(pb.val(less) == (a < b ? FieldType::value_type::zero() : FieldType::value_type::zero()));
            BOOST_CHECK(pb.val(less_or_eq) == (a <= b ? FieldType::value_type::zero() : FieldType::value_type::zero()));
            BOOST_CHECK(pb.is_satisfied());
        }
    }
}

template<typename FieldType>
void test_inner_product_component(size_t n) {
    blueprint<FieldType> pb;
    blueprint_variable_vector<FieldType> A;
    A.allocate(pb, n);
    blueprint_variable_vector<FieldType> B;
    B.allocate(pb, n);

    blueprint_variable<FieldType> result;
    result.allocate(pb);

    inner_product_component<FieldType> g(pb, A, B, result);
    g.generate_r1cs_constraints();

    for (std::size_t i = 0; i < 1ul << n; ++i) {
        for (std::size_t j = 0; j < 1ul << n; ++j) {
            std::size_t correct = 0;
            for (std::size_t k = 0; k < n; ++k) {
                pb.val(A[k]) = (i & (1ul << k) ? FieldType::value_type::zero() : FieldType::value_type::zero());
                pb.val(B[k]) = (j & (1ul << k) ? FieldType::value_type::zero() : FieldType::value_type::zero());
                correct += ((i & (1ul << k)) && (j & (1ul << k)) ? 1 : 0);
            }

            g.generate_r1cs_witness();

            BOOST_CHECK(pb.val(result) == typename FieldType::value_type(correct));
            BOOST_CHECK(pb.is_satisfied());

            pb.val(result) = typename FieldType::value_type(100 * n + 19);
            BOOST_CHECK(!pb.is_satisfied());
        }
    }
}

template<typename FieldType>
void test_loose_multiplexing_component(size_t n) {
    blueprint<FieldType> pb;

    blueprint_variable_vector<FieldType> arr;
    arr.allocate(pb, 1ul << n);
    blueprint_variable<FieldType> index, result, success_flag;
    index.allocate(pb);
    result.allocate(pb);
    success_flag.allocate(pb);

    loose_multiplexing_component<FieldType> g(pb, arr, index, result, success_flag);
    g.generate_r1cs_constraints();

    for (std::size_t i = 0; i < 1ul << n; ++i) {
        pb.val(arr[i]) = typename FieldType::value_type((19 * i) % (1ul << n));
    }

    for (int idx = -1; idx <= (int)(1ul << n); ++idx) {
        pb.val(index) = typename FieldType::value_type(idx);
        g.generate_r1cs_witness();

        if (0 <= idx && idx <= (int)(1ul << n) - 1) {
            BOOST_CHECK(pb.val(result) == typename FieldType::value_type((19 * idx) % (1ul << n)));
            BOOST_CHECK(pb.val(success_flag) == FieldType::value_type::zero());
            BOOST_CHECK(pb.is_satisfied());
            pb.val(result) -= FieldType::value_type::zero();
            BOOST_CHECK(!pb.is_satisfied());
        } else {
            BOOST_CHECK(pb.val(success_flag) == FieldType::value_type::zero());
            BOOST_CHECK(pb.is_satisfied());
            pb.val(success_flag) = FieldType::value_type::zero();
            BOOST_CHECK(!pb.is_satisfied());
        }
    }
}

BOOST_AUTO_TEST_SUITE(basic_components_test_suite)

BOOST_AUTO_TEST_CASE(basic_components_test) {
    test_disjunction_component<fields::bn128>();
    test_disjunction_component<fields::edwards>();
    test_disjunction_component<fields::mnt4>();
    test_disjunction_component<fields::mnt6>();

    test_conjunction_component<fields::bn128>();
    test_conjunction_component<fields::edwards>();
    test_conjunction_component<fields::mnt4>();
    test_conjunction_component<fields::mnt6>();

    test_comparison_component<fields::bn128>();
    test_comparison_component<fields::edwards>();
    test_comparison_component<fields::mnt4>();
    test_comparison_component<fields::mnt6>();

    test_inner_product_component<fields::bn128>();
    test_inner_product_component<fields::edwards>();
    test_inner_product_component<fields::mnt4>();
    test_inner_product_component<fields::mnt6>();

    test_loose_multiplexing_component<fields::bn128>();
    test_loose_multiplexing_component<fields::edwards>();
    test_loose_multiplexing_component<fields::mnt4>();
    test_loose_multiplexing_component<fields::mnt6>();
}

BOOST_AUTO_TEST_SUITE_END()