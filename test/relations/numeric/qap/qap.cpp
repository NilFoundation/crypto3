//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE qap_test

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

using namespace nil::crypto3::zk::snark;

template<typename FieldType>
void test_qap(const std::size_t qap_degree, const std::size_t num_inputs, const bool binary_input) {
    /*
      We construct an instance where the QAP degree is qap_degree.
      So we generate an instance of R1CS where the number of constraints qap_degree - num_inputs - 1.
      See the transformation from R1CS to QAP for why this is the case.
      So we need that qap_degree >= num_inputs + 1.
    */
    BOOST_CHECK(num_inputs + 1 <= qap_degree);

    const std::size_t num_constraints = qap_degree - num_inputs - 1;

    r1cs_example<FieldType> example;
    if (binary_input) {
        example = generate_r1cs_example_with_binary_input<FieldType>(num_constraints, num_inputs);
    } else {
        example = generate_r1cs_example_with_field_input<FieldType>(num_constraints, num_inputs);
    }

    BOOST_CHECK(example.constraint_system.is_satisfied(example.primary_input, example.auxiliary_input));

    const typename FieldType::value_type t = random_element<FieldType>(), d1 = random_element<FieldType>(), d2 = random_element<FieldType>(),
                    d3 = random_element<FieldType>();

    qap_instance<FieldType> qap_inst_1 = r1cs_to_qap_instance_map(example.constraint_system);

    qap_instance_evaluation<FieldType> qap_inst_2 =
        r1cs_to_qap_instance_map_with_evaluation(example.constraint_system, t);

    qap_witness<FieldType> qap_wit =
        r1cs_to_qap_witness_map(example.constraint_system, example.primary_input, example.auxiliary_input, d1, d2, d3);

    BOOST_CHECK(qap_inst_1.is_satisfied(qap_wit));
    BOOST_CHECK(qap_inst_2.is_satisfied(qap_wit));
}

BOOST_AUTO_TEST_SUITE(qap_test_suite)

BOOST_AUTO_TEST_CASE(qap_test_case) {
    const std::size_t num_inputs = 10;

    const std::size_t basic_domain_size = 1ul << algebra::mnt6_Fr::s;
    const std::size_t step_domain_size = (1ul << 10) + (1ul << 8);
    const std::size_t extended_domain_size = 1ul << (algebra::mnt6_Fr::s + 1);
    const std::size_t extended_domain_size_special = extended_domain_size - 1;

    test_qap<typename algebra::curves::mnt6::scalar_field_type>(basic_domain_size, num_inputs, true);
    test_qap<typename algebra::curves::mnt6::scalar_field_type>(step_domain_size, num_inputs, true);
    test_qap<typename algebra::curves::mnt6::scalar_field_type>(extended_domain_size, num_inputs, true);
    test_qap<typename algebra::curves::mnt6::scalar_field_type>(extended_domain_size_special, num_inputs, true);

    test_qap<typename algebra::curves::mnt6::scalar_field_type>(basic_domain_size, num_inputs, false);
    test_qap<typename algebra::curves::mnt6::scalar_field_type>(step_domain_size, num_inputs, false);
    test_qap<typename algebra::curves::mnt6::scalar_field_type>(extended_domain_size, num_inputs, false);
    test_qap<typename algebra::curves::mnt6::scalar_field_type>(extended_domain_size_special, num_inputs, false);
}

BOOST_AUTO_TEST_SUITE_END()