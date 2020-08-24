//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE sap_test

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

#include <nil/crypto3/zk/snark/reductions/r1cs_to_sap/r1cs_to_sap.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

using namespace nil::crypto3::zk::snark;

template<typename FieldType>
void test_sap(const std::size_t sap_degree, const std::size_t num_inputs, const bool binary_input) {
    /*
      We construct an instance where the SAP degree is <= sap_degree.
      The R1CS-to-SAP reduction produces SAPs with degree
        (2 * num_constraints + 2 * num_inputs + 1).
      So we generate an instance of R1CS where the number of constraints is
        (sap_degree - 1) / 2 - num_inputs.
    */
    const std::size_t num_constraints = (sap_degree - 1) / 2 - num_inputs;
    BOOST_CHECK(num_constraints >= 1);

    r1cs_example<FieldType> example;
    if (binary_input) {
        example = generate_r1cs_example_with_binary_input<FieldType>(num_constraints, num_inputs);
    } else {
        example = generate_r1cs_example_with_field_input<FieldType>(num_constraints, num_inputs);
    }
    BOOST_CHECK(example.constraint_system.is_satisfied(example.primary_input, example.auxiliary_input));

    const FieldType t = FieldType::random_element(), d1 = FieldType::random_element(), d2 = FieldType::random_element();

    sap_instance<FieldType> sap_inst_1 = r1cs_to_sap_instance_map(example.constraint_system);

    sap_instance_evaluation<FieldType> sap_inst_2 = r1cs_to_sap_instance_map_with_evaluation(example.constraint_system, t);

    sap_witness<FieldType> sap_wit =
        r1cs_to_sap_witness_map(example.constraint_system, example.primary_input, example.auxiliary_input, d1, d2);

    BOOST_CHECK(sap_inst_1.is_satisfied(sap_wit));
    BOOST_CHECK(sap_inst_2.is_satisfied(sap_wit));
}

BOOST_AUTO_TEST_SUITE(sap_test_suite)

BOOST_AUTO_TEST_CASE(sap_test) {
    const std::size_t num_inputs = 10;

    /**
     * due to the specifics of our reduction, we can only get SAPs with odd
     * degrees, so we can only test "special" versions of the domains
     */

    const std::size_t basic_domain_size_special = (1ul << algebra::mnt6_Fr::s) - 1ul;
    const std::size_t step_domain_size_special = (1ul << 10) + (1ul << 8) - 1ul;
    const std::size_t extended_domain_size_special = (1ul << (algebra::mnt6_Fr::s + 1)) - 1ul;

    test_sap<typename algebra::curves::mnt6::scalar_field_type>(basic_domain_size_special, num_inputs, true);
    test_sap<typename algebra::curves::mnt6::scalar_field_type>(step_domain_size_special, num_inputs, true);
    test_sap<typename algebra::curves::mnt6::scalar_field_type>(extended_domain_size_special, num_inputs, true);

    test_sap<typename algebra::curves::mnt6::scalar_field_type>(basic_domain_size_special, num_inputs, false);
    test_sap<typename algebra::curves::mnt6::scalar_field_type>(step_domain_size_special, num_inputs, false);
    test_sap<typename algebra::curves::mnt6::scalar_field_type>(extended_domain_size_special, num_inputs, false);
}

BOOST_AUTO_TEST_SUITE_END()
