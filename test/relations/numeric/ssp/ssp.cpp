//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE ssp_test

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

#include <nil/crypto3/zk/snark/reductions/uscs_to_ssp/uscs_to_ssp.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/uscs/uscs.hpp>

#include <nil/algebra/utils/random_element.hpp>

#include "uscs_examples.hpp"

using namespace nil::crypto3::zk::snark;

template<typename FieldType>
void test_ssp(const std::size_t num_constraints, const std::size_t num_inputs, const bool binary_input) {
    uscs_example<FieldType> example;
    if (binary_input) {
        example = generate_uscs_example_with_binary_input<FieldType>(num_constraints, num_inputs);
    } else {
        example = generate_uscs_example_with_field_input<FieldType>(num_constraints, num_inputs);
    }

    BOOST_CHECK(example.constraint_system.is_satisfied(example.primary_input, example.auxiliary_input));

    const typename FieldType::value_type t = random_element<FieldType>(), d = random_element<FieldType>();

    ssp_instance<FieldType> ssp_inst_1 = uscs_to_ssp_instance_map(example.constraint_system);

    ssp_instance_evaluation<FieldType> ssp_inst_2 =
        uscs_to_ssp_instance_map_with_evaluation(example.constraint_system, t);

    ssp_witness<FieldType> ssp_wit =
        uscs_to_ssp_witness_map(example.constraint_system, example.primary_input, example.auxiliary_input, d);

    BOOST_CHECK(ssp_inst_1.is_satisfied(ssp_wit));
    BOOST_CHECK(ssp_inst_2.is_satisfied(ssp_wit));
}

BOOST_AUTO_TEST_SUITE(ssp_test_suite)

BOOST_AUTO_TEST_CASE(ssp_test) {
    const std::size_t num_inputs = 10;

    const std::size_t basic_domain_size = 1ul << algebra::mnt6_Fr::s;
    const std::size_t step_domain_size = (1ul << 10) + (1ul << 8);
    const std::size_t extended_domain_size = 1ul << (algebra::mnt6_Fr::s + 1);
    const std::size_t extended_domain_size_special = extended_domain_size - 1;

    test_ssp<typename algebra::curves::mnt6::scalar_field_type>(basic_domain_size, num_inputs, true);
    test_ssp<typename algebra::curves::mnt6::scalar_field_type>(step_domain_size, num_inputs, true);
    test_ssp<typename algebra::curves::mnt6::scalar_field_type>(extended_domain_size, num_inputs, true);
    test_ssp<typename algebra::curves::mnt6::scalar_field_type>(extended_domain_size_special, num_inputs, true);

    test_ssp<typename algebra::curves::mnt6::scalar_field_type>(basic_domain_size, num_inputs, false);
    test_ssp<typename algebra::curves::mnt6::scalar_field_type>(step_domain_size, num_inputs, false);
    test_ssp<typename algebra::curves::mnt6::scalar_field_type>(extended_domain_size, num_inputs, false);
    test_ssp<typename algebra::curves::mnt6::scalar_field_type>(extended_domain_size_special, num_inputs, false);
}

BOOST_AUTO_TEST_SUITE_END()