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

#define BOOST_TEST_MODULE ssp_test

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

#include <nil/crypto3/zk/snark/reductions/uscs_to_ssp.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/uscs.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
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

#include "uscs_examples.hpp"

using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::algebra;

template<typename FieldType>
void test_ssp(const std::size_t num_constraints, const std::size_t num_inputs, const bool binary_input) {
    uscs_example<FieldType> example;
    if (binary_input) {
        example = generate_uscs_example_with_binary_input<FieldType>(num_constraints, num_inputs);
    } else {
        example = generate_uscs_example_with_field_input<FieldType>(num_constraints, num_inputs);
    }

    BOOST_CHECK(example.constraint_system.is_satisfied(example.primary_input, example.auxiliary_input));

    const typename FieldType::value_type t = random_element<FieldType>(),
                                         d = random_element<FieldType>();

    ssp_instance<FieldType> ssp_inst_1 = reductions::uscs_to_ssp<FieldType>::instance_map(example.constraint_system);

    ssp_instance_evaluation<FieldType> ssp_inst_2 =
        reductions::uscs_to_ssp<FieldType>::instance_map_with_evaluation(example.constraint_system, t);

    ssp_witness<FieldType> ssp_wit =
        reductions::uscs_to_ssp<FieldType>::witness_map(example.constraint_system, example.primary_input, example.auxiliary_input, d);

    BOOST_CHECK(ssp_inst_1.is_satisfied(ssp_wit));
    BOOST_CHECK(ssp_inst_2.is_satisfied(ssp_wit));
}

BOOST_AUTO_TEST_SUITE(ssp_test_suite)

BOOST_AUTO_TEST_CASE(ssp_test) {
    const std::size_t num_inputs = 10;

    using basic_curve_type = curves::mnt6<298>;

    const std::size_t basic_domain_size = 1ul << fields::arithmetic_params<basic_curve_type::scalar_field_type>::s;
    const std::size_t step_domain_size = (1ul << 10) + (1ul << 8);
    const std::size_t extended_domain_size = 1ul << (fields::arithmetic_params<basic_curve_type::scalar_field_type>::s + 1);
    const std::size_t extended_domain_size_special = extended_domain_size - 1;

    test_ssp<typename basic_curve_type::scalar_field_type>(basic_domain_size, num_inputs, true);
    test_ssp<typename basic_curve_type::scalar_field_type>(step_domain_size, num_inputs, true);
    test_ssp<typename basic_curve_type::scalar_field_type>(extended_domain_size, num_inputs, true);
    test_ssp<typename basic_curve_type::scalar_field_type>(extended_domain_size_special, num_inputs, true);

    test_ssp<typename basic_curve_type::scalar_field_type>(basic_domain_size, num_inputs, false);
    test_ssp<typename basic_curve_type::scalar_field_type>(step_domain_size, num_inputs, false);
    test_ssp<typename basic_curve_type::scalar_field_type>(extended_domain_size, num_inputs, false);
    test_ssp<typename basic_curve_type::scalar_field_type>(extended_domain_size_special, num_inputs, false);
}

BOOST_AUTO_TEST_SUITE_END()