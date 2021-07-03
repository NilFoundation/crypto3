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

#define BOOST_TEST_MODULE sap_test

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

#include <nil/crypto3/zk/snark/reductions/r1cs_to_sap.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

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

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_examples.hpp>

using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::algebra;

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

    const typename FieldType::value_type t = random_element<FieldType>(),
                                         d1 = random_element<FieldType>(),
                                         d2 = random_element<FieldType>();

    sap_instance<FieldType> sap_inst_1 = reductions::r1cs_to_sap<FieldType>::instance_map(example.constraint_system);

    sap_instance_evaluation<FieldType> sap_inst_2 =
        reductions::r1cs_to_sap<FieldType>::instance_map_with_evaluation(example.constraint_system, t);

    sap_witness<FieldType> sap_wit =
        reductions::r1cs_to_sap<FieldType>::witness_map(example.constraint_system, example.primary_input, example.auxiliary_input, d1, d2);

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

    using basic_curve_type = curves::mnt6<298>;

    const std::size_t basic_domain_size_special = (1ul << fields::arithmetic_params<basic_curve_type::scalar_field_type>::s) - 1ul;
    const std::size_t step_domain_size_special = (1ul << 10) + (1ul << 8) - 1ul;
    const std::size_t extended_domain_size_special = (1ul << (fields::arithmetic_params<basic_curve_type::scalar_field_type>::s + 1)) - 1ul;

    test_sap<typename basic_curve_type::scalar_field_type>(basic_domain_size_special, num_inputs, true);
    test_sap<typename basic_curve_type::scalar_field_type>(step_domain_size_special, num_inputs, true);
    test_sap<typename basic_curve_type::scalar_field_type>(extended_domain_size_special, num_inputs, true);

    test_sap<typename basic_curve_type::scalar_field_type>(basic_domain_size_special, num_inputs, false);
    test_sap<typename basic_curve_type::scalar_field_type>(step_domain_size_special, num_inputs, false);
    test_sap<typename basic_curve_type::scalar_field_type>(extended_domain_size_special, num_inputs, false);
}

BOOST_AUTO_TEST_SUITE_END()
