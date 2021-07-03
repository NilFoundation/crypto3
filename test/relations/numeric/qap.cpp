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

#define BOOST_TEST_MODULE qap_test

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>
#include <chrono>

#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>
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

#include "../../schemes/ppzksnark/r1cs_examples.hpp"

using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::algebra;

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

    std::cout << "Num constraints " << num_constraints << std::endl;
    std::cout << "Binary input " << bool(binary_input) << std::endl;

    auto begin = std::chrono::high_resolution_clock::now();

    r1cs_example<FieldType> example;
    if (binary_input) {
        example = generate_r1cs_example_with_binary_input<FieldType>(num_constraints, num_inputs);
    } else {
        example = generate_r1cs_example_with_field_input<FieldType>(num_constraints, num_inputs);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

    std::cout << "Example generated, time: " << elapsed.count() * 1e-9 << std::endl;

    BOOST_CHECK(example.constraint_system.is_satisfied(example.primary_input, example.auxiliary_input));

    std::cout << "Constraint system satisfied" << std::endl;

    const typename FieldType::value_type t = random_element<FieldType>(),
                                         d1 = random_element<FieldType>(),
                                         d2 = random_element<FieldType>(),
                                         d3 = random_element<FieldType>();
    begin = std::chrono::high_resolution_clock::now();

    qap_instance<FieldType> qap_inst_1 = reductions::r1cs_to_qap<FieldType>::instance_map(example.constraint_system);

    end = std::chrono::high_resolution_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

    std::cout << "Instance 1 evaluated, time: " << elapsed.count() * 1e-9 << std::endl;

    begin = std::chrono::high_resolution_clock::now();

    qap_instance_evaluation<FieldType> qap_inst_2 =
        reductions::r1cs_to_qap<FieldType>::instance_map_with_evaluation(example.constraint_system, t);

    end = std::chrono::high_resolution_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

    std::cout << "Instance 2 evaluated, time: " << elapsed.count() * 1e-9 << std::endl;

    begin = std::chrono::high_resolution_clock::now();

    qap_witness<FieldType> qap_wit =
        reductions::r1cs_to_qap<FieldType>::witness_map(example.constraint_system, example.primary_input, example.auxiliary_input, d1, d2, d3);

    end = std::chrono::high_resolution_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

    std::cout << "Witness evaluated, time: " << elapsed.count() * 1e-9 << std::endl;

    BOOST_CHECK(qap_inst_1.is_satisfied(qap_wit));
    BOOST_CHECK(qap_inst_2.is_satisfied(qap_wit));
}

BOOST_AUTO_TEST_SUITE(qap_test_suite)

BOOST_AUTO_TEST_CASE(qap_test_case) {
    const std::size_t num_inputs = 10;

    using basic_curve_type = curves::mnt6<298>;

    const std::size_t basic_domain_size = 1ul << fields::arithmetic_params<basic_curve_type::scalar_field_type>::s;
    const std::size_t step_domain_size = (1ul << 10) + (1ul << 8);
    const std::size_t extended_domain_size = 1ul << (fields::arithmetic_params<basic_curve_type::scalar_field_type>::s + 1);
    const std::size_t extended_domain_size_special = extended_domain_size - 1;

    test_qap<typename basic_curve_type::scalar_field_type>(basic_domain_size, num_inputs, true);
    test_qap<typename basic_curve_type::scalar_field_type>(step_domain_size, num_inputs, true);
    test_qap<typename basic_curve_type::scalar_field_type>(extended_domain_size, num_inputs, true);
    test_qap<typename basic_curve_type::scalar_field_type>(extended_domain_size_special, num_inputs, true);

    test_qap<typename basic_curve_type::scalar_field_type>(basic_domain_size, num_inputs, false);
    test_qap<typename basic_curve_type::scalar_field_type>(step_domain_size, num_inputs, false);
    test_qap<typename basic_curve_type::scalar_field_type>(extended_domain_size, num_inputs, false);
    test_qap<typename basic_curve_type::scalar_field_type>(extended_domain_size_special, num_inputs, false);
}

BOOST_AUTO_TEST_SUITE_END()