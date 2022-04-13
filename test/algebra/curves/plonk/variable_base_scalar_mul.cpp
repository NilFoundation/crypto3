//---------------------------------------------------------------------------//
// Copyright (c) 2018-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2022 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE variable_base_scalar_mul_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/variable_base_scalar_mul_15_wires.hpp>
#include "test_plonk_component.hpp"

#include "../../../profiling.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

/*BOOST_AUTO_TEST_CASE(variable_base_scalar_mul_5_wires_test_case) {

	using curve_type = algebra::curves::bls12<381>;
	using BlueprintFieldType = typename curve_type::base_field_type;
	constexpr std::size_t WitnessColumns = 5;
	using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;

	zk::blueprint<ArithmetizationType> bp;

	using component_type = zk::components::element_g1_variable_base_scalar_mul<ArithmetizationType, curve_type, 0, 1, 2, 3, 4>;

	component_type scalar_mul_component(bp);

	scalar_mul_component.generate_gates();

	typename curve_type::scalar_field_type::value_type a = curve_type::scalar_field_type::value_type::one();
	typename curve_type::template g1_type<>::value_type P = curve_type::template g1_type<>::value_type::one();

	scalar_mul_component.generate_assignments(a, P);

	auto cs = bp.get_constraint_system();

	auto assignments = bp.full_variable_assignment();

	typedef zk::snark::redshift_preprocessor <typename curve_type::base_field_type, 5, 1> preprocess_type;

    auto preprocessed_data = preprocess_type::process(cs, assignments);
	typedef zk::snark::redshift_prover <typename curve_type::base_field_type, 5, 5, 1, 5> prove_type;
	auto proof = prove_type::process(preprocessed_data, cs, assignments);
}

BOOST_AUTO_TEST_CASE(variable_base_scalar_mul_9_wires_test_case) {

	using curve_type = algebra::curves::bls12<381>;
	using BlueprintFieldType = typename curve_type::base_field_type;
	constexpr std::size_t WitnessColumns = 9;
	using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;

	zk::blueprint<ArithmetizationType> bp;

	using component_type = zk::components::element_g1_variable_base_scalar_mul<ArithmetizationType, curve_type, 0, 1, 2, 3, 4, 5, 6, 7, 8>;

	component_type scalar_mul_component = component_type(bp);

	scalar_mul_component.generate_gates();

	typename curve_type::scalar_field_type::value_type a = curve_type::scalar_field_type::value_type::one();
	typename curve_type::template g1_type<>::value_type P = curve_type::template g1_type<>::value_type::one();

	scalar_mul_component.generate_assignments(a, P);

	auto cs = bp.get_constraint_system();

	auto assignments = bp.full_variable_assignment();

	typedef zk::snark::redshift_preprocessor <typename curve_type::base_field_type, 9, 1> preprocess_type;

    auto preprocessed_data = preprocess_type::process(cs, assignments);
	typedef zk::snark::redshift_prover <typename curve_type::base_field_type, 9, 5, 1, 5> prove_type;
	auto proof = prove_type::process(preprocessed_data, cs, assignments);
}*/

BOOST_AUTO_TEST_CASE(blueprint_plonk_variable_base_scalar_mul) {

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using BlueprintScalarType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using component_type = zk::components::curve_element_variable_base_scalar_mul<ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    typename component_type::public_params_type init_params = {};
    curve_type::scalar_field_type::value_type b = algebra::random_element<BlueprintScalarType>();
    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type T = algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();
	typename component_type::private_params_type assignment_params = {T,b};
	typename curve_type::scalar_field_type::value_type tmp = 2;
	tmp = tmp.pow(255);
	tmp = (1 + tmp + 2*b);
	curve_type::scalar_field_type::value_type c = tmp;
	curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type acc = c*T;
    std::cout<<"Expected result: "<<acc.X.data<<" "<< acc.Y.data<<std::endl;
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (init_params, assignment_params);
}

BOOST_AUTO_TEST_SUITE_END()