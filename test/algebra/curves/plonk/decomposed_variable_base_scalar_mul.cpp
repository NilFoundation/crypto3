//---------------------------------------------------------------------------//
// Copyright (c) 2018-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#define BOOST_TEST_MODULE decomposed_variable_base_scalar_mul_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/decomposed_variable_base_scalar_mul_15_wires.hpp>
#include "test_plonk_component.hpp"

#include "../../zk/include/nil/crypto3/zk/snark/systems/plonk/placeholder/profiling.hpp"

using namespace nil::crypto3;

template<typename CurveType>
constexpr static bool scalar_larger() {
    using ScalarField = typename CurveType::scalar_field_type;
    using BaseField = typename CurveType::base_field_type;

    auto n1 = ScalarField::modulus;
    auto n2 = BaseField::modulus;

    return n1 > n2;
}

template <typename CurveType>
void test_decomposed_variable_base_scalar_mul (std::vector<typename CurveType::base_field_type::value_type> public_input,
typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type expected){
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 4;
	using BlueprintFieldType = typename CurveType::base_field_type;
    using BlueprintScalarType = typename CurveType::scalar_field_type;
    using ArithmetizationParams = nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;
	using component_type = nil::blueprint::components::curve_element_decomposed_variable_base_scalar_mul<ArithmetizationType, CurveType, 15>;

	using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

	var scalar_var1 = {0, 2, false, var::column_type::public_input};
	var scalar_var2 = {0, 3, false, var::column_type::public_input};
    var T_X_var = {0, 0, false, var::column_type::public_input};
    var T_Y_var = {0, 1, false, var::column_type::public_input};
    typename component_type::input_type instance_input = {{T_X_var, T_Y_var},scalar_var1, scalar_var2};
	

	component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},{0},{});
	
	auto result_check = [&expected, public_input](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
			typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type R;
			R.X = var_value(assignment, real_res.X);
			R.Y = var_value(assignment, real_res.Y);

			#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
		    std::cout << std::hex;
	        std::cout << "_________________________________________________________________________________________________________________________________________________\n"; 
			std::cout << "decomposed var base scal mul: (" << public_input[0].data << " " << public_input[1].data << ") * " << public_input[2].data << "\n";
			std::cout << "expected:" << expected.X.data << " " << expected.Y.data << "\n";
			std::cout << "real    :" << R.X.data << " " << R.Y.data << "\n";
			#endif

			assert(expected.X == R.X);
			assert(expected.Y - R.Y == 0); // not (expected.Y == R.Y) because of issue https://github.com/NilFoundation/crypto3-multiprecision/issues/38
    };
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (component_instance, public_input, result_check, instance_input);
}

template <typename CurveType>
struct shift_params;

template<>
struct shift_params<nil::crypto3::algebra::curves::pallas> {
	constexpr static const typename nil::crypto3::algebra::curves::pallas::scalar_field_type::value_type shift_base = 2;
	constexpr static const typename nil::crypto3::algebra::curves::pallas::scalar_field_type::value_type shift_for_1_0_neg1 = shift_base.pow(255) + 1;
	constexpr static const typename nil::crypto3::algebra::curves::pallas::scalar_field_type::value_type denominator_for_1_0_neg1 = 2;
};

template<typename CurveType>
typename CurveType::base_field_type::integral_type shift_scalar(typename CurveType::scalar_field_type::value_type unshifted) {
	typename CurveType::scalar_field_type::value_type shift_base = 2;
	typename CurveType::scalar_field_type::value_type shift = shift_base.pow(255) + 1;
	typename CurveType::scalar_field_type::value_type denominator = 2;

	typename CurveType::scalar_field_type::value_type shift_for_1_0_neg1 =  shift_params<CurveType>::shift_for_1_0_neg1;
	typename CurveType::scalar_field_type::value_type denominator_for_1_0_neg1 =  shift_params<CurveType>::denominator_for_1_0_neg1;

	typename CurveType::scalar_field_type::value_type shifted;

	if ((unshifted == 1) || (unshifted == 0) || (unshifted == -1)){
		shifted = (unshifted - shift_for_1_0_neg1) / denominator_for_1_0_neg1;
	}
	else {
		shifted = (unshifted - shift) / denominator;
	}

	typename CurveType::scalar_field_type::integral_type shifted_integral_type = typename CurveType::scalar_field_type::integral_type(shifted.data);
	return shifted_integral_type;
}

template<typename CurveType>
void test_decomposed_vbsm(
	typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type point,
	typename CurveType::scalar_field_type::value_type scalar) {
		typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type zero_point = {0, 0};
		typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type expected;
		if (scalar != 0) {
			expected = point * scalar;
		} else {
			expected = {0, 0};
		}

		typename CurveType::scalar_field_type::integral_type shifted_scalar = shift_scalar<CurveType>(scalar);
		typename CurveType::scalar_field_type::integral_type one = 1;
		typename CurveType::scalar_field_type::integral_type mask = (one << 254) - 1;

		typename CurveType::scalar_field_type::integral_type least254bytes = shifted_scalar & mask;
		typename CurveType::scalar_field_type::integral_type other_bytes = shifted_scalar >> 254;


		test_decomposed_variable_base_scalar_mul<CurveType>({point.X, point.Y, least254bytes, other_bytes}, expected);
	}


BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_decomposed_variable_base_scalar_mul_random_scalar_pallas) {
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using BlueprintScalarType = typename curve_type::scalar_field_type;

	static_assert(scalar_larger<curve_type>(), "Decomposed vbsm is only for scalar_field > base_field! Use usual vbsm");

	nil::crypto3::random::algebraic_engine<typename curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>> random_point;
    boost::random::mt19937 seed_seq;
    random_point.seed(seed_seq);

	nil::crypto3::random::algebraic_engine<BlueprintScalarType> random_scalar;
    boost::random::mt19937 seed_seq2;
    random_scalar.seed(seed_seq2);

	typename BlueprintScalarType::value_type two = 2;
	typename BlueprintScalarType::value_type threefff = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_cppui255;
	typename BlueprintScalarType::value_type unshifted_threefff = 2*threefff + two.pow(255) + 1;

	test_decomposed_vbsm<curve_type>(random_point(), two + two.pow(255) + 1);
	test_decomposed_vbsm<curve_type>(random_point(), two - two + two.pow(255) + 1);
	test_decomposed_vbsm<curve_type>(random_point(), two - two - two + two.pow(255) + 1);
	test_decomposed_vbsm<curve_type>(random_point(), random_scalar());
	test_decomposed_vbsm<curve_type>(random_point(), unshifted_threefff);
	test_decomposed_vbsm<curve_type>(random_point(), 1);
	test_decomposed_vbsm<curve_type>(random_point(), 0);
	test_decomposed_vbsm<curve_type>(random_point(), -1);

	test_decomposed_vbsm<curve_type>({0, 0}, two + two.pow(255) + 1);
	test_decomposed_vbsm<curve_type>({0, 0}, two - two + two.pow(255) + 1);
	test_decomposed_vbsm<curve_type>({0, 0}, two - two - two + two.pow(255) + 1);
	test_decomposed_vbsm<curve_type>({0, 0}, random_scalar());
	test_decomposed_vbsm<curve_type>({0, 0}, unshifted_threefff);
	test_decomposed_vbsm<curve_type>({0, 0}, 1);
	test_decomposed_vbsm<curve_type>({0, 0}, 0);
	test_decomposed_vbsm<curve_type>({0, 0}, -1);
}

BOOST_AUTO_TEST_SUITE_END()