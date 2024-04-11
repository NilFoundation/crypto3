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

#define BOOST_TEST_MODULE variable_base_scalar_mul_test

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
#include <nil/blueprint/component_stretcher.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/variable_base_scalar_mul.hpp>
#include "../../../test_plonk_component.hpp"

template <typename CurveType, bool Stretched = false>
void test_variable_base_scalar_mul (
		const std::vector<typename CurveType::base_field_type::value_type> &public_input,
		typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type expected){
    constexpr std::size_t WitnessColumns = 15 * (Stretched ? 2 : 1);
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 4;
	using BlueprintFieldType = typename CurveType::base_field_type;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = nil::blueprint::assignment<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;
	using component_type = nil::blueprint::components::curve_element_variable_base_scalar_mul<ArithmetizationType, CurveType>;

	using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

	component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},{0},{});

	auto result_check = [&expected, public_input](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
			typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type R;
			R.X = var_value(assignment, real_res.X);
			R.Y = var_value(assignment, real_res.Y);

			assert(expected.X == R.X);
			assert(expected.Y - R.Y == 0); // not (expected.Y == R.Y) because of issue https://github.com/NilFoundation/crypto3-multiprecision/issues/38
    };

	var scalar_var = {0, 2, false, var::column_type::public_input};
    var T_X_var = {0, 0, false, var::column_type::public_input};
    var T_Y_var = {0, 1, false, var::column_type::public_input};

	if constexpr (Stretched) {
        using stretched_component_type = nil::blueprint::components::component_stretcher<
            BlueprintFieldType,
            component_type>;

        stretched_component_type stretched_instance(component_instance, WitnessColumns / 2, WitnessColumns);

		if constexpr (std::is_same<CurveType,nil::crypto3::algebra::curves::pallas>::value) {
			var high_bit = {0, 3, false, var::column_type::public_input};
			typename component_type::input_type instance_input = {{T_X_var, T_Y_var},scalar_var, high_bit};
			nil::crypto3::test_component<stretched_component_type, BlueprintFieldType,
										 hash_type, Lambda>
			 	(stretched_instance, desc, public_input, result_check, instance_input);
		} else {
			typename component_type::input_type instance_input = {{T_X_var, T_Y_var},scalar_var};
			nil::crypto3::test_component<stretched_component_type, BlueprintFieldType,
										 hash_type, Lambda>
				(stretched_instance, desc, public_input, result_check, instance_input);
		}
	} else {
		if constexpr (std::is_same<CurveType,nil::crypto3::algebra::curves::pallas>::value) {
			var high_bit = {0, 3, false, var::column_type::public_input};
			typename component_type::input_type instance_input = {{T_X_var, T_Y_var},scalar_var, high_bit};
			nil::crypto3::test_component<component_type, BlueprintFieldType,
										 hash_type, Lambda>
			 	(component_instance, desc, public_input, result_check, instance_input);
		} else {
			typename component_type::input_type instance_input = {{T_X_var, T_Y_var},scalar_var};
			nil::crypto3::test_component<component_type, BlueprintFieldType,
										 hash_type, Lambda>
				(component_instance, desc, public_input, result_check, instance_input);
		}
	}
}


template <typename CurveType>
struct shift_params;

template<>
struct shift_params<nil::crypto3::algebra::curves::pallas> {
	constexpr static const typename nil::crypto3::algebra::curves::pallas::scalar_field_type::value_type shift_base = 2;
	constexpr static const typename nil::crypto3::algebra::curves::pallas::scalar_field_type::value_type shift_for_1_0_neg1 = shift_base.pow(255) + 1;
	constexpr static const typename nil::crypto3::algebra::curves::pallas::scalar_field_type::value_type denominator_for_1_0_neg1 = 2;
};

template<>
struct shift_params<nil::crypto3::algebra::curves::vesta> {
	constexpr static const typename nil::crypto3::algebra::curves::vesta::scalar_field_type::value_type shift_base = 2;
	constexpr static const typename nil::crypto3::algebra::curves::vesta::scalar_field_type::value_type shift_for_1_0_neg1 = shift_base.pow(255);
	constexpr static const typename nil::crypto3::algebra::curves::vesta::scalar_field_type::value_type denominator_for_1_0_neg1 = 1;
};

template<typename CurveType>
typename CurveType::scalar_field_type::value_type shift_scalar(typename CurveType::scalar_field_type::value_type unshifted) {
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

	return shifted;
}

template <typename CurveType>
void test_variable_base_scalar_mul_with_stretching(
	const std::vector<typename CurveType::base_field_type::value_type> &public_input,
	typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type expected) {

	test_variable_base_scalar_mul<CurveType, false>(public_input, expected);
	test_variable_base_scalar_mul<CurveType, true>(public_input, expected);
}


template<typename CurveType>
void test_vbsm(
	typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type point,
	typename CurveType::scalar_field_type::value_type scalar) {
		typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type zero_point = {0, 0};
		typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type expected;
		if (scalar != 0) {
			expected = point * scalar;
		} else {
			expected = {0, 0};
		}

		typename CurveType::scalar_field_type::value_type shifted = shift_scalar<CurveType>(scalar);
		typename CurveType::scalar_field_type::integral_type shifted_integral_type = typename CurveType::scalar_field_type::integral_type(shifted.data);
		typename CurveType::base_field_type::value_type shifted_base_value_type = shifted_integral_type;
		typename CurveType::base_field_type::value_type shifted_base_value_type_bit;
		typename CurveType::scalar_field_type::value_type two = 2;

		if constexpr (std::is_same<CurveType, nil::crypto3::algebra::curves::pallas>::value) {
			if (shifted >= two.pow(254)) {
				shifted = shifted - two.pow(254);
				shifted_integral_type = typename CurveType::scalar_field_type::integral_type(shifted.data);
				shifted_base_value_type = shifted_integral_type;
				shifted_base_value_type_bit = 1;
			} else {
				shifted_base_value_type = shifted_integral_type;
				shifted_base_value_type_bit = 0;
			}
			test_variable_base_scalar_mul_with_stretching<CurveType>(
				{point.X, point.Y, shifted_base_value_type, shifted_base_value_type_bit}, expected);
		} else {
			shifted_base_value_type = shifted_integral_type;
			test_variable_base_scalar_mul_with_stretching<CurveType>(
				{point.X, point.Y, shifted_base_value_type}, expected);
		}
	}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_variable_base_scalar_mul_random_scalar_pallas) {

	// regular test (base field larger than scalar field)
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using BlueprintScalarType = typename curve_type::scalar_field_type;

	nil::crypto3::random::algebraic_engine<typename curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>> random_point;
    boost::random::mt19937 seed_seq;
    random_point.seed(seed_seq);

	nil::crypto3::random::algebraic_engine<BlueprintScalarType> random_scalar;
    boost::random::mt19937 seed_seq2;
    random_scalar.seed(seed_seq2);

	typename BlueprintScalarType::value_type two = 2;
	typename BlueprintScalarType::value_type threefff = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_cppui255;
	typename BlueprintScalarType::value_type unshifted_threefff = 2*threefff + two.pow(255) + 1;

	test_vbsm<curve_type>(random_point(), two + two.pow(255) + 1);
	test_vbsm<curve_type>(random_point(), two - two + two.pow(255) + 1);
	test_vbsm<curve_type>(random_point(), two - two - two + two.pow(255) + 1);
	test_vbsm<curve_type>(random_point(), unshifted_threefff);
	test_vbsm<curve_type>(random_point(), random_scalar());
	test_vbsm<curve_type>(random_point(), 1);
	test_vbsm<curve_type>(random_point(), 0);
	test_vbsm<curve_type>(random_point(), -1);

	test_vbsm<curve_type>({0, 0}, two + two.pow(255) + 1);
	test_vbsm<curve_type>({0, 0}, two - two + two.pow(255) + 1);
	test_vbsm<curve_type>({0, 0}, two - two - two + two.pow(255) + 1);
	test_vbsm<curve_type>({0, 0}, unshifted_threefff);
	test_vbsm<curve_type>({0, 0}, random_scalar());
	test_vbsm<curve_type>({0, 0}, 1);
	test_vbsm<curve_type>({0, 0}, 0);
	test_vbsm<curve_type>({0, 0}, -1);

	// decomposed test (scalar field larger than base field)
	using pallas_curve_type = nil::crypto3::algebra::curves::pallas;

	nil::crypto3::random::algebraic_engine<typename pallas_curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>> pallas_random_point;
	boost::random::random_device dev;
    boost::random::mt19937 pallas_seed_seq(dev);
    random_point.seed(pallas_seed_seq);
	nil::crypto3::random::algebraic_engine<pallas_curve_type::scalar_field_type> pallas_random_scalar;
    random_scalar.seed(pallas_seed_seq);

	typename pallas_curve_type::scalar_field_type::value_type pallas_two = 2;
	typename pallas_curve_type::scalar_field_type::value_type pallas_threefff = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_cppui255;
	typename pallas_curve_type::scalar_field_type::value_type pallas_unshifted_threefff = 2*pallas_threefff + pallas_two.pow(255) + 1;
	typename pallas_curve_type::scalar_field_type::value_type pallas_p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui255;

	test_vbsm<pallas_curve_type>(pallas_random_point(), pallas_two + pallas_two.pow(255) + 1);
	test_vbsm<pallas_curve_type>(pallas_random_point(), pallas_two - pallas_two + pallas_two.pow(255) + 1);
	test_vbsm<pallas_curve_type>(pallas_random_point(), pallas_two - pallas_two - pallas_two + pallas_two.pow(255) + 1);
	test_vbsm<pallas_curve_type>(pallas_random_point(), pallas_unshifted_threefff);
	test_vbsm<pallas_curve_type>(pallas_random_point(), pallas_random_scalar());
	test_vbsm<pallas_curve_type>(pallas_random_point(), 1);
	test_vbsm<pallas_curve_type>(pallas_random_point(), 0);
	test_vbsm<pallas_curve_type>(pallas_random_point(), -1);

	test_vbsm<pallas_curve_type>({0, 0}, pallas_two + pallas_two.pow(255) + 1);
	test_vbsm<pallas_curve_type>({0, 0}, pallas_two - pallas_two + pallas_two.pow(255) + 1);
	test_vbsm<pallas_curve_type>({0, 0}, pallas_two - pallas_two - pallas_two + pallas_two.pow(255) + 1);
	test_vbsm<pallas_curve_type>({0, 0}, pallas_unshifted_threefff);
	test_vbsm<pallas_curve_type>({0, 0}, pallas_random_scalar());
	test_vbsm<pallas_curve_type>({0, 0}, 1);
	test_vbsm<pallas_curve_type>({0, 0}, 0);
	test_vbsm<pallas_curve_type>({0, 0}, -1);

	test_vbsm<pallas_curve_type>(pallas_random_point(), pallas_p + 2);
}

BOOST_AUTO_TEST_SUITE_END()