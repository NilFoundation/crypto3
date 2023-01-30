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
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/variable_base_scalar_mul_15_wires.hpp>
#include "test_plonk_component.hpp"

#include "../../zk/include/nil/crypto3/zk/snark/systems/plonk/placeholder/profiling.hpp"

template <typename CurveType>
void test_variable_base_scalar_mul (std::vector<typename CurveType::base_field_type::value_type> public_input,
typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type expected){
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 3;
	using BlueprintFieldType = typename CurveType::base_field_type;
    using BlueprintScalarType = typename CurveType::scalar_field_type;
    using ArithmetizationParams = nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;
	using component_type = nil::blueprint::components::curve_element_variable_base_scalar_mul<ArithmetizationType, CurveType, 15>;

	using var = nil::crypto3::zk::snark::plonk_variable<BlueprintFieldType>;

    var scalar_var = {0, 2, false, var::column_type::public_input};
    var T_X_var = {0, 0, false, var::column_type::public_input};
    var T_Y_var = {0, 1, false, var::column_type::public_input};
    typename component_type::input_type instance_input = {{T_X_var, T_Y_var},scalar_var};

	component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},{0},{});
	
	auto result_check = [&expected, public_input](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
			typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type R;
			R.X = var_value(assignment, real_res.X);
			R.Y = var_value(assignment, real_res.Y);
			std::cout << "var base scal mul: (" << public_input[0].data << " " << public_input[1].data << ") * " << public_input[2].data << "\n";
			std::cout << "expected:" << expected.X.data << " " << expected.Y.data << "\n";
			std::cout << "real    :" << R.X.data << " " << R.Y.data << "\n\n";
			auto ydata_expected = expected.Y.data;
			auto ydata_real = R.Y.data;

			assert(expected.X == R.X);
			std::cout << "assert(" << ydata_expected << " == " << ydata_real << ");" << std::endl;
			assert(ydata_expected == ydata_real);
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

template<>
struct shift_params<nil::crypto3::algebra::curves::vesta> {
	constexpr static const typename nil::crypto3::algebra::curves::vesta::scalar_field_type::value_type shift_base = 2;
	constexpr static const typename nil::crypto3::algebra::curves::vesta::scalar_field_type::value_type shift_for_1_0_neg1 = shift_base.pow(255);
	constexpr static const typename nil::crypto3::algebra::curves::vesta::scalar_field_type::value_type denominator_for_1_0_neg1 = 1;
};

template<typename CurveType>
typename CurveType::base_field_type::value_type shift_scalar(typename CurveType::scalar_field_type::value_type unshifted) {
	typename CurveType::scalar_field_type::value_type shift_base = 2;
	typename CurveType::scalar_field_type::value_type shift = shift_base.pow(255) + 1;
	typename CurveType::scalar_field_type::value_type denominator = 2;

	typename CurveType::scalar_field_type::value_type shift_for_1_0_neg1 =  shift_params<CurveType>::shift_for_1_0_neg1;
	typename CurveType::scalar_field_type::value_type denominator_for_1_0_neg1 =  shift_params<CurveType>::denominator_for_1_0_neg1;

	typename CurveType::scalar_field_type::value_type shifted;

	if ((unshifted == 1) || (unshifted == 0) || (unshifted == 1)){
		shifted = (unshifted - shift_for_1_0_neg1) / denominator_for_1_0_neg1;
	}
	else {
		shifted = (unshifted - shift) / denominator;
	}

	typename CurveType::scalar_field_type::integral_type shifted_integral_type = typename CurveType::scalar_field_type::integral_type(shifted.data);
	typename CurveType::base_field_type::value_type shifted_base_value_type = shifted_integral_type;
	return shifted_base_value_type;
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_variable_base_scalar_mul_random_scalar_pallas) {
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using BlueprintScalarType = typename curve_type::scalar_field_type;

    typename BlueprintScalarType::value_type b_scalar = 0x20000000000000000000000000000000224698fc094cf91b992d30ed00000000_cppui256;//nil::crypto3::algebra::random_element<BlueprintScalarType>();
	typename curve_type::scalar_field_type::value_type shift_base = 2;
	auto shift = shift_base.pow(255) + 1;
	typename BlueprintScalarType::value_type x = (b_scalar - shift)/2;
	typename BlueprintScalarType::integral_type integral_x = typename BlueprintScalarType::integral_type(x.data);
	typename BlueprintFieldType::value_type x_scalar =  integral_x;
	shift_scalar<curve_type>(b_scalar);

	curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type T = nil::crypto3::algebra::random_element<curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>>();
	curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type zero_point = {0, 0};
	std::vector<typename BlueprintFieldType::value_type> public_input = {T.X, T.Y, x_scalar};
    curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type expected;
	if (b_scalar != 0) {
	 	expected = b_scalar * T;
	} else {
		expected = {0, 0};
	}

	test_variable_base_scalar_mul<curve_type>({T.X, T.Y, shift_scalar<curve_type>(b_scalar)}, expected);
	test_variable_base_scalar_mul<curve_type>({T.X, T.Y, shift_scalar<curve_type>(-1)}, {T.X, -T.Y});
	test_variable_base_scalar_mul<curve_type>({T.X, T.Y, shift_scalar<curve_type>(0)}, zero_point);
	test_variable_base_scalar_mul<curve_type>({T.X, T.Y, shift_scalar<curve_type>(1)}, T);

	test_variable_base_scalar_mul<curve_type>({0, 0, shift_scalar<curve_type>(b_scalar)}, zero_point);
	test_variable_base_scalar_mul<curve_type>({0, 0, shift_scalar<curve_type>(-1)}, zero_point);
	test_variable_base_scalar_mul<curve_type>({0, 0, shift_scalar<curve_type>(0)}, zero_point);
	test_variable_base_scalar_mul<curve_type>({0, 0, shift_scalar<curve_type>(1)}, zero_point);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_variable_base_scalar_mul_scalar_one_pallas) {
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using BlueprintScalarType = typename curve_type::scalar_field_type;

    typename BlueprintScalarType::value_type b_scalar = 1;

	typename curve_type::scalar_field_type::value_type shift_base = 2;
	auto shift = shift_base.pow(255) + 1;
	typename BlueprintScalarType::value_type x = (b_scalar - shift)/2;
	typename BlueprintScalarType::integral_type integral_x = typename BlueprintScalarType::integral_type(x.data);
	typename BlueprintFieldType::value_type x_scalar =  integral_x;

	curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type T = nil::crypto3::algebra::random_element<curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>>();
	std::vector<typename BlueprintFieldType::value_type> public_input = {T.X, T.Y, x_scalar};
	curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type expected;
	if (b_scalar != 0) {
	 	expected = b_scalar * T;
	} else {
		expected = {0, 0};
	}

	test_variable_base_scalar_mul<curve_type>(public_input, expected);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_variable_base_scalar_mul_scalar_zero_pallas) {
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using BlueprintScalarType = typename curve_type::scalar_field_type;

    typename BlueprintScalarType::value_type b_scalar = 0;

	typename curve_type::scalar_field_type::value_type shift_base = 2;
	auto shift = shift_base.pow(255) + 1;
	typename BlueprintScalarType::value_type x = (b_scalar - shift)/2;
	typename BlueprintScalarType::integral_type integral_x = typename BlueprintScalarType::integral_type(x.data);
	typename BlueprintFieldType::value_type x_scalar =  integral_x;

	curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type T = nil::crypto3::algebra::random_element<curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>>();
	std::vector<typename BlueprintFieldType::value_type> public_input = {T.X, T.Y, x_scalar};
	curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type expected;
	if (b_scalar != 0) {
	 	expected = b_scalar * T;
	} else {
		expected = {0, 0};
	}

	test_variable_base_scalar_mul<curve_type>(public_input, expected);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_variable_base_scalar_mul_scalar_minus_one_pallas) {
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using BlueprintScalarType = typename curve_type::scalar_field_type;

    typename BlueprintScalarType::value_type b_scalar = -1;

	typename curve_type::scalar_field_type::value_type shift_base = 2;
	auto shift = shift_base.pow(255) + 1;
	typename BlueprintScalarType::value_type x = (b_scalar - shift)/2;
	typename BlueprintScalarType::integral_type integral_x = typename BlueprintScalarType::integral_type(x.data);
	typename BlueprintFieldType::value_type x_scalar =  integral_x;

	curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type T = nil::crypto3::algebra::random_element<curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>>();
	std::vector<typename BlueprintFieldType::value_type> public_input = {T.X, T.Y, x_scalar};
	curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type expected;
	if (b_scalar != 0) {
	 	expected = b_scalar * T;
	} else {
		expected = {0, 0};
	}

	test_variable_base_scalar_mul<curve_type>(public_input, expected);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_variable_base_scalar_mul_random_scalar_vesta) {
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using BlueprintScalarType = typename curve_type::scalar_field_type;

    typename BlueprintScalarType::value_type b_scalar = nil::crypto3::algebra::random_element<BlueprintScalarType>();

	typename curve_type::scalar_field_type::value_type shift_base = 2;
	auto shift = shift_base.pow(255) + 1;
	typename BlueprintScalarType::value_type x = (b_scalar - shift)/2;
	typename BlueprintScalarType::integral_type integral_x = typename BlueprintScalarType::integral_type(x.data);
	typename BlueprintFieldType::value_type x_scalar =  integral_x;

	curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type T = nil::crypto3::algebra::random_element<curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>>();
	std::vector<typename BlueprintFieldType::value_type> public_input = {T.X, T.Y, x_scalar};
	curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type expected;
	if (b_scalar != 0) {
	 	expected = b_scalar * T;
	} else {
		expected = {0, 0};
	}

	test_variable_base_scalar_mul<curve_type>(public_input, expected);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_variable_base_scalar_mul_scalar_one_vesta) {
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using BlueprintScalarType = typename curve_type::scalar_field_type;

    typename BlueprintScalarType::value_type b_scalar = 1;

	typename curve_type::scalar_field_type::value_type shift_base = 2;
	auto shift = shift_base.pow(255);
	typename BlueprintScalarType::value_type x = (b_scalar - shift);
	typename BlueprintScalarType::integral_type integral_x = typename BlueprintScalarType::integral_type(x.data);
	typename BlueprintFieldType::value_type x_scalar =  integral_x;

	curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type T = nil::crypto3::algebra::random_element<curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>>();
	std::vector<typename BlueprintFieldType::value_type> public_input = {T.X, T.Y, x_scalar};
	curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type expected;
	if (b_scalar != 0) {
	 	expected = b_scalar * T;
	} else {
		expected = {0, 0};
	}

	test_variable_base_scalar_mul<curve_type>(public_input, expected);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_variable_base_scalar_mul_scalar_zero_vesta) {
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using BlueprintScalarType = typename curve_type::scalar_field_type;

    typename BlueprintScalarType::value_type b_scalar = 0;

	typename curve_type::scalar_field_type::value_type shift_base = 2;
	auto shift = shift_base.pow(255);
	typename BlueprintScalarType::value_type x = (b_scalar - shift);
	typename BlueprintScalarType::integral_type integral_x = typename BlueprintScalarType::integral_type(x.data);
	typename BlueprintFieldType::value_type x_scalar =  integral_x;

	curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type T = nil::crypto3::algebra::random_element<curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>>();
	std::vector<typename BlueprintFieldType::value_type> public_input = {T.X, T.Y, x_scalar};
	curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type expected;
	if (b_scalar != 0) {
	 	expected = b_scalar * T;
	} else {
		expected = {0, 0};
	}

	test_variable_base_scalar_mul<curve_type>(public_input, expected);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_variable_base_scalar_mul_scalar_minus_one_vesta) {
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using BlueprintScalarType = typename curve_type::scalar_field_type;

    typename BlueprintScalarType::value_type b_scalar = -1;

	typename curve_type::scalar_field_type::value_type shift_base = 2;
	auto shift = shift_base.pow(255);
	typename BlueprintScalarType::value_type x = (b_scalar - shift);
	typename BlueprintScalarType::integral_type integral_x = typename BlueprintScalarType::integral_type(x.data);
	typename BlueprintFieldType::value_type x_scalar =  integral_x;

	curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type T = nil::crypto3::algebra::random_element<curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>>();
	std::vector<typename BlueprintFieldType::value_type> public_input = {T.X, T.Y, x_scalar};
	curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type expected;
	if (b_scalar != 0) {
	 	expected = b_scalar * T;
	} else {
		expected = {0, 0};
	}

	test_variable_base_scalar_mul<curve_type>(public_input, expected);
}

BOOST_AUTO_TEST_SUITE_END()