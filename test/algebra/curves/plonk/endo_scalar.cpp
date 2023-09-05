//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_endo_scalar_test

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
#include <nil/blueprint/components/algebra/curves/pasta/plonk/endo_scalar.hpp>

#include "../../../test_plonk_component.hpp"

template<typename CurveType>
struct endo_scalar_params;

template<>
struct endo_scalar_params<nil::crypto3::algebra::curves::vesta> {
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using base_field_type = typename curve_type::base_field_type;
    constexpr static const typename scalar_field_type::value_type endo_r =
        0x12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9_cppui255;
    constexpr static const typename base_field_type::value_type endo_q =
        0x2D33357CB532458ED3552A23A8554E5005270D29D19FC7D27B7FD22F0201B547_cppui255;
};

template<>
struct endo_scalar_params<nil::crypto3::algebra::curves::pallas> {
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using base_field_type = typename curve_type::base_field_type;
    constexpr static const typename scalar_field_type::value_type endo_r =
        0x397E65A7D7C1AD71AEE24B27E308F0A61259527EC1D4752E619D1840AF55F1B1_cppui255;
    constexpr static const typename base_field_type::value_type endo_q =
        0x2D33357CB532458ED3552A23A8554E5005270D29D19FC7D27B7FD22F0201B547_cppui255;
};

template<typename CurveType, std::size_t ScalarSize>
typename CurveType::scalar_field_type::value_type calculate_endo_scalar(typename CurveType::scalar_field_type::value_type scalar) {

    using endo_params = endo_scalar_params<CurveType>;
    using BlueprintFieldType = typename CurveType::scalar_field_type;

    typename BlueprintFieldType::value_type endo_r = endo_params::endo_r;

    const std::size_t crumbs_per_row = 8;
    const std::size_t bits_per_crumb = 2;
    const std::size_t bits_per_row =
        bits_per_crumb * crumbs_per_row;    // we suppose that ScalarSize % bits_per_row = 0

    typename BlueprintFieldType::integral_type integral_scalar =
        typename BlueprintFieldType::integral_type(scalar.data);
    std::array<bool, ScalarSize> bits_msb;
    {
        nil::marshalling::status_type status;
        assert(ScalarSize <= 255);
        std::array<bool, 255> bits_msb_all =
            nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_scalar, status);
        assert(status == nil::marshalling::status_type::success);
        std::copy(bits_msb_all.end() - ScalarSize, bits_msb_all.end(), bits_msb.begin());

        for(std::size_t i = 0; i < 255 - ScalarSize; ++i) {
            assert(bits_msb_all[i] == false);
        }
    }
    typename BlueprintFieldType::value_type a = 2;
    typename BlueprintFieldType::value_type b = 2;
    typename BlueprintFieldType::value_type n = 0;

    assert (ScalarSize % bits_per_row == 0);
    for (std::size_t chunk_start = 0; chunk_start < bits_msb.size(); chunk_start += bits_per_row) {
        for (std::size_t j = 0; j < crumbs_per_row; j++) {
            std::size_t crumb = chunk_start + j * bits_per_crumb;
            typename BlueprintFieldType::value_type b0 = static_cast<int>(bits_msb[crumb + 1]);
            typename BlueprintFieldType::value_type b1 = static_cast<int>(bits_msb[crumb + 0]);

            typename BlueprintFieldType::value_type crumb_value = b0 + b1.doubled();

            a = a.doubled();
            b = b.doubled();

            typename BlueprintFieldType::value_type s =
                (b0 == BlueprintFieldType::value_type::one()) ? 1 : -1;
            if (b1 == BlueprintFieldType::value_type::zero()) {
                b += s;
            } else {
                a += s;
            }

            n = (n.doubled()).doubled();
            n += crumb_value;
        }
    }
    auto res = a * endo_r + b;
    return res;
}

template <typename CurveType>
void test_endo_scalar(std::vector<typename CurveType::scalar_field_type::value_type> public_input,
            typename CurveType::scalar_field_type::value_type expected_res){
    using BlueprintFieldType = typename CurveType::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 2;
    using ArithmetizationParams = nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
	constexpr static const std::size_t num_bits = 128;

    using component_type = nil::blueprint::components::endo_scalar<ArithmetizationType, CurveType>;

	using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    var challenge_var(0, 0, false, var::column_type::public_input);
    typename component_type::input_type instance_input = {challenge_var};

    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "endo_scalar input: " << std::hex << public_input[0].data << "\n";
            std::cout << "expected result  : " << std::hex << expected_res.data << "\n";
            std::cout << "real result      : " << std::hex << var_value(assignment, real_res.output).data << "\n\n";
            #endif

            assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},{},{},num_bits);

    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (component_instance, public_input, result_check, instance_input);
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_endo_scalar_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_endo_scalar_vesta) {
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;

    typename BlueprintFieldType::value_type challenge = 0x00000000000000000000000000000000FC93536CAE0C612C18FBE5F6D8E8EEF2_cppui255;
    typename BlueprintFieldType::value_type result = 0x004638173549A4C55A118327904B54E5F6F6314225C8C862F5AFA2506C77AC65_cppui255;

	test_endo_scalar<curve_type>({challenge}, result);
	test_endo_scalar<curve_type>({1}, calculate_endo_scalar<curve_type, 128>(1));
	test_endo_scalar<curve_type>({0}, calculate_endo_scalar<curve_type, 128>(0));
	test_endo_scalar<curve_type>({0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_cppui255},
        calculate_endo_scalar<curve_type, 128>(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_cppui255));

    nil::crypto3::random::algebraic_engine<curve_type::scalar_field_type> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    for (std::size_t i = 0; i < random_tests_amount; i++){
        typename curve_type::scalar_field_type::value_type input = generate_random();
    	typename curve_type::scalar_field_type::integral_type input_integral = typename curve_type::scalar_field_type::integral_type(input.data);
        input_integral = input_integral & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_cppui255;
    	typename curve_type::scalar_field_type::value_type input_scalar =  input_integral;
        test_endo_scalar<curve_type>({input_scalar}, calculate_endo_scalar<curve_type, 128>(input_scalar));
	}
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_endo_scalar_pallas) {
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::scalar_field_type;

    typename BlueprintFieldType::value_type challenge = 0x00000000000000000000000000000000FC93536CAE0C612C18FBE5F6D8E8EEF2_cppui255;

	test_endo_scalar<curve_type>({challenge}, calculate_endo_scalar<curve_type, 128>(challenge));
	test_endo_scalar<curve_type>({1}, calculate_endo_scalar<curve_type, 128>(1));
	test_endo_scalar<curve_type>({0}, calculate_endo_scalar<curve_type, 128>(0));
	test_endo_scalar<curve_type>({0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_cppui255},
        calculate_endo_scalar<curve_type, 128>(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_cppui255));

    nil::crypto3::random::algebraic_engine<curve_type::scalar_field_type> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    for (std::size_t i = 0; i < random_tests_amount; i++){
        typename curve_type::scalar_field_type::value_type input = generate_random();
    	typename curve_type::scalar_field_type::integral_type input_integral = typename curve_type::scalar_field_type::integral_type(input.data);
        input_integral = input_integral & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_cppui255;
    	typename curve_type::scalar_field_type::value_type input_scalar =  input_integral;
        test_endo_scalar<curve_type>({input_scalar}, calculate_endo_scalar<curve_type, 128>(input_scalar));
	}
}

BOOST_AUTO_TEST_SUITE_END()