//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_non_native_scalar_range_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/scalar_non_native_range.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template<typename BlueprintFieldType>
void test_scalar_non_native_range(std::vector<typename BlueprintFieldType::value_type> public_input,
                                  const bool expected_to_pass) {

    using ed25519_type = crypto3::algebra::curves::ed25519;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 2;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::scalar_non_native_range<ArithmetizationType, ed25519_type>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    auto result_check = [public_input](AssignmentType &assignment, typename component_type::result_type &real_res) {
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << std::hex
                  << "________________________________________________________________________________________\ninput: "
                  << public_input[0].data << std::endl;
#endif
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {}, {});

    if (expected_to_pass) {
        crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
    } else {
        crypto3::test_component_to_fail<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_non_native_scalar_range_test0) {
    test_scalar_non_native_range<typename crypto3::algebra::curves::pallas::base_field_type>({45524}, true);
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_scalar_range_test1) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

    typename field_type::integral_type ed25519_scalar_modulus =
        0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed_cppui255;
    typename field_type::value_type ones = 0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_cppui255;

    test_scalar_non_native_range<field_type>({typename field_type::value_type(ed25519_scalar_modulus - 1)}, true);

    test_scalar_non_native_range<field_type>({typename field_type::value_type(ones)}, true);

    test_scalar_non_native_range<field_type>({1}, true);

    test_scalar_non_native_range<field_type>({0}, true);

    nil::crypto3::random::algebraic_engine<field_type> rand;
    boost::random::mt19937 seed_seq;
    rand.seed(seed_seq);

    typename field_type::value_type r;
    typename field_type::integral_type r_integral;

    for (std::size_t i = 0; i < random_tests_amount; i++) {
        r = rand();
        r_integral = typename field_type::integral_type(r.data);
        r_integral = r_integral % ed25519_scalar_modulus;
        r = typename field_type::value_type(r_integral);
        test_scalar_non_native_range<field_type>({r}, true);
    }
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_scalar_range_test_must_fail) {
    using field_type = crypto3::algebra::curves::pallas::base_field_type;

    nil::crypto3::random::algebraic_engine<field_type> rand;
    boost::random::mt19937 seed_seq;
    rand.seed(seed_seq);

    typename field_type::integral_type ed25519_scalar_modulus =
        0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed_cppui255;
    typename field_type::integral_type zero = 0;
    typename field_type::integral_type ed25519_scalar_overage = zero - ed25519_scalar_modulus - 1;

    typename field_type::integral_type overage;

    for (std::size_t i = 0; i < random_tests_amount; i++) {
        overage = (typename field_type::integral_type(rand().data)) % ed25519_scalar_overage;
        test_scalar_non_native_range<field_type>(
            {typename field_type::value_type(ed25519_scalar_modulus + overage)}, false);    // false positive
    }
    test_scalar_non_native_range<field_type>({-1}, false);
}

BOOST_AUTO_TEST_SUITE_END()