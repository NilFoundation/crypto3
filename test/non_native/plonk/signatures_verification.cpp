//---------------------------------------------------------------------------//
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

#define BOOST_TEST_MODULE blueprint_plonk_signatures_verification_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/signatures_verification.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/ed25519.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_signatures_verification) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using ed25519_type = algebra::curves::ed25519;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 11;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;
    constexpr const std::size_t k = 1;
    using component_type = zk::components::signatures_verification<ArithmetizationType, curve_type, ed25519_type, k, 0, 1, 2, 3,
                                                                          4, 5, 6, 7, 8>;
    using ed25519_component = zk::components::eddsa25519<ArithmetizationType, curve_type, ed25519_type,
                    0, 1, 2, 3, 4, 5, 6, 7, 8>; 
    using var_ec_point = typename ed25519_component::params_type::var_ec_point;
    using signature = typename ed25519_component::params_type::signature;

    ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type B =
    ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type::one();
    auto M = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui256;
    
    std::vector<typename BlueprintFieldType::value_type> public_input;
    typename ed25519_type::base_field_type::integral_type base = 1;
    typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;
    std::array<signature, k> Signatures;
    std::array<var_ec_point, k> Public_keys;
    for(std::size_t i = 0; i < k; i++) {
        ed25519_type::scalar_field_type::value_type r = algebra::random_element<ed25519_type::scalar_field_type>();
        ed25519_type::scalar_field_type::value_type c = algebra::random_element<ed25519_type::scalar_field_type>();
        ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type R = r*B;
        ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type P = c*B;
        ed25519_type::scalar_field_type::value_type s = r + c;
        ed25519_type::base_field_type::integral_type Rx = ed25519_type::base_field_type::integral_type(R.X.data);
        ed25519_type::base_field_type::integral_type Ry = ed25519_type::base_field_type::integral_type(R.Y.data);
        ed25519_type::base_field_type::integral_type Px = ed25519_type::base_field_type::integral_type(P.X.data);
        ed25519_type::base_field_type::integral_type Py = ed25519_type::base_field_type::integral_type(P.Y.data);
        public_input.insert(public_input.end(), {Rx & mask, (Rx >> 66) & mask, (Rx >> 132) & mask, (Rx >> 198) & mask,
        Ry & mask, (Ry >> 66) & mask, (Ry >> 132) & mask, (Ry >> 198) & mask, typename BlueprintFieldType::integral_type(s.data), 
        Px & mask, (Px >> 66) & mask, (Px >> 132) & mask, (Px >> 198) & mask,
        Py & mask, (Py >> 66) & mask, (Py >> 132) & mask, (Py >> 198) & mask});
        std::array<var, 4> e_R_x = {var(0, i*17 + 0, false, var::column_type::public_input), var(0, i*17 + 1, false, var::column_type::public_input),
        var(0, i*17 + 2, false, var::column_type::public_input), var(0, i*17 + 3, false, var::column_type::public_input)};
        std::array<var, 4> e_R_y = {var(0, i*17 + 4, false, var::column_type::public_input), var(0, i*17 + 5, false, var::column_type::public_input),
            var(0, i*17 + 6, false, var::column_type::public_input), var(0, i*17 + 7, false, var::column_type::public_input)};
        var_ec_point R_i = {e_R_x, e_R_y};
        var e_s = var(0, i*17 + 8, false, var::column_type::public_input);
        Signatures[i] = {R_i, e_s};
        std::array<var, 4> pk_x = {var(0, i*17 + 9, false, var::column_type::public_input), var(0, i*17 + 10, false, var::column_type::public_input),
            var(0, i*17 + 11, false, var::column_type::public_input), var(0, i*17 + 12, false, var::column_type::public_input)};
        std::array<var, 4> pk_y = {var(0, i*17 + 13, false, var::column_type::public_input), var(0, i*17 + 14, false, var::column_type::public_input),
            var(0, i*17 + 15, false, var::column_type::public_input), var(0, i*17 + 16, false, var::column_type::public_input)};
        Public_keys[i] = {pk_x, pk_y};
    }
    public_input.insert(public_input.end(), {M & mask, (M >> 66) & mask, (M >> 132) & mask, (M >> 198) & mask});

    std::array<var, 4> M_var = {var(0, k*17, false, var::column_type::public_input), var(0, k*17 + 1, false, var::column_type::public_input),
        var(0, k*17 + 2, false, var::column_type::public_input), var(0, k*17 + 3, false, var::column_type::public_input)};


    typename component_type::params_type params = {Signatures, Public_keys, M_var};
    
    auto result_check = [](AssignmentType &assignment, 
        component_type::result_type &real_res) {
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "Time_execution: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()