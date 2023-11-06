//---------------------------------------------------------------------------//
// Copyright (c) 2023 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#define BOOST_TEST_MODULE plonk_permutation_argument_verifier_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/permutation_argument_verifier.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template<typename BlueprintFieldType>
void test(std::vector<typename BlueprintFieldType::value_type> &public_input,
          std::array<typename BlueprintFieldType::value_type, 3> &expected_res) {

    constexpr std::size_t WitnessColumns = 6;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 4;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::permutation_verifier<ArithmetizationType>;

    std::size_t m = (public_input.size() - 7) / 3;
    component_type component_instance({0, 1, 2, 3, 4, 5}, {}, {}, m);

    std::vector<var> f, Se, Ssigma;
    var L0, V, V_zeta, q_last, q_pad;
    std::array<var, 2> thetas;
    for (int i = 0; i < m; i++) {
        f.push_back(var(0, i, false, var::column_type::public_input));
    }
    for (int i = 0; i < m; i++) {
        Se.push_back(var(0, m + i, false, var::column_type::public_input));
    }
    for (int i = 0; i < m; i++) {
        Ssigma.push_back(var(0, 2 * m + i, false, var::column_type::public_input));
    }
    L0 = var(0, 3 * m, false, var::column_type::public_input);
    V = var(0, 3 * m + 1, false, var::column_type::public_input);
    V_zeta = var(0, 3 * m + 2, false, var::column_type::public_input);
    q_last = var(0, 3 * m + 3, false, var::column_type::public_input);
    q_pad = var(0, 3 * m + 4, false, var::column_type::public_input);
    thetas[0] = var(0, 3 * m + 5, false, var::column_type::public_input);
    thetas[1] = var(0, 3 * m + 6, false, var::column_type::public_input);
    typename component_type::input_type instance_input = {f, Se, Ssigma, L0, V, V_zeta, q_last, q_pad, thetas};

    auto result_check = [expected_res](AssignmentType &assignment, typename component_type::result_type &real_res) {
        for (std::size_t i = 0; i < 3; i++) {
            std::cout << "F_" << i << ": " << std::hex << var_value(assignment, real_res.output[i]).data << std::endl;
        }
        for (std::size_t i = 0; i < 3; i++) {
            assert(var_value(assignment, real_res.output[i]) == expected_res[i]);
        }
    };

    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance,
        public_input,
        result_check,
        instance_input,
        nil::crypto3::detail::connectedness_check_type::STRONG,
        m);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_permutation_argument_verifier_test0) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        /*.f = */ 0xad2bcf3656123a451e5ae737a10600efd60eb61a019329f54336e570a35ab9_cppui255,
        0x3a229abbe186e216f2c24d215d3a14ec65f213fda941f5d4ee6894ea0f20331e_cppui255,
        0x314564d4bb2dc124ebe6977105d2a16a70e5bc0a100095e28a9931be6a37770a_cppui255,
        0x20b742463ddb6422a9638a1e1e024b97f67786fded20e091254f2d6a0476f847_cppui255,
        /*.Se = */ 0xd76a2e28c1a0d640b40187154c48effa28452984730b0a7a0eb15e5ce281546_cppui255,
        0x3512e6cbc8242f438407a36a7d6cafe0a4f03fd5aa67a2a8b6a3c9006c86a5d_cppui255,
        0x1095e81fae8b4ec5194263114731f6f6338b13f2c54062d4b9132ed021ea13d1_cppui255,
        0x12ed889e68b889d97e4bef5663f9d2cedf70cac1d0f4f50c0432b923a9926314_cppui255,
        /*.Ssigma = */ 0xd76a2e28c1a0d640b40187154c48effa28452984730b0a7a0eb15e5ce281546_cppui255,
        0x740745f98a84b4a006f567611871547c31fc448c6a32fd0b31e2ae2cb614ef6_cppui255,
        0x2a966cffe76f3bf716c6f0abfb15f48472f34b3284e716a4c52108f4e1a9365b_cppui255,
        0x3c814ce925e32a65c269304816c7e0114dfe0cf6a234ca8140fd133f2c19cf2c_cppui255,
        /*.L0_y = */ 0x22e9429d6b3f5e7b775dab62879dbaf184cbd89c713ee99e165040d7052d550d_cppui255,
        /*.Vsigma_y = */ 0xb69213d83fd8da544645b1bcf69e827f5327ee15437632222676104ad1b08a3_cppui255,
        /*.Vsigma_zetay = */ 0x1d4e3ecd39d89a37045c909602e88968d376bc444b6c8976ff0d2d0d407a4ac5_cppui255,
        /*.q_last_y = */ 0x22e9429d6b3f5e7b775dab62879dbaf184cbd89c713ee99e165040d7052d550d_cppui255,
        /*.q_pad_y = */ 0xeae8e9652b38b988bfcd8e9ef1a418990021cd4fa6981461d0e1c50049b76f2_cppui255,
        /*.theta = {*/ 0xc51d84f8427d67ce47566fb043b6415f91196129cb6fd0ea3362f213a0e8cc8_cppui255,
        0x3301d234398523d96772d81b9b06b066888f67fcc3f1d0af919bbc7b856cf854_cppui255};

    std::array<typename BlueprintFieldType::value_type, 3> expected_res = {
        0x164cd4eb4883a25e30db9cf84de858ae429a9e8bc1cc6afa78610548c0455b69_cppui255,
        0x644e8375bddf7d18597aab619542335c0767f3398461c70b3ca1ad73c9a89c1_cppui255,
        0x34bbaf6e1e85fef1a66b63e96f343e34c02cbcfc8531d7f18dea0e1c9425ca24_cppui255,
    };

    test<BlueprintFieldType>(public_input, expected_res);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_permutation_argument_verifier_test1) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        /*.f = */ 0x15d6ac6a26ba0bf2d81357fc2009ca5c8df2ee41a3442fdb40f9ef7d31d2968f_cppui255,
        0x0_cppui255,
        0x15d6ac6a26ba0bf2d81357fc2009ca5c8df2ee41a3442fdb40f9ef7d31d2968f_cppui255,
        /*.Se = */ 0x3b96bf475105236e888b56379c4a37e56e694e4778d96480b2bff231b3448fd8_cppui255,
        0x29f1bc649519b128aab8af160d73177a9ef42375370b1215190af7448056cf34_cppui255,
        0x11b8adf6e98075cb559b6b6e433f7564b3f0e655f7506f16b1af418f81b20c01_cppui255,
        /*.Ssigma = */ 0x3b96bf475105236e888b56379c4a37e56e694e4778d96480b2bff231b3448fd8_cppui255,
        0x29f1bc649519b128aab8af160d73177a9ef42375370b1215190af7448056cf34_cppui255,
        0x11b8adf6e98075cb559b6b6e433f7564b3f0e655f7506f16b1af418f81b20c01_cppui255,
        /*.L0_y = */ 0x2a37d8915b58f641a50e3d4e43869c2987f7988f0ff7dac56a285ee684e53af3_cppui255,
        /*.Vsigma_y = */ 0x1_cppui255,
        /*.Vsigma_zetay = */ 0x1_cppui255,
        /*.q_last_y = */ 0x2a37d8915b58f641a50e3d4e43869c2987f7988f0ff7dac56a285ee684e53af3_cppui255,
        /*.q_pad_y = */ 0x362c09c9697f3d477eee786396c2e690cc2f73d44a5650e351b2b844dba3fb73_cppui255,
        /*.theta = {*/ 0xc51d84f8427d67ce47566fb043b6415f91196129cb6fd0ea3362f213a0e8cc8_cppui255,
        0x3301d234398523d96772d81b9b06b066888f67fcc3f1d0af919bbc7b856cf854_cppui255};

    std::array<typename BlueprintFieldType::value_type, 3> expected_res = {
        0x0_cppui255,
        0x0_cppui255,
        0x0_cppui255,
    };

    test<BlueprintFieldType>(public_input, expected_res);
}

BOOST_AUTO_TEST_SUITE_END()
