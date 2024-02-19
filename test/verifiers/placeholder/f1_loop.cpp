//---------------------------------------------------------------------------//
// Copyright (c) 2023 Valeh Farzaliyev <estonia@nil.foundation>
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

#define BOOST_TEST_MODULE plonk_permutation_loop_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/detail/f1_loop.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template<typename BlueprintFieldType, std::uint32_t WitnessAmount>
void test(std::vector<typename BlueprintFieldType::value_type> &public_input,
          typename BlueprintFieldType::value_type &expected_res) {

    constexpr std::size_t WitnessColumns = WitnessAmount;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = WitnessAmount + (WitnessAmount - 1) / 3;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::detail::f1_loop<ArithmetizationType>;

    std::size_t m = (public_input.size() - 2) / 2;

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }
    component_type component_instance(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(), m);

    std::vector<std::vector<var>> gates;
    std::vector<var> selectors;
    std::size_t ctr = 0;
    var beta = var(0, ctr++, false, var::column_type::public_input);
    var gamma = var(0, ctr++, false, var::column_type::public_input);
    std::vector<var> si, ti;
    for (std::uint32_t i = 0; i < m; i++) {
        si.push_back(var(0, ctr++, false, var::column_type::public_input));
    }
    for (std::uint32_t i = 0; i < m; i++) {
        ti.push_back(var(0, ctr++, false, var::column_type::public_input));
    }

    typename component_type::input_type instance_input = {beta, gamma, si, ti};

    auto result_check = [expected_res](AssignmentType &assignment, typename component_type::result_type &real_res) {
        std::cout << "F: 0x" << std::hex << var_value(assignment, real_res.output).data << std::endl;
        assert(var_value(assignment, real_res.output) == expected_res);
    };

    crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance,
        desc,
        public_input,
        result_check,
        instance_input,
        nil::blueprint::connectedness_check_type::type::STRONG,
        m);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_permutation_loop_test0) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        0x343841a32c928eb4e2ae534f59cc5cf1e25c53e307a5b81b75c131c73b6fc7a0_cppui255,    // gamma
        0x69e9e35f0c0f9c2c99fa7d570a5c269a886544f6708a4d2bb1e6f227c44ac62_cppui255,     // beta
        0x3ed0f74ff54a53257fc6836fec09caef8293a302ea145f6aa536b1c1eea3ab46_cppui255,
        0x1acd7d04aa7b58b4eece036b22952608b6d36426fb7b6886580f0b94fba78027_cppui255,
        0xff593d0141cbe02fec2f5a6423c83388c61787ac53ba0bf30c7176b21e93004_cppui255,
        0x27a5ffbc960919dd52e5e701d1cbf1b34bca1178031bc6a669c4d569234397d7_cppui255,
        0x3e1bdecdd496459ee5a11c2665460a832d084d28c68f98eeb035f2549e994be4_cppui255,
        0x39786922cdb8e0f0e8338bd6796833d3c653e5ef7b22478a01b24f3c0ff43402_cppui255,
    };

    typename BlueprintFieldType::value_type expected_res =
        0x29edab3fc33b0e6d6a75f53dac8612ac902a363340da6f1e5f0f91af80ff9e5e_cppui255;

    test<BlueprintFieldType, 4>(public_input, expected_res);
    test<BlueprintFieldType, 5>(public_input, expected_res);
    test<BlueprintFieldType, 6>(public_input, expected_res);
    test<BlueprintFieldType, 7>(public_input, expected_res);
    test<BlueprintFieldType, 8>(public_input, expected_res);
    test<BlueprintFieldType, 9>(public_input, expected_res);
    test<BlueprintFieldType, 10>(public_input, expected_res);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_permutation_loop_test1) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        0x13d38859e00f79df76e547b36dee3c0d19c5a4c6b7bc33ae284ec653e2db0e66_cppui255,    // gamma
        0x2d05f8356617f5060a8c5593d0bcbf5e15c74eb5fd681140b018139c0b453e48_cppui255,    // beta
        0xf7436a0e17af4814bd5da359d8b3c3c01bd2dd85d67ba4eb66e73a6852f694b_cppui255,
        0x3fd11cbab87d551cc8b10411f1ee2abfbc68cc27e9fe275912670a794ebc6b06_cppui255,
        0x366217783833274a413583bb6fcfaa3de8dfee3c2885526255a28302bb93231_cppui255,
        0x3b5e28af60706486205ddb4f197e3b8923199c89e043392d36489b299a5ac600_cppui255,
        0xec45e2ee30419aa67682743019246bb630a2d35abcc64ef51295b1dabc9cc4f_cppui255,
        0x1a0f8fdb5e646f277cd13d360a1238a0bcfc13b2dc1acb89dc4cbe90a0e296b9_cppui255,
        0x3f479ebb49bb54c6e7bedf53b04ab68682de35c188ab61096fc433991c567186_cppui255,
        0x2ad86697004fb86c9ff21eefb5a5302ee93a5af6d66e9177039070e0d9008b08_cppui255,
        0x2fbb8c6fa08d8deff7dede25f772a7660e7f3d6214a9924ea6401086b218c21a_cppui255,
        0x2c7bcd2773ec55c8f5833ff46e1542c5390746e05185b379f19d00c5248adb56_cppui255,
        0xf4c65e93df2d11107677b1096c1177c0acb9a3b373cda815b5c5b739862abf2_cppui255,
        0xf163e52958ab4026cc78a067a636cd7c9c358354c747829e0706a77267fe32a_cppui255,
        0x3147dc26cd071216a5cceb16291d35c68ce3e01505adff83b690bd3f82655ae3_cppui255,
        0x39354121b4b606762eb088e4fed35a3aedd44feecfaebd6aecb0e508da13f0f3_cppui255};

    typename BlueprintFieldType::value_type expected_res =
        0x10fdfb2f515ec48c32c7b31b7e3039739bb22cd7bee475b5a74327ccd0dd0f6d_cppui255;

    test<BlueprintFieldType, 4>(public_input, expected_res);
    test<BlueprintFieldType, 5>(public_input, expected_res);
    test<BlueprintFieldType, 6>(public_input, expected_res);
    test<BlueprintFieldType, 7>(public_input, expected_res);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_permutation_loop_test2) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        /*beta: */
        0x181227226c1423739b9ac923321ed2f09ed6b194314f01fa63cf06a993087d47_cppui255,
        /*gamma: */
        0x2e42a7ce383a60b4a57ead1d59609e3c77d54efdbc3fb3b78df45906b61fa26c_cppui255,
        0x3d08d7113ec5ad138d4d720b44f3a8839a8541ee8f677bd6b688a821e34c2df6_cppui255,
        0x130b302c3079f281cef9b0082567fb0a5504ae46546dbe46a6a0c1a217148bd1_cppui255,
        0x1601b0e7bc9d588bfd28ebc94bc310654ab24669f26645d575cbfb1423cb0f90_cppui255,
        0x3cd9714e6b5440733518b80c64a3aaa050516c848b3a09c456d2c99112f396c3_cppui255,
        0x20e9e41aa6d693d979e31d4cd3426d1ba1138f59b18f3e354758343ba6e857d9_cppui255,
        0x3f48aa78bdb07bc9dea0e8b9c5050f653a3e883061fb3e7242975c11cfafa9bc_cppui255, 0x0_cppui255, 0x0_cppui255,
        0x0_cppui255, 0x18582466937834d434ceff70fa27ea4a1486d5c835080ebc13cb1f7b5bbd4850_cppui255,
        0x1979a1d3b8e9bfc29212140b1f38ea9120aa47febf6a0df823348102f783be15_cppui255,
        0x7d60e5c26d15b2aa293d72a00194e20e533fc3f38aa259ac899b4e82b0b3a3b_cppui255,
        0x3a3c06a35de362be982b6bd008c05efce84f297d4893cb61faee0e230e465502_cppui255,
        0x51a74265a7a5c53a24d9d461403d93aba9c5151e77a4da184dab3c417f687f6_cppui255,
        0xae1137ab4cd9d26666d9dbc0ee2f21a1f1692730311f89f97a5f825992e0f26_cppui255, 0x0_cppui255, 0x0_cppui255,
        0x0_cppui255};

    typename BlueprintFieldType::value_type expected_res =
        0x1fe0cedb4028c10c6fbb7984040bacd33a3644a3df6c157a7d253af03168ee8b_cppui255;

    test<BlueprintFieldType, 4>(public_input, expected_res);
    test<BlueprintFieldType, 5>(public_input, expected_res);
    test<BlueprintFieldType, 6>(public_input, expected_res);
    test<BlueprintFieldType, 7>(public_input, expected_res);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_permutation_loop_test3) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        /*beta: */
        0x815e5816cf879a118c629f6f724e75486494f53371ad59a031e8acf03199b88_cppui255,
        /*gamma: */
        0x257158c4ad84265ed8011284ea62f8d24834881034b1d1bf2bdf6dfd0d87aab6_cppui255,
        0x1b5ed497136f6e508532fd859a0cb4fdad54c84549a665d5d580943fa88bb5de_cppui255,
        0x45d83c89ccb02eceedf188623a5cc960fe523678bb70567bcfcada4a8f1d7aa_cppui255};

    typename BlueprintFieldType::value_type expected_res =
        0x3df91b519c56c1661226abe86c59cd26f3a63c2dbaac2cdeecb286d4735dcbf2_cppui255;

    test<BlueprintFieldType, 4>(public_input, expected_res);
    test<BlueprintFieldType, 5>(public_input, expected_res);
    test<BlueprintFieldType, 6>(public_input, expected_res);
    test<BlueprintFieldType, 7>(public_input, expected_res);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_permutation_loop_test4) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        /*beta: */
        0x815e5816cf879a118c629f6f724e75486494f53371ad59a031e8acf03199b88_cppui255,
        /*gamma: */
        0x257158c4ad84265ed8011284ea62f8d24834881034b1d1bf2bdf6dfd0d87aab6_cppui255,
        0x1b5ed497136f6e508532fd859a0cb4fdad54c84549a665d5d580943fa88bb5de_cppui255,
        0x45d83c89ccb02eceedf188623a5cc960fe523678bb70567bcfcada4a8f1d7aa_cppui255,
        0x1601b0e7bc9d588bfd28ebc94bc310654ab24669f26645d575cbfb1423cb0f90_cppui255,
        0x3cd9714e6b5440733518b80c64a3aaa050516c848b3a09c456d2c99112f396c3_cppui255};

    typename BlueprintFieldType::value_type expected_res =
        0x3368f12ac6c75aceaed6f7f2e9af9926674370ddb3d12c00c83c225cc6b88380_cppui255;

    test<BlueprintFieldType, 4>(public_input, expected_res);
    test<BlueprintFieldType, 5>(public_input, expected_res);
    test<BlueprintFieldType, 6>(public_input, expected_res);
    test<BlueprintFieldType, 7>(public_input, expected_res);
    test<BlueprintFieldType, 8>(public_input, expected_res);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_permutation_loop_test5) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        /*beta: */
        0x181227226c1423739b9ac923321ed2f09ed6b194314f01fa63cf06a993087d47_cppui255,
        /*gamma: */
        0x2e42a7ce383a60b4a57ead1d59609e3c77d54efdbc3fb3b78df45906b61fa26c_cppui255,
        0x29566d61a92beabbe4124f3c1140e1621e6dbf40685efcdd3654ebb4a120936f_cppui255,
        0x371ed596cbfbef3fb137c07f7387f0694fb9df229725ecbfa7275460091e5292_cppui255,
        0x5b880339bcbe06aad36ac71638d5d3e831f1dec5ca6f97a456f9936b6690c4c_cppui255,
        0x29566d61a92beabbe4124f3c1140e1621e6dbf40685efcdd3654ebb4a120936f_cppui255,
        0x371ed596cbfbef3fb137c07f7387f0694fb9df229725ecbfa7275460091e5292_cppui255,
        0x5b880339bcbe06aad36ac71638d5d3e831f1dec5ca6f97a456f9936b6690c4c_cppui255};

    typename BlueprintFieldType::value_type expected_res =
        0x37b68c62a05782ebfe610897109adc5e0c343a4468372c305e050b4a133860d5_cppui255;

    test<BlueprintFieldType, 4>(public_input, expected_res);
    test<BlueprintFieldType, 5>(public_input, expected_res);
    test<BlueprintFieldType, 6>(public_input, expected_res);
    test<BlueprintFieldType, 7>(public_input, expected_res);
    test<BlueprintFieldType, 8>(public_input, expected_res);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_permutation_loop_test6) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        /*beta: */
        0x181227226c1423739b9ac923321ed2f09ed6b194314f01fa63cf06a993087d47_cppui255,
        /*gamma: */
        0x2e42a7ce383a60b4a57ead1d59609e3c77d54efdbc3fb3b78df45906b61fa26c_cppui255,
        0x3a7580268e270952e70bf455392b34d33608d4291f37c778edf18a1df79b3d02_cppui255,
        0x12cc7a905f5ba0f349772eccf0a4f893255895eab99b4654971beb32c3d18e4c_cppui255,
        0x233de57bb49faf3747f8065836f6e150326ffbcec7f5ff84ab3ed517dff9f782_cppui255,
        0x46ac9a0a0a61d85811114d1b5a59055a1476d224220100ea28aef3ff5057b36_cppui255,
        0x19527a8b49c446bf75b243da6ac78d7c48e4b60c1071a4e5d369c3b46ab184d8_cppui255,
        0xbfdd514782dd17a99538aab6f7c447bb39607098ff684d907d05c4ee6b47364_cppui255,
        0x3cfd22f42d7f4bb00884f12035ac3b507bb19e482dd2e7787754e5cf67dd72a1_cppui255,
        0x1e0fb613aca0c659711bd4c889a691aa78953f8738d6005673123c2667c3cd50_cppui255,
        0x218014cf84950736b0d9c62ccb68ee90f755fc6dd0ed60a208d09da39e64bfd2_cppui255,
        0x237428f92e0be38a22c6220ea2cf7b010a2eae8670f062647bebcab8506fdddc_cppui255,
        0xc0af31fd4848be3dd24df1eb1681e13cb4de4395df9a3c1c8835270e4ae1699_cppui255,
        0x2708b8c59416e906abec12349b0aa4bd8e4e22dfc216b1a78f82daf83aa219df_cppui255};

    typename BlueprintFieldType::value_type expected_res =
        0x3a204699d97747058b03b75350f8969b7022230a7b6a46bb764050759b6a7363_cppui255;

    test<BlueprintFieldType, 4>(public_input, expected_res);
    test<BlueprintFieldType, 5>(public_input, expected_res);
    test<BlueprintFieldType, 6>(public_input, expected_res);
    test<BlueprintFieldType, 7>(public_input, expected_res);
    test<BlueprintFieldType, 8>(public_input, expected_res);
}

BOOST_AUTO_TEST_SUITE_END()
