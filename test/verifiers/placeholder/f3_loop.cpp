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
#include <nil/blueprint/components/systems/snark/plonk/placeholder/detail/f3_loop.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template<typename BlueprintFieldType, std::uint32_t WitnessAmount>
void test(std::vector<typename BlueprintFieldType::value_type> &public_input,
          typename BlueprintFieldType::value_type &expected_res) {

    constexpr std::size_t WitnessColumns = WitnessAmount;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = WitnessAmount + 1;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::detail::f3_loop<ArithmetizationType>;

    std::size_t m = public_input.size() / 3;

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }
    component_type component_instance(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(), m);

    std::vector<std::vector<var>> gates;
    std::vector<var> selectors;
    std::size_t ctr = 0;
    std::vector<var> si, ti, alphai;
    for (int i = 0; i < m; i++) {
        alphai.push_back(var(0, ctr++, false, var::column_type::public_input));
    }
    for (int i = 0; i < m; i++) {
        si.push_back(var(0, ctr++, false, var::column_type::public_input));
    }
    for (int i = 0; i < m; i++) {
        ti.push_back(var(0, ctr++, false, var::column_type::public_input));
    }

    typename component_type::input_type instance_input = {alphai, si, ti};

    auto result_check = [expected_res](AssignmentType &assignment, typename component_type::result_type &real_res) {
        std::cout << "F: 0x" << std::hex << var_value(assignment, real_res.output).data << std::endl;
        assert(var_value(assignment, real_res.output) == expected_res);
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

BOOST_AUTO_TEST_CASE(blueprint_plonk_permutation_loop_test0) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        0x343841a32c928eb4e2ae534f59cc5cf1e25c53e307a5b81b75c131c73b6fc7a0_cppui255,
        0x69e9e35f0c0f9c2c99fa7d570a5c269a886544f6708a4d2bb1e6f227c44ac62_cppui255,
        0x3ed0f74ff54a53257fc6836fec09caef8293a302ea145f6aa536b1c1eea3ab46_cppui255,
        0x1acd7d04aa7b58b4eece036b22952608b6d36426fb7b6886580f0b94fba78027_cppui255,
        0xff593d0141cbe02fec2f5a6423c83388c61787ac53ba0bf30c7176b21e93004_cppui255,
        0x27a5ffbc960919dd52e5e701d1cbf1b34bca1178031bc6a669c4d569234397d7_cppui255,
        0x3e1bdecdd496459ee5a11c2665460a832d084d28c68f98eeb035f2549e994be4_cppui255,
        0x39786922cdb8e0f0e8338bd6796833d3c653e5ef7b22478a01b24f3c0ff43402_cppui255,
        0x29edab3fc33b0e6d6a75f53dac8612ac902a363340da6f1e5f0f91af80ff9e5e_cppui255};

    typename BlueprintFieldType::value_type expected_res =
        0x10f04580466164e2155d833e6489f63f259071438925993668473cf36d4e3826_cppui255;

    test<BlueprintFieldType, 4>(public_input, expected_res);
    test<BlueprintFieldType, 5>(public_input, expected_res);
    test<BlueprintFieldType, 6>(public_input, expected_res);
    test<BlueprintFieldType, 7>(public_input, expected_res);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_permutation_loop_test1) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        0x13d38859e00f79df76e547b36dee3c0d19c5a4c6b7bc33ae284ec653e2db0e66_cppui255,
        0x2d05f8356617f5060a8c5593d0bcbf5e15c74eb5fd681140b018139c0b453e48_cppui255,
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
        0x3147dc26cd071216a5cceb16291d35c68ce3e01505adff83b690bd3f82655ae3_cppui255};

    typename BlueprintFieldType::value_type expected_res =
        0x3627e4bec2ef12578906bbc3d1820ad3e351949cbff1a8cf4783e82caaa4a225_cppui255;

    test<BlueprintFieldType, 4>(public_input, expected_res);
    test<BlueprintFieldType, 5>(public_input, expected_res);
    test<BlueprintFieldType, 6>(public_input, expected_res);
    test<BlueprintFieldType, 7>(public_input, expected_res);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_permutation_loop_test2) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        0x3ac916e994eb085e73928ffcf7349bd78232597abe727e5419efca5da3352762_cppui255,
        0x28c5329493df6684237fe29b099bd63b8e308890d824cc22e1cae645ca74d16e_cppui255,
        0x20850cee63944d67e20b3a7bbb287445d56d896b21dfad679371f92d7c8cfdde_cppui255,
        0x733d8c425ee853f86e19b732693e23fb0b3455e4716461232558a95c507edc7_cppui255,
        0x10107a265a3e1c84a7bfba1098d21f8c454e7b924dbd1da5ac8b3aab636c6a0c_cppui255,
        0x350d9495311fef9a4b0209edb4a3c4bddd5ffb56ce2f191ef970ab9c0ed0ea89_cppui255,
        0x4f4a9468effe3b8b593752aa6ca4076d9548e7ad0db0dd4db34775c4806d44f_cppui255,
        0x3f3c910aa039f6a9c696978cffd810099023bac4778c6a25df3e7cc4882e249f_cppui255,
        0x362a6fe7cda76313effd4f422c2aa30517af2e8cf75cbd6cacd18592f8504465_cppui255,
        0x2a6d49e1c07f61f3356cde688fb9807c7efa8120c1357b768292038c29c33ca1_cppui255,
        0x2fc44c30d66a005631bab5e36186f6f2df3d82695bb41025d12706204a8e98fa_cppui255,
        0x34aa8f0b44149c23df98d0a7950f11945bcaf1588a589d8442fcf6a4551ff475_cppui255,
        0x384d6cead91ac3c0ae1a8acc9f4d753121afe02066774dd10a381ce3f30649f9_cppui255,
        0x181e07ef1cacc19be824f2d02109b1863ab1740bdc82e0e184b3246af28f8773_cppui255,
        0x17a9cdd5c4c1fe3143318316c5a9b18d879813ebda0c56f2b3ab5faaf8e530af_cppui255,
        0x1df2aafa1674d30190d7e9fc28bb72263c0e73ff16f4558736d45836e45de71a_cppui255,
        0x1c397b8d8e0b71e74a95b05b6769850aa0cff9c3d29bf0e48c7df205c571f7ab_cppui255,
        0x3fc816df5e71c581a52cdbbd4cee972b9b56cb08b5d838dfe317b93e0243e11a_cppui255};

    typename BlueprintFieldType::value_type expected_res =
        0x2cc334d4e4f1ba642074f6700758d854b5ae4862b5a9cb4b8f8e1fb814b767df_cppui255;

    test<BlueprintFieldType, 4>(public_input, expected_res);
    test<BlueprintFieldType, 5>(public_input, expected_res);
    test<BlueprintFieldType, 6>(public_input, expected_res);
    test<BlueprintFieldType, 7>(public_input, expected_res);
}

BOOST_AUTO_TEST_SUITE_END()
