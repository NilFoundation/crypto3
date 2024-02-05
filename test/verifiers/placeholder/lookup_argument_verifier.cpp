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

#define BOOST_TEST_MODULE plonk_lookup_argument_verifier_test

#include <set>
#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/lookup_argument_verifier.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template<typename BlueprintFieldType, std::size_t WitnessAmount>
void test(std::vector<typename BlueprintFieldType::value_type> &public_input,
          std::array<typename BlueprintFieldType::value_type, 4> &expected_res, std::size_t num_gates,
          std::vector<std::size_t> gate_constraints_sizes, std::vector<size_t> gate_constraint_lookup_input_sizes,
          std::size_t num_tables, std::vector<size_t> lookup_table_lookup_options_sizes,
          std::vector<size_t> lookup_table_columns_number) {

    constexpr std::size_t WitnessColumns = WitnessAmount;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 10 * WitnessAmount;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using ArithmetizationParams = crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns,
                                                                                   ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::lookup_verifier<ArithmetizationType>;

    std::size_t num_constraints = std::accumulate(gate_constraints_sizes.begin(), gate_constraints_sizes.end(), 0);
    std::size_t num_lu_options = 0;
    for (std::size_t i = 0; i < num_tables; i++) {
        num_lu_options += lookup_table_lookup_options_sizes[i] * lookup_table_columns_number[i];
    }

    std::size_t num_lu_ops =
        std::accumulate(lookup_table_lookup_options_sizes.begin(), lookup_table_lookup_options_sizes.end(), 0);
    std::size_t num_lu_inputs =
        std::accumulate(gate_constraint_lookup_input_sizes.begin(), gate_constraint_lookup_input_sizes.end(), 0);

    std::size_t m = num_constraints + num_lu_ops;

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }
    component_type component_instance(witnesses, std::array<std::uint32_t, 1>(), std::array<std::uint32_t, 1>(),
                                      num_gates, gate_constraints_sizes, gate_constraint_lookup_input_sizes, num_tables,
                                      lookup_table_lookup_options_sizes, lookup_table_columns_number);

    std::size_t ctr = 0;
    var theta = var(0, ctr++, false, var::column_type::public_input);
    var beta = var(0, ctr++, false, var::column_type::public_input);
    var gamma = var(0, ctr++, false, var::column_type::public_input);
    std::vector<var> alphas;
    for (std::uint32_t i = 0; i < m - 1; i++) {
        alphas.push_back(var(0, ctr++, false, var::column_type::public_input));
    }

    std::array<var, 2> V_L_values;
    V_L_values[0] = var(0, ctr++, false, var::column_type::public_input);
    V_L_values[1] = var(0, ctr++, false, var::column_type::public_input);

    std::array<var, 2> q_last;
    q_last[0] = var(0, ctr++, false, var::column_type::public_input);
    q_last[1] = var(0, ctr++, false, var::column_type::public_input);

    std::array<var, 2> q_blind;
    q_blind[0] = var(0, ctr++, false, var::column_type::public_input);
    q_blind[1] = var(0, ctr++, false, var::column_type::public_input);

    var L0 = var(0, ctr++, false, var::column_type::public_input);

    std::vector<var> lookup_gate_selectors;
    for (std::uint32_t i = 0; i < num_gates; i++) {
        lookup_gate_selectors.push_back(var(0, ctr++, false, var::column_type::public_input));
    }

    std::vector<var> lookup_gate_constraints_table_ids;
    for (std::uint32_t i = 0; i < num_constraints; i++) {
        lookup_gate_constraints_table_ids.push_back(var(0, ctr++, false, var::column_type::public_input));
    }

    std::vector<var> lookup_gate_constraints_lookup_inputs;
    for (std::uint32_t i = 0; i < num_lu_inputs; i++) {
        lookup_gate_constraints_lookup_inputs.push_back(var(0, ctr++, false, var::column_type::public_input));
    }

    std::vector<var> lookup_table_selectors;
    for (std::uint32_t i = 0; i < num_tables; i++) {
        lookup_table_selectors.push_back(var(0, ctr++, false, var::column_type::public_input));
    }

    std::vector<var> lookup_table_lookup_options;
    for (std::uint32_t i = 0; i < num_lu_options; i++) {
        lookup_table_lookup_options.push_back(var(0, ctr++, false, var::column_type::public_input));
    }

    std::vector<var> shifted_lookup_table_selectors;
    for (std::uint32_t i = 0; i < num_tables; i++) {
        shifted_lookup_table_selectors.push_back(var(0, ctr++, false, var::column_type::public_input));
    }

    std::vector<var> shifted_lookup_table_lookup_options;
    for (std::uint32_t i = 0; i < num_lu_options; i++) {
        shifted_lookup_table_lookup_options.push_back(var(0, ctr++, false, var::column_type::public_input));
    }

    std::vector<var> sorted;
    for (std::uint32_t i = 0; i < 3 * m - 1; i++) {
        sorted.push_back(var(0, ctr++, false, var::column_type::public_input));
    }

    typename component_type::input_type instance_input = {theta,
                                                          beta,
                                                          gamma,
                                                          alphas,
                                                          V_L_values,
                                                          q_last,
                                                          q_blind,
                                                          L0,
                                                          lookup_gate_selectors,
                                                          lookup_gate_constraints_table_ids,
                                                          lookup_gate_constraints_lookup_inputs,
                                                          lookup_table_selectors,
                                                          lookup_table_lookup_options,
                                                          shifted_lookup_table_selectors,
                                                          shifted_lookup_table_lookup_options,
                                                          sorted};

    auto result_check = [expected_res](AssignmentType &assignment, typename component_type::result_type &real_res) {
        for (int i = 0; i < 4; i++) {
            std::cout << "F[" << i << "]: 0x" << std::hex << var_value(assignment, real_res.output[i]).data
                      << std::endl;
        }

        for (int i = 0; i < 4; i++) {
            assert(var_value(assignment, real_res.output[i]) == expected_res[i]);
        }

        // std::cout << "expected F: " << expected_res.data << std::endl;
    };

    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input,
        nil::crypto3::detail::connectedness_check_type::STRONG, num_gates, gate_constraints_sizes,
        gate_constraint_lookup_input_sizes, num_tables, lookup_table_lookup_options_sizes, lookup_table_columns_number);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_gate_argument_verifier_test) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::size_t lookup_gates_size = 3;
    std::size_t lookup_tables_size = 3;
    std::vector<std::size_t> gate_constraints_sizes = {1, 1, 1};
    std::vector<std::size_t> gate_constraint_lookup_input_sizes = {7, 2, 1};
    std::vector<std::size_t> lookup_table_lookup_options_sizes = {1, 2, 3};
    std::vector<std::size_t> lookup_table_columns_number = {7, 2, 1};

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        /*theta: */
        0x1f91750ec43107c824e1b79cb0e5b0ce2d5a99ee4d931726955dd619926b3ac8_cppui255,
        /*beta: */
        0x181227226c1423739b9ac923321ed2f09ed6b194314f01fa63cf06a993087d47_cppui255,
        /*gamma: */
        0x2e42a7ce383a60b4a57ead1d59609e3c77d54efdbc3fb3b78df45906b61fa26c_cppui255,
        /*alpha: */
        0x12c35108408002e011a77b1385fafa519b0c049dda69edeec76a5582aefdf679_cppui255,
        0x3c43857ea745aebffbf5b5a15c1f19f6c544fc6f4c058200e8c1fcfc94be97a2_cppui255,
        0xed5489c9d40c4d8a7214f245430ca28651cf789957e34a192e5a25bbe99a36f_cppui255,
        0x24a490b07a66d4d3c7889869f50b54b7d45e049c959d2c7b3908127cc0166736_cppui255,
        0x20082215dffd067489b93a647a77e2d063a0a020b1d1c833fac1d38127789a52_cppui255,
        0x2535b195a0c7d604ab78762b644abe5eb3ce5bb9bf637954b073753c08b913ed_cppui255,
        0xb4959a45c71c0be90a8a6df21b547679746452337f85337087f18498e96b39f_cppui255,
        0x1009604828f0b005c222820f19d2586ce28ff73d888558ea1bae36dc10923fe4_cppui255,
        /*V_L: */
        0x2f067360ee454281ed80c4bfd37b9e0140071ed383651858abb37d0d868238a2_cppui255,
        0xd079c9f0f66462d4dcf74077bcf5d4e1fb62214198a22d789637d6651d840de_cppui255,
        /*q_last_0: */
        0x2fe713a78f776121b2d68cfe5d35db3f34ca42b4973228a520617b5d92e8e449_cppui255,
        0x36041a6ee4c9d83ca3b8f282a8212e5ecd3a1304f01aeb6fc81dd055c30a115d_cppui255,
        /*q_blind_0: */
        0x143ef00c6cd28361b04c9c9e3782c1cb5e4543f1faea52c9b22a93803bed7f9d_cppui255,
        0x2fe713a78f776121b2d68cfe5d35db3f34ca42b4973228a520617b5d92e8e449_cppui255,
        /*L_0: */
        0x3c8519a916c0ddd81a0992eeb1fc91bc33674d02900ba9977478c89af7e5fd37_cppui255,
        /*gate selectors: */
        0x31269dc016cbeeb0720063dcd5494f9eb9348c5dd1d03c98a7ea90340c6cf4e3_cppui255,
        0x3bd9fc4c03b61b7c9cdcd6636b4762f5b17dab51807d76c85fce52fc31299c1d_cppui255,
        0x3f54e2a2ecf53da482d34374b94ad139a05cf74af9bec64c8482bb4e39439ee7_cppui255,
        /*table_ids: */
        1, 2, 3,
        /*lookup gate constraint lookup inputs: */
        0x124971c6cce767192245d6688a4af4482b1c5e935bbdec7825da26763c93e6fc_cppui255,
        0x3a57f30b24c9aec7984dd8bed4f52cf9497665344886c51d9bb9821309c4623b_cppui255,
        0x3ebc055241d36e5d1c8afb9ef7466f8e5d01ac3d16ce2c707d78a92820e61a1c_cppui255,
        0x32da319a20e51a7808c32e35c73434b5f72e0f5031e8c10cdce4b218fc87781a_cppui255,
        0x186be39596fdb9314fbb1f081dcd7056eefe8beec42a1cf745a42863028325c2_cppui255,
        0x9ea111bf6543ac23f0cb51d9ec6a57265709bf3d294df922d7b6841348c255c_cppui255,
        0x2d93a78ddc155e05f452fbf35778c89283dc93503bed266bda527150a440a17b_cppui255,
        0x32da319a20e51a7808c32e35c73434b5f72e0f5031e8c10cdce4b218fc87781a_cppui255,
        0x10e3d915ddd49ca40f1011a754ef3e1e3fa146fed50413be1d8b0c2c9b1a6484_cppui255,
        0x2fddfd79e3de586bd5a03b21b6592cae2ef255e993a07c77dd51d26a6afbfaa8_cppui255,
        /*lookup tables selcetors: */
        0xcb0e17a777c9ade431b8751afd8057cdd15f74a6795dedd6c1f56bdcdfcff41_cppui255,
        0x32a401287578a2c63fb7bc230972cbbcc34700009228e76f186364906b469fa6_cppui255,
        0x32a401287578a2c63fb7bc230972cbbcc34700009228e76f186364906b469fa6_cppui255,
        /* lookup tables lookup option: */
        0x1b058d4ad7a64a076158339af0f28f31b92d727545c3d63fc2d682721d7849fc_cppui255,
        0x13c8cbb50c4a86600d432cc5340ef1bfa78bb5a35c9381e67b1fe23584a5c12_cppui255,
        0x3628c1c830ae70a28bf4129c6a01662df74ded3b0529e820fdc3ccf8377ee0e2_cppui255,
        0x1f36ae1c91b093f88ab05c97230c85bdd79c4d791ac2b0e8bf5c7889bb80aafd_cppui255,
        0x27b1ece6c803fcf6de3fd9aa5207378466f574a6e9b30e188b1158962fec34cf_cppui255,
        0x31acc41a65db47a663c27d691157e2f9dcf92de98d482f347c6fa0a78e67d988_cppui255,
        0x2f971ec81c0309f69e82434a3c6596a509f586fa36712e7fd965ab31ce83b8c2_cppui255,
        0x1b058d4ad7a64a076158339af0f28f31b92d727545c3d63fc2d682721d7849fc_cppui255,
        0x13c8cbb50c4a86600d432cc5340ef1bfa78bb5a35c9381e67b1fe23584a5c12_cppui255,
        0x3628c1c830ae70a28bf4129c6a01662df74ded3b0529e820fdc3ccf8377ee0e2_cppui255,
        0x1f36ae1c91b093f88ab05c97230c85bdd79c4d791ac2b0e8bf5c7889bb80aafd_cppui255,
        0x27b1ece6c803fcf6de3fd9aa5207378466f574a6e9b30e188b1158962fec34cf_cppui255,
        0x31acc41a65db47a663c27d691157e2f9dcf92de98d482f347c6fa0a78e67d988_cppui255,
        0x2f971ec81c0309f69e82434a3c6596a509f586fa36712e7fd965ab31ce83b8c2_cppui255,
        /*lookup tables shifted selcetors: */
        0xb9481d2c72ffdac988d67079b8eeb9a17a0883db91507b650af1fb2992cdd7d_cppui255,
        0x3a41600a57bc459360967cd9279748fceee9a90ae09a7cbde02e93e0d4f2ad44_cppui255,
        0x3a41600a57bc459360967cd9279748fceee9a90ae09a7cbde02e93e0d4f2ad44_cppui255,
        /* lookup tables shifted lookup option: */
        0x1db8ba9b27956295bdf26c4b9502d384ce2447fa7d596fc62263314822fec898_cppui255,
        0x342b0f9fb517871584711bfbefe1ffa3e79d7bdf47980a15f6954402d5e7d8a2_cppui255,
        0x1ed54bb4ec015e30fe0bef1cfc7e702391b1d73dc45f4289b67b04acd2dcf2e9_cppui255,
        0x139c294a0d36efa023e4a91d157774ce8e78f8da9172c90915184b683eaa93d2_cppui255,
        0x4e7594148540be9d7608b428fc578288bb480844be045c03bf67bb63a6425df_cppui255,
        0x14d6b4ef9917aa59be762b845f2befa11a438bc9b52548b1e1a50649c0f3be7a_cppui255,
        0x6042e08d361d89c0d0344212ae9043ba052d5708398387d0e911392a2f3d340_cppui255,
        0x1db8ba9b27956295bdf26c4b9502d384ce2447fa7d596fc62263314822fec898_cppui255,
        0x342b0f9fb517871584711bfbefe1ffa3e79d7bdf47980a15f6954402d5e7d8a2_cppui255,
        0x1ed54bb4ec015e30fe0bef1cfc7e702391b1d73dc45f4289b67b04acd2dcf2e9_cppui255,
        0x139c294a0d36efa023e4a91d157774ce8e78f8da9172c90915184b683eaa93d2_cppui255,
        0x4e7594148540be9d7608b428fc578288bb480844be045c03bf67bb63a6425df_cppui255,
        0x14d6b4ef9917aa59be762b845f2befa11a438bc9b52548b1e1a50649c0f3be7a_cppui255,
        0x6042e08d361d89c0d0344212ae9043ba052d5708398387d0e911392a2f3d340_cppui255,
        /* sorted :*/
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
        0x0_cppui255, 0x2187d355d7ebd8be30402d16877e181cca486f51fad291095b33096277e13e_cppui255,
        0x1ef8272e914c2ccd659341031794f603a21dcf3ac35d2e0a9c26bf8881c1ea18_cppui255,
        0x36954d713e9209b0975b87b6b3d51d89ddf76338178177a0b5a503dad5bebd9c_cppui255,
        0x169244a31230525091fa126d82a977e8a7c65705d7aacf73cc28732ed1447f71_cppui255,
        0x28395c6c442a250e83922de639e4296d8925f96f2f0ac1fcd6c129391c76b423_cppui255,
        0x189d2fbb6f71ef06571eeed614cbd374257fb5205ca63b28a5414d3997c1ae4e_cppui255, 0x0_cppui255, 0x0_cppui255};

    std::array<typename BlueprintFieldType::value_type, 4> expected_res = {
        0x3fb663ded7ac8eb4b399cf60ec20e4a5e51e1d2fe3fc28759f012f13fac238a7_cppui255,
        0x5f511600d82c0f86b86133984c868d32994819f499e0403b5eb708129de72ae_cppui255,
        0x19278da4bf5d19e98a445ebadc0910733d4ad48527b3417af89b9571a7b886c4_cppui255,
        0x20faeea92ea55a96f57dea87d5ce112778185cb59ef6a1252242d571d1a3f3aa_cppui255};    // F

    test<BlueprintFieldType, 4>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 5>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 6>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 7>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_gate_argument_verifier_test1) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::size_t lookup_gates_size = 2;
    std::size_t lookup_tables_size = 2;
    std::vector<std::size_t> gate_constraints_sizes = {2, 1};
    std::vector<std::size_t> gate_constraint_lookup_input_sizes = {1, 1, 1};
    std::vector<std::size_t> lookup_table_lookup_options_sizes = {1, 3};
    std::vector<std::size_t> lookup_table_columns_number = {1, 1};

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        /*theta: */
        0x1bfbff1c2f23e10837c97d97f72c907607f1bcfd3b4700ee2b6781dfc732fbca_cppui255,
        /*beta: */
        0x314d7748efea79faaa93c1b943ce278d30e412a8a293df7f21674ac0da207ddf_cppui255,
        /*gamma: */
        0xc4b0a8e57586aeb49fa3282f7d4584da1b8c127ae316a599a37654c83577aac_cppui255,
        /*alpha: */
        0x3ac916e994eb085e73928ffcf7349bd78232597abe727e5419efca5da3352762_cppui255,
        0x28c5329493df6684237fe29b099bd63b8e308890d824cc22e1cae645ca74d16e_cppui255,
        0x20850cee63944d67e20b3a7bbb287445d56d896b21dfad679371f92d7c8cfdde_cppui255,
        0x733d8c425ee853f86e19b732693e23fb0b3455e4716461232558a95c507edc7_cppui255,
        0x10107a265a3e1c84a7bfba1098d21f8c454e7b924dbd1da5ac8b3aab636c6a0c_cppui255,
        0x350d9495311fef9a4b0209edb4a3c4bddd5ffb56ce2f191ef970ab9c0ed0ea89_cppui255,
        /*V_L: */
        0x2f9124776b548d7c11e42c640a80bac1629a259098c027712ac5c8d03861f9a1_cppui255,
        0x26e20a54731d9020cd3a49f4f93647a9fc6c4220c04c12252381b38822bde8ff_cppui255,
        /*q_last_0: */
        0x3e4be0f60a0892de53ce64e30dbeeb2ad97a4a9f48f8d0de90179dff9b655ee_cppui255,
        0x55b0e97fa86bdb951a6f982ebb8e625911af5d675ae321772de8859ef16759_cppui255,
        /*q_blind_0: */
        0x15cb10dc31dd9dd99205932dc89d5f4cc9d516dd93c82c005e49eb276a565fc3_cppui255,
        0x3e4be0f60a0892de53ce64e30dbeeb2ad97a4a9f48f8d0de90179dff9b655ee_cppui255,
        /*L_0: */
        0x3e480b88f7e13e682fbd0e71b75ae9b7e779f1e5513868152c6cacece130159_cppui255,
        /*gate selectors: */
        0x265031146d81d8f888bd86840686b200aad9dd7480f5400d51e1cbe59bf34a51_cppui255,
        0x226bb05bde03c51205c1b59ceb1103652c623e562be1b98bff1b0116cde048f8_cppui255,
        /*table_ids: */
        1, 2, 2,
        /*lookup gate constraint lookup inputs: */
        0x38cf0677a1def0c0aebaa6d9df9a338e213824e22eaae2279d8e824189bcc666_cppui255,
        0x1bc6cc84db93e32cdcb39fcf0b737ce973ec99e2139941a1eaf10e1f4358f9bb_cppui255,
        0x277581609fba694550ec7d87c8d3c92fdaf392f7303ff5e4d26ad9e187c2a4af_cppui255,
        /*lookup tables selcetors: */
        0x226bb05bde03c51205c1b59ceb1103652c623e562be1b98bff1b0116cde048f8_cppui255,
        0x226bb05bde03c51205c1b59ceb1103652c623e562be1b98bff1b0116cde048f8_cppui255,
        /* lookup tables lookup option: */
        0x13b142d74d5d6ce3355ef3c65e9809d91eb69e0ad2deea4197761e3e3361dc16_cppui255,
        0x13b142d74d5d6ce3355ef3c65e9809d91eb69e0ad2deea4197761e3e3361dc16_cppui255,
        0x3fcbb4a2a370463d52277fd6f5ed1ad2b814a3c19bad97c660a2c1d638c348ec_cppui255,
        0x1d0c444e682d3cd84514835b04cc28bd46f35621d6c6dbea5e34e783a6836b9a_cppui255,
        /*lookup tables shifted selcetors: */
        0x25fa802aedd96d1cf3a316ebd7cb239e51c82e17199a5cebdab3e35ffd01e2f8_cppui255,
        0x25fa802aedd96d1cf3a316ebd7cb239e51c82e17199a5cebdab3e35ffd01e2f8_cppui255,
        /* lookup tables shifted lookup option: */
        0x3b8e1e41ccc266c12d5f3e08397385c4d88c4f0fd56b7ae5f9dd594b44ce5451_cppui255,
        0x3b8e1e41ccc266c12d5f3e08397385c4d88c4f0fd56b7ae5f9dd594b44ce5451_cppui255,
        0x39729f1872018851ef8eb0a3706b37dc0aa16a8f3988602e73d9376435d7c326_cppui255,
        0x7be020326311d5b6ba5130e1d85ab6ae573fa30f2218b4d10325204dc16a399_cppui255,
        /* sorted :*/
        0x144cf6b94befcde04ca399aa28f7c19b9c7abe4516b149d51c979578c26132aa_cppui255,
        0x4f4a9468effe3b8b593752aa6ca4076d9548e7ad0db0dd4db34775c4806d44f_cppui255,
        0x3f3c910aa039f6a9c696978cffd810099023bac4778c6a25df3e7cc4882e249f_cppui255,
        0x362a6fe7cda76313effd4f422c2aa30517af2e8cf75cbd6cacd18592f8504465_cppui255,
        0x2a6d49e1c07f61f3356cde688fb9807c7efa8120c1357b768292038c29c33ca1_cppui255,
        0x2fc44c30d66a005631bab5e36186f6f2df3d82695bb41025d12706204a8e98fa_cppui255,
        0x34aa8f0b44149c23df98d0a7950f11945bcaf1588a589d8442fcf6a4551ff475_cppui255,
        0x2be0a5cb81a428769c7a00a5c286d190daa41649ce8cc80dd48da8ddb6541ff4_cppui255,
        0x37822189c5f080b02ce93fd126be0cd976149faf2c698a05f8e67716c95fff2c_cppui255,
        0x3c107fd152981cf471acbcec2bc52731776ee7572a0358668751955be7ebe5e3_cppui255,
        0x20a347ef86111d08804823c1e81f6c7bffa4c768533e19f86bbd4dacb9539fb5_cppui255,
        0x22e3fb00764626ac8e7f5765869236b03c60e073c00bfd01e63a662ab7a66199_cppui255,
        0x3f4bda0c68abd98d7b543381553ac4523dc3510eb347a1072a08246a7a454491_cppui255,
        0x44ac8e5824fe8aa17842a4a4fe23aadcbbc09f07b02c60df78e22fcb4bcec46_cppui255,
        0x384d6cead91ac3c0ae1a8acc9f4d753121afe02066774dd10a381ce3f30649f9_cppui255,
        0x181e07ef1cacc19be824f2d02109b1863ab1740bdc82e0e184b3246af28f8773_cppui255,
        0x17a9cdd5c4c1fe3143318316c5a9b18d879813ebda0c56f2b3ab5faaf8e530af_cppui255,
        0x1df2aafa1674d30190d7e9fc28bb72263c0e73ff16f4558736d45836e45de71a_cppui255,
        0x1c397b8d8e0b71e74a95b05b6769850aa0cff9c3d29bf0e48c7df205c571f7ab_cppui255,
        0x3fc816df5e71c581a52cdbbd4cee972b9b56cb08b5d838dfe317b93e0243e11a_cppui255};

    std::array<typename BlueprintFieldType::value_type, 4> expected_res = {
        0x35e69c5ddd12ba21112c825dbece7df98c7e250b0c4e4517a8aa79f0925499b0_cppui255,
        0x246009173489a2c898257f798838fbbf15099b5e311b765e0114cbb017472baa_cppui255,
        0x1f4800182b9b832ceaca69367a60809745976e7793157079f305358ecc0d1034_cppui255,
        0x3784c3bbe15ea3db50780f6d73698cd40e98f82aafdc6dfd62f7d3f29aa4f1ff_cppui255};    // F

    test<BlueprintFieldType, 4>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 5>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 6>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 7>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_gate_argument_verifier_test2) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::size_t lookup_gates_size = 1;
    std::size_t lookup_tables_size = 1;
    std::vector<std::size_t> gate_constraints_sizes = {1};
    std::vector<std::size_t> gate_constraint_lookup_input_sizes = {3};
    std::vector<std::size_t> lookup_table_lookup_options_sizes = {1};
    std::vector<std::size_t> lookup_table_columns_number = {3};

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        /*theta: */
        0x1d7f68089e58314bd0fd09de62903aa5ec3268b574f97bf7cad8e1af15952f05_cppui255,
        /*beta: */
        0x815e5816cf879a118c629f6f724e75486494f53371ad59a031e8acf03199b88_cppui255,
        /*gamma: */
        0x257158c4ad84265ed8011284ea62f8d24834881034b1d1bf2bdf6dfd0d87aab6_cppui255,
        /*alpha: */
        0xc5f37c144b3d9a3727c15cb2860927aa1852b09741fa40473fc9eb1787dc89e_cppui255,
        /*V_L: */
        0x3d71d8822355d24ec28a4689490af52a0edec77b1a1e1a336b00136ca5b2aa55_cppui255,
        0x39bfbccba576b46aadd07a1269e2167a8af30ee2f5b63d18da633976f8d39b90_cppui255,
        /*q_last_0: */
        0x289716269efe8d211ed1c4b73cf3a1a8a92c4f35b60c88610e2a2274a9462e4d_cppui255,
        0x3938ee6f665648111b1fb38692685fc58d13dd96eb282fa132df606fc13c24ff_cppui255,
        /*q_blind_0: */
        0x2ce4873d86986fd9fd9f80e3d17f77086d77fa3600ffcc14a5b151735026659_cppui255,
        0x1d9d793626a197fb1ca1b02a9283241f3de2f6291d8e3009ef5c5a2f90ccb87b_cppui255,
        /*L_0: */
        0x3c64fd8ec24abf24f8ff563202680a359bc5d73caac1096da418e429324017db_cppui255,
        /*gate selectors: */
        0x3c64fd8ec24abf24f8ff563202680a359bc5d73caac1096da418e429324017db_cppui255,
        /*table_ids: */
        1,
        /*lookup gate constraint lookup inputs: */
        0x3c64fd8ec24abf24f8ff563202680a359bc5d73caac1096da418e429324017db_cppui255, 0x0_cppui255, 0x0_cppui255,
        /*lookup tables selcetors: */
        0x1835a3d6c64d2cbc4854ed08838c5cb178c38be251bc63a735bc4624ef775382_cppui255,
        /* lookup tables lookup option: */
        0x3d3c325d1c415801ca4b9f57fe82a5e5ee1dd4f0cd544d2bac86cf6507d1411b_cppui255,
        0x1af97179aa0bd4ba7e094db08509b6cbacec4fed8db50f972262a7ace7a61268_cppui255,
        0x40343edb5eb0ff0af2bebd16c1a46206109f759e22c1d8a79a76ef546951c1c_cppui255,
        /*lookup tables shifted selcetors: */
        0x1b61b2f62241a3d026348fb3f38c07218775858811553d73a6f5c9de607b465e_cppui255,
        /* lookup tables shifted lookup option: */
        0x175e6f086c5693df7708a3e28771c101266b8e2e2f291fe92d4e5ae919e62a42_cppui255,
        0x40343edb5eb0ff0af2bebd16c1a46206109f759e22c1d8a79a76ef546951c1c_cppui255,
        0x3c64fd8ec24abf24f8ff563202680a359bc5d73caac1096da418e429324017db_cppui255,
        /* sorted :*/
        0xaae87d4c1a9c5f67fd8d128e52c19df71cae8ae988616ccdf64469b1f622167_cppui255,
        0x88ac88639b105ff6b4c74b858b9a6956b54ec13dc00aa5db193d934078a6744_cppui255,
        0x22cf6baa70e28b08de79a41bffe3ba33dff26ef9269dee9488688f53652a3f6c_cppui255,
        0x3ad0b47143a7797996a7583b7b976d1d65dd0dfb82c24e3095d5ad597451ebd8_cppui255,
        0x2882c884e7588cb74da62fb359b02d5143f2eff9d3e475112caee5f237f5265c_cppui255};

    std::array<typename BlueprintFieldType::value_type, 4> expected_res = {
        0x1d38affafcaea87529bfbd1eecfb8bdfec63c8477ef34d81ed7524a4b3dfd0ee_cppui255,
        0x1517c78abe81de6b6ab6cea789d87b139ae198de67059be4da160d4eef47a120_cppui255,
        0x1c6d84769c65a19b6291825efc7e31c970629504b4c88816a90e7d339ebe2252_cppui255,
        0x3c74bf9104f97f4019d75b317c1df2629f1f421002b7abc02344d53707b21de2_cppui255};    // F

    test<BlueprintFieldType, 4>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 5>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 6>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 7>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_gate_argument_verifier_test3) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::size_t lookup_gates_size = 1;
    std::size_t lookup_tables_size = 1;
    std::vector<std::size_t> gate_constraints_sizes = {1};
    std::vector<std::size_t> gate_constraint_lookup_input_sizes = {3};
    std::vector<std::size_t> lookup_table_lookup_options_sizes = {1};
    std::vector<std::size_t> lookup_table_columns_number = {3};

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        /*theta: */
        0xc51d84f8427d67ce47566fb043b6415f91196129cb6fd0ea3362f213a0e8cc8_cppui255,
        /*beta: */
        0x234beb2f67e10c0b52a8162be56be6d0b441bfb15b18ea41167ff3eb6f07160e_cppui255,
        /*gamma: */
        0x1855e317848ad8aa18904176c2af32d853dfc7698d97dc19b608992e6bdaa052_cppui255,
        /*alpha: */
        0x17f36241082dc5dc4e12968736300a389c2cbab471ace605aa7eb8d1cc91016f_cppui255,
        /*V_L: */
        0x2aad0ea7357d6d6bc3e696cb9f53a669b36ef1888fd3daefda299547d5222873_cppui255,
        0x20d25dca706ce16e69797886802260ca4dbfbde1dbc488d97c44af1b752dc2cb_cppui255,
        /*q_last_0: */
        0x30895ee54f09f37d02e99a406c6c8af394e4dd638575bb48bb97498bea211940_cppui255,
        0x2afc6ee2bd64a76ce5d5a2345bed6c99dd4452d7d1712321e497c67b3906a86c_cppui255,
        /*q_blind_0: */
        0x31849db7e2ccf46d25b15a478e4da18972e88efdeccd4525110e636f945a2b3c_cppui255,
        0x16c598e3d182c4be8e8c706fd77a79e03918b7cd335d74768864041a54a195eb_cppui255,
        /*L_0: */
        0x2342576902db29a6082f737d90dd8ceca2aa402444b829d177859040ca028f33_cppui255,
        /*gate selectors: */
        0x2342576902db29a6082f737d90dd8ceca2aa402444b829d177859040ca028f33_cppui255,
        /*table_ids: */
        1,
        /*lookup gate constraint lookup inputs: */
        0x2342576902db29a6082f737d90dd8ceca2aa402444b829d177859040ca028f33_cppui255, 0x0_cppui255, 0x0_cppui255,
        /*lookup tables selcetors: */
        0x3aafabf9cb4dee6fcf3597fa74684696bc5c1e6e64ebc113875c558ab7822c55_cppui255,
        /* lookup tables lookup option: */
        0x334125c610355fc7c5f126ca247e9a5233590241e3050c6a97c4f3c942db3c7a_cppui255,
        0x76e8633bb188ea8094471304fe9ac4489031c2c81e6b4a8ef9761c174a6efdb_cppui255,
        0x844b6e352d0b85ae01b8495c8912db85614af6a1193e948b32d2d4e09d4940e_cppui255,
        /*lookup tables shifted selcetors: */
        0x32f5948010c470a8f18f6943a95866e981c20bbad832c7c31a4a1f50487e131c_cppui255,
        /* lookup tables shifted lookup option: */
        0x2ab0dd9cbdf3b84e1173e4ade0c739312bad5c50c69ede7a671cf2023ea97f0e_cppui255,
        0x844b6e352d0b85ae01b8495c8912db85614af6a1193e948b32d2d4e09d4940e_cppui255,
        0x2342576902db29a6082f737d90dd8ceca2aa402444b829d177859040ca028f33_cppui255,
        /* sorted :*/
        0x309c3f5b27a9decbc857a77c4de0dcf924ab52beef5f1fe1478b4d5f0cdea83d_cppui255,
        0x2f84548fee17235fa8b337133a77b4325accc997229273a513d7eeb2c26d8c72_cppui255,
        0x3c3a027f046e121eb28f3f3a8c595f722b5711aca301ac25563a0bc13f600a8c_cppui255,
        0x3aa7d1881a22a4408949c2b9e4ad31bba1329e386882f6454c8070c3673f2783_cppui255,
        0xf47f8092f969b60daabd4cb1ef68b595a76c42fdc9e217912e4ced2f7dcad3a_cppui255};

    std::array<typename BlueprintFieldType::value_type, 4> expected_res = {
        0xed0fd5a4c7353bbe05c6b605c83fbec891cdf62c9e137b630aea8fc23eba213_cppui255,
        0x2730aed0d40e486fefa62d17dceffdd430ddd4e1129876f1be75b0440887f59a_cppui255,
        0x509b68f48912d1abc42fead48c7aae0adc49dfc05aafcabbcd1b4a84a81822b_cppui255,
        0x126cb3995ab0d911bb988e50df2ece7ba3d22d3fd272421c29579d7c091bbea4_cppui255};    // F

    test<BlueprintFieldType, 4>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 5>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 6>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 7>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_gate_argument_verifier_test4) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::size_t lookup_gates_size = 1;
    std::size_t lookup_tables_size = 1;
    std::vector<std::size_t> gate_constraints_sizes = {1};
    std::vector<std::size_t> gate_constraint_lookup_input_sizes = {3};
    std::vector<std::size_t> lookup_table_lookup_options_sizes = {1};
    std::vector<std::size_t> lookup_table_columns_number = {3};

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        /*theta: */
        0x3570e3894c1215e257f32b60a2506ab1bb838dd71e5bdd070aeea75eef5c04e1_cppui255,
        /*beta: */
        0x4110a75d7bb3b6119d90555bef2ef98a5cc6d02b863d166a8478e7db7d097b7_cppui255,
        /*gamma: */
        0xd8c6a785dd97b0298dec35c05b9a644434fb8ffb8fd571b0efa28269166320f_cppui255,
        /*alpha: */
        0x22c705f52e10b6f5c581348c05068b813972db6286d46fe377bc0e5cd43b6986_cppui255,
        /*V_L: */
        0xfed12cbd566c5b8f2643428652eb43c7bc927475b69c7a4e24deacb830e18b2_cppui255,
        0x19e5f35744d2e897dc93a79eb0ad4840205abcb9f75a7bbc25c82c09d7d12b86_cppui255,
        /*q_last_0: */
        0x25f7509bea7b2d56c9ff4f491e4414772c978dca237a1fae98d9f51bf31ae22d_cppui255,
        0x349f44e2ae4743a2763ccf01c567c9b869a176070df81d96a490c496cad8c2c4_cppui255,
        /*q_blind_0: */
        0x23b533ff1c373758f4acbd22122f1c0262a368e2b7fe16da8407f08650e476b3_cppui255,
        0x36b42752f807b80ecc9b48c46f7af88581f8a1d01062d7b6599c88e22cfde5d1_cppui255,
        /*L_0: */
        0x3b34f6cecb7a7e839ae09301afc44b95407a20905b8a14be97abd9f4d8d9173e_cppui255,
        /*gate selectors: */
        0x2b041988e0bcf922cb877fb2c7b9c78f089b71c49697abfb91c120c7c2eba5a3_cppui255,
        /*table_ids: */
        1,
        /*lookup gate constraint lookup inputs: */
        0x216a008a9b4cb540a650f5b8ce4ffa32ed13b0b36d772aa4b44c34e7089b30ec_cppui255,
        0xf34378a7a7d68ec55dc448195fe4d8230e3e586f8d33e253fa06b55c9bb2c81_cppui255,
        0x3f89dc06cbc9ed36f7c9eb31a5ba50c08c81b20e3cc6df6392088d3e70560457_cppui255,
        /*lookup tables selcetors: */
        0x3b1e84962dd31ccca67360931fc883f1971eb3b6e4e4a00b16f9d32fe3278fe6_cppui255,
        /* lookup tables lookup option: */
        0x2270b42c8a18543699ab4604e78e1fa874b8bbd2921a33b51ec991ce9917dc3c_cppui255,
        0x3feea6bec6d7e5cfec0942e3cd3ad1b016583f8dae822d4928482006c3edc444_cppui255,
        0x349f44e2ae4743a2763ccf01c567c9b869a176070df81d96a490c496cad8c2c4_cppui255,
        /*lookup tables shifted selcetors: */
        0x1b436824b0657adcb1724930a2505ce4bb0c54429299e1770e7b7a0f127e45f_cppui255,
        /* lookup tables shifted lookup option: */
        0x3920d125f461b2c1993aeae529f95de7da14a84e2df91eec971d5994c7541af9_cppui255,
        0x3b2fddd766fb36fcba6a1daf528db241a30d0d253faf6bdd87dee4161f39cba3_cppui255,
        0x2dd16f49dbd11094236e7703222655f02d5ddec78d6f0f3a1365fe24ce3f1979_cppui255,
        /* sorted :*/
        0x29caaf2bb1ed8d76799585de1615640b5e860512b975eddc1ccc07f3c98b7020_cppui255,
        0x3dec9024d47503f3c555ecc92ff68f5341be354cfb6f996d3891259b01f9b447_cppui255,
        0x2f5a6a904d8e435c78790bc85d1451d353480bbca304a67878b4d130098d7faa_cppui255,
        0x3a5fb8b401914e92a328bc1f72fb8671d39432059ed0b4b17e457899ae244e47_cppui255,
        0x561e67687c658bf77f8a1bac00def678dcd280cd0e94cb52cb4870589541c9e_cppui255};

    std::array<typename BlueprintFieldType::value_type, 4> expected_res = {
        0x304cec1d36435a3e6b2b0d8a03d7ca470fe20f1e0664b0a87b330020abeb7790_cppui255,
        0xc87379013fea37f144c3272f082dd7687a98f7531d6ecd8030e58ebe38bb21d_cppui255,
        0x2db7784e371e44e5a2c8bd73f52edf1a0e24801444f312c67a41054f4367cfe4_cppui255,
        0x1300ba94cabf85c2f178f39aa3322edf9db9fb27e284fd75f03fdc0f5ba3711a_cppui255};    // F

    test<BlueprintFieldType, 4>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 5>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 6>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 7>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_gate_argument_verifier_test5) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    std::size_t lookup_gates_size = 1;
    std::size_t lookup_tables_size = 1;
    std::vector<std::size_t> gate_constraints_sizes = {1};
    std::vector<std::size_t> gate_constraint_lookup_input_sizes = {3};
    std::vector<std::size_t> lookup_table_lookup_options_sizes = {1};
    std::vector<std::size_t> lookup_table_columns_number = {3};

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        /*theta: */
        0xc51d84f8427d67ce47566fb043b6415f91196129cb6fd0ea3362f213a0e8cc8_cppui255,
        /*beta: */
        0x3e13fbff8a3e86fd9f2008fad7038a4cd7f131714459e26db3dcd6d4ade21176_cppui255,
        /*gamma: */
        0x3812204b2d8a8231ea5b286ba560cb5f81d79413f41da18e1e46864c4b4f8d91_cppui255,
        /*alpha: */
        0x248372a47839f741d202d4c85de0073259242acc0d885a2d6bde0962fa8a6a10_cppui255,
        /*V_L: */
        0x4e37933c31782d66c0562d7d9cb454160e1978332bd5bd21e5ea353b5683e17_cppui255,
        0xe6354934aa089780f37b58f2a1e06d3e86abe87b914e9fd570874bb50b7d824_cppui255,
        /*q_last_0: */
        0x27e2f5b264645452ea918502e707d6bfbd367964a9941a43c60b4c3a1cf07a6d_cppui255,
        0x185ff7f1d1095cb5afd3453b60b94979e86bae25d109aebe649b37f686a5166e_cppui255,
        /*q_blind_0: */
        0x207dc1c6703c47f4d2677a9d22b5067a0286f863e7d111d36141ab7c2c47cf95_cppui255,
        0x640e57a8467b4ac8c5f28df2de4c22e9bfe4ebe2a38d9463c88af718fe8eff9_cppui255,
        /*L_0: */
        0x216c498e3d3ac1475457bdf32d60392f8c5ba174e750103cdecad98748c8f76f_cppui255,
        /*gate selectors: */
        0x1be57e68b61a28070b21d2c655643b1ba0f3ac40f1b420dae429069f370284f4_cppui255,
        /*table_ids: */
        1,
        /*lookup gate constraint lookup inputs: */
        0x286d7641832338fb96156dc92b252e9373ebf6467885af29d34af6eeaa3f4d0f_cppui255,
        0x172b41321a52e33fbc0dc04bafc25ddd93b28d1dafa4769e9a2c3e17bddbf593_cppui255,
        0x66e1ce661dd815a11bad6d33497ff7c90a77ab56c90fc777203287884102451_cppui255,
        /*lookup tables selcetors: */
        0x1632fef8ee24a270eeaf426cc8e2e996f8741eba99e4b5e32c42909c6dfebe92_cppui255,
        /* lookup tables lookup option: */
        0x3827f3dafcadebcc13addd89f6e1fb57f23d5371cc843d18dfea03bde8f33af5_cppui255,
        0x3419c210464e9866e7b872d501983124cc47c214608a54038b7f9b7b066a477b_cppui255,
        0x185ff7f1d1095cb5afd3453b60b94979e86bae25d109aebe649b37f686a5166e_cppui255,
        /*lookup tables shifted selcetors: */
        0x1f3f50955a5607029333bb249589d94c9c641209b02b1761a672322d30229f93_cppui255,
        /* lookup tables shifted lookup option: */
        0x3b81c607a0e9cac79bbfc5e837079988edadb93a8afb339fa2332f4be2135594_cppui255,
        0x22193ce8a7d60a0a06f6cf97c74ab8724e72f5a242a75afb39f0260e67947718_cppui255,
        0x1fc7fbe92ba48f1663da984e9628b1de09d1a54bfb7a8e5a7b4ecbc7624e2487_cppui255,
        /* sorted :*/
        0x1ad4c042735d793d01537bad9f89a0f1dacacdc47495cd16a638e9ddf74b7f90_cppui255,
        0xeef4260e7f2f40ebcf749089fb3bcc22a0d504a0c4b0b0bb581832fb8597e3d_cppui255,
        0x263a119ae0c496c4a6a289302d2eb77f1acbb3cf11c71b7594b8102060192c5_cppui255,
        0x3c6db664b0ff67f755a19001fdd120088a06e162e3ef0cb16dfe35095040147b_cppui255,
        0x3d35e0079956b46536464e7edd6e72c1cfd8c58c07d9127ef7c79b03776e5ee3_cppui255};

    std::array<typename BlueprintFieldType::value_type, 4> expected_res = {
        0x2413f12ba244014bb6d17827fdf209681c9f3a27fbce3708282075180377399d_cppui255,
        0x1b8893815550e740989d0307c537ee686917e97aeedc6373cf074bb385d4b1bc_cppui255,
        0x3b6b19adb84d93d44f6d20a4d2e7318130609cf9d0dbcf032265e31b92dd20ec_cppui255,
        0x39ee0a3ffd9389e182c7918896bc78ba74b7af4fc8e2ae5e585b4566b0ea183_cppui255};    // F

    test<BlueprintFieldType, 4>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 5>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 6>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
    test<BlueprintFieldType, 7>(public_input, expected_res, lookup_gates_size, gate_constraints_sizes,
                                gate_constraint_lookup_input_sizes, lookup_tables_size,
                                lookup_table_lookup_options_sizes, lookup_table_columns_number);
}

BOOST_AUTO_TEST_SUITE_END()
