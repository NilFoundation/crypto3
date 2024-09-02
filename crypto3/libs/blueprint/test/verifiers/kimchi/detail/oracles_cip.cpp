//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_verifiers_kimchi_detail_oracles_cip_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/oracles_scalar/oracles_cip.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms_cip.hpp"
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"
#include "../../../test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_verifiers_kimchi_detail_oracles_cip_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_kimchi_detail_oracles_cip_test2) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    constexpr static std::size_t public_input_size = 0;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 0;

    constexpr static const std::size_t eval_points_amount = 2;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_cip_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
                                                                           witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
                                                             public_input_size, prev_chal_size>;

    using component_type =
        zk::components::oracles_cip<ArithmetizationType, kimchi_params, 0, 1, 2, 3, 4,
                                    5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    // component input
    var v;
    var u;
    var ft_eval0;
    var ft_eval1;
    std::array<
        std::array<
            std::array<var, commitment_params::split_poly_eval_size>,
            eval_points_amount>,
        kimchi_params::prev_challenges_size> polys;
    std::array<var,eval_points_amount> p_eval;
    std::array<zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>,
               eval_points_amount> evals;
    typename BlueprintFieldType::value_type expected_result = 0x354a5816578a0f9d8d9ddb7fa580573882cb771454a716e4838c1b29e24034a2_cppui_modular255;

    public_input.push_back(0x1A27603517D952BB0060BB01DE0DA94CFC587748DD85D4987C14883E3BA51BAB_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    v = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0CD95BF326F609A8D27F9CD8CFA5C1A0662C588EEA1E5B84CD517DC5BA09C502_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    u = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0C5FFA9CCCAB64B985EB4467CE3933E6F4BFF202AEA53ACD4E27C0C6BBE902B2_cppui_modular255);
    ft_eval0 = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x16FE1AE7F56997161DB512632BE7BFA337F47F422E0D01AF06DE298DD8C429D5_cppui_modular255);
    ft_eval1 = var(0, public_input.size() - 1, false, var::column_type::public_input);


    //    }
    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui_modular255);//x35557EBE9125C357A755F10D90F82A78DE0522FCBA6A3C2039F7F4F95B24F1BC_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    p_eval[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui_modular255);//0x175762EC87AE06A44B63D3F5626B76591A06D32BB6A2FCCA8A62A36C1D7A59E7_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    p_eval[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x1480D3E4FD095CEC3688F88B105EE6F2365DCFAAA28CCB6B87DAB7E71E58010B_cppui_modular255);//lgebra::random_element<BlueprintFieldType>());
    evals[0].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui_modular255);
    evals[0].s[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x05EDDC1E6C268DF398F068F06C51794D6F672E27FB800DFF6C5C35E5C3D84207_cppui_modular255);
    evals[0].s[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1B03A1DBEA987367FDEF97CC27F7441C4845E93AD1583167DA4A1A9CCFFB1E71_cppui_modular255);
    evals[0].s[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x11347E33DF1631D59D66F6149D99DD22FD23B185D7D89CFE0909877C494D7916_cppui_modular255);
    evals[0].s[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0E1372B72364C37883171F80BC89F2AC7043464C8C30E1D2B5D94105035A6C6E_cppui_modular255);
    evals[0].s[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x336A5683971A09A68D33D77B41947F8CAFFE3923190B51D443E515761A32889B_cppui_modular255);
    evals[0].s[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);


    public_input.push_back(0x0C2F522FB163AE4A8D2890C57ABF95E55EF7DDD27A928EFAD0D3FA447D40BC29_cppui_modular255);
    evals[0].w[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x3F0169364239FF2352BFFEF6D2A206A6DC8FAA526C51EB51FC7610F6E73DFAE5_cppui_modular255);
    evals[0].w[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x2BCBED001BA14933A1766C68E09BF19C133AB20B87A9D0DB68321A99C4C7A157_cppui_modular255);
    evals[0].w[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1430DC77EBF0048A4E26DDB817DD34D3F253AA9894C7D442B8BC06C7683D0188_cppui_modular255);
    evals[0].w[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x3B79EBE49FAEF6F123C168CF484296A84186EF1FB9FFFA528B0AAC0761F535AD_cppui_modular255);
    evals[0].w[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x16C6D43CFFB252215D05E1A05DBA2EEAADB3FAAF88B8AABDBD4E8860B9623530_cppui_modular255);
    evals[0].w[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1C0801C94EA28AAD68CEA9C9524106D39DC1A3491435A23D35EEBE56DB3AB116_cppui_modular255);
    evals[0].w[6] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x21545E083F1282D939751D5E0D4EF173C7528C9E38349FE5E02BAB4686B542D4_cppui_modular255);
    evals[0].w[7] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x2E8F53F919EBB22022424A175A051F6FBDB2B57E06E1AC8A8201FBDD02CEE2FD_cppui_modular255);
    evals[0].w[8] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1B5A53763A06BFAF8BAAF566FE885CD31355B2AC4F0F04B13F05610DE1EBAB5E_cppui_modular255);
    evals[0].w[9] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x212CC53B694BA1B3ED2D6C514B97325D62BF301F18E76B7DF94F04B7875C7E64_cppui_modular255);
    evals[0].w[10] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x22C1E6932B0336B13262867483DEE4C6B8E798C24F4245051254A64C61EAC604_cppui_modular255);
    evals[0].w[11] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x356428F289E597185A60ED494351FF93B5802480DC375E4B2C6ECAB816B69524_cppui_modular255);
    evals[0].w[12] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x08066B51E8C7F77F825F541E02C51A608FD217435FDF7E75AD5BBE36CB826443_cppui_modular255);
    evals[0].w[13] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1AA8ADB147AA57E6AA5DBAF2C238352D8C6AA301ECD497BBC775E2A2804E3363_cppui_modular255);
    evals[0].w[14] = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x1635A182C3B5623D5E7CF31D244F389FB478B0612B27937A39D48B473DB68931_cppui_modular255);//lgebra::random_element<BlueprintFieldType>());
    evals[1].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x069DE7D0EBB1985B05DAB9E13348C12530D374BAD474C76C4AB9FAC8EB557332_cppui_modular255);
    evals[1].s[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x177B2B5F39976BE667F5D6768480F1555F52395613AF100529C99844DA28DCC9_cppui_modular255);
    evals[1].s[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x2941C2A82AC0067D3DD6A2C47EDD675D5B7BA071414A8324BA4CFAA1816B163F_cppui_modular255);
    evals[1].s[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x05EA2B93EF3D2CD3E8DDDA175F2446A8390E35219DFBA39111C8CDBFA3038FCE_cppui_modular255);
    evals[1].s[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x15C6FB1ACD775DF5E860906CDDF37C4E6B82CDC1A67F02F129DEAE98A11620D6_cppui_modular255);
    evals[1].s[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x338D629CA1F64B37674CA7B5AF91015CA50A5D335E7076E25D9F4C230C99395D_cppui_modular255);
    evals[1].s[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);


    public_input.push_back(0x144FF7F30B8C75C60E63614EA792F9A41E41C2DBE40F816A602160960C071F56_cppui_modular255);
    evals[1].w[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x114768369E43EA7A13DE72AC855AE7D31DC52B34EB45BB96EA1BDFF54FEC4AB8_cppui_modular255);
    evals[1].w[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x006259A5F4A9A82296077396D476F9E59392BDDA93E63B9A582EF9BBA452A7A2_cppui_modular255);
    evals[1].w[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x3F9EBB3D514729A24B0C87FB434FC043F48195FA45E510BA5817F0ED05DED76B_cppui_modular255);
    evals[1].w[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x06F0CA9962E207949F85C22ADCBE8F27E632D14B843F2C65E264752B6100049E_cppui_modular255);
    evals[1].w[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x3885B6A574C4B6B89867EE499534E0F4937C7D71BA724A857F5E7F797059E879_cppui_modular255);
    evals[1].w[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0554E97666ABA1659D7D107E3F709F546625481B1A5684BE24EFE9B3CBBC300F_cppui_modular255);
    evals[1].w[6] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x06C748D2C049B08C50633EBF7F7A0C68A03677CE382BF6697B7D285F30215616_cppui_modular255);
    evals[1].w[7] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0B252004A6768951624E56F1D98B1DDB006B2284FE1C08B258D95B92BF40266F_cppui_modular255);
    evals[1].w[8] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x029236F173E5278B30CB9DAD8C87CEDE865AD1293B9BBF991F1743E8D1FD6638_cppui_modular255);
    evals[1].w[9] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x28C63DB702FFC629457818259603A154886B11D1D1FB7065037F51212E5BE2D3_cppui_modular255);
    evals[1].w[10] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0219DC4D947F1109C90CD6C0112559A5D04528C2B264062A98DC5E7BBF85F269_cppui_modular255);
    evals[1].w[11] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x246CB73F3BB0A9AC5FA65DED8A1617E0CB8231146F0DF67467ED5E85242DF2B6_cppui_modular255);
    evals[1].w[12] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x06BF9230E2E2424EF63FE51B0306D61BA478A06A226AEDA29DD12DA188D5F302_cppui_modular255);
    evals[1].w[13] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x29126D228A13DAF18CD96C487BF794569FB5A8BBDF14DDEC6CE22DAAED7DF34F_cppui_modular255);
    evals[1].w[14] = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    evals[0].generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    evals[0].poseidon_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    evals[1].generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    evals[1].poseidon_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);



    typename component_type::params_type params = {
        v,
        u,
        ft_eval0,
        ft_eval1,
        polys,
        p_eval,
        evals
    };

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));

    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_kimchi_detail_oracles_cip_test) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    constexpr static std::size_t public_input_size = 0;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    constexpr static const std::size_t eval_points_amount = 2;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
                                                                           witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
                                                             public_input_size, prev_chal_size>;

    using component_type =
        zk::components::oracles_cip<ArithmetizationType, kimchi_params, 0, 1, 2, 3, 4,
                                    5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    // component input
    var v;
    var u;
    var ft_eval0;
    var ft_eval1;
    std::array<
        std::array<
            std::array<var, commitment_params::split_poly_eval_size>,
            eval_points_amount>,
        kimchi_params::prev_challenges_size> polys;
    std::array<var,eval_points_amount> p_eval;
    std::array<zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>,
               eval_points_amount> evals;
    typename BlueprintFieldType::value_type expected_result = 0x092931C57CBF91630B192C9BB166864F5D3F7E3D2C9217FDB382DB82564D4607_cppui_modular255;

    public_input.push_back(0x0416077232C8D4EFD0D1120ACC756A397EA8DCDCF792E5E0F9CDFF82BDF42D2D_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    v = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x2E0BB5E9179A691E51FB7336CB161A330268EE64C745078D6FD460E02A76729D_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    u = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x36B33A1266C7DCF380A308055D32978AE1F469723AAEB3EDBC512B18D6C095BD_cppui_modular255);
    ft_eval0 = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x30B81DB776FF4C13A0BF7BAB87E9768D7ADE52CD3D29549FB1E08798D6A3EF9E_cppui_modular255);
    ft_eval1 = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x2C27D4E04141972BE1147405F66D1EBAF82622DC3A0B97AF902988E38E76614F_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    polys[0][0][0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x2034A41141E8DAFD88D5625DC695D10351CD8DACB545B4D260560DE31EF123EF_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    polys[0][0][1] = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui_modular255);//x35557EBE9125C357A755F10D90F82A78DE0522FCBA6A3C2039F7F4F95B24F1BC_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    p_eval[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui_modular255);//0x175762EC87AE06A44B63D3F5626B76591A06D32BB6A2FCCA8A62A36C1D7A59E7_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    p_eval[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x3F8D8F25CB5A2D2533B3063716C83ADDBFF999C60BC5DEBC3A633EF82EBE108D_cppui_modular255);//lgebra::random_element<BlueprintFieldType>());
    evals[0].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x35557EBE9125C357A755F10D90F82A78DE0522FCBA6A3C2039F7F4F95B24F1BC_cppui_modular255);
    evals[0].s[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x3BD62FADFBC967B2DDE2CD067A531BF158C20BBE1B42BB53BF7EE8EC3834555F_cppui_modular255);
    evals[0].s[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1D4D2D839270B2866A00334B3CD86E5B7A759B59329F1662039D6D2124FEE4D4_cppui_modular255);
    evals[0].s[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x2CA95F70D9D97BD9AB7F633B85556C1ABD1938D49ED2975FE62319951E69A022_cppui_modular255);
    evals[0].s[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x2601AC11905952B2EFD1BB4BE50AC2E86BBC421876C07312CFCC3AED17556926_cppui_modular255);
    evals[0].s[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x16303670383248B3C7D5786C8161EE001848D3D86D98F1069A3E0136E8AF322F_cppui_modular255);
    evals[0].s[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);


    public_input.push_back(0x30AC247252D0ABAA93BDEEFBF27F4931E8F995D58AE78FC99910719A226ED51E_cppui_modular255);
    evals[0].w[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0E22763F6B830A605362663C49102E31FE20AE4A653038C3007B45CC85CBB96A_cppui_modular255);
    evals[0].w[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x2B98C80C843569161306DD7C9FA11332358E5FBB48C5DAD801134AEBE9289DB7_cppui_modular255);
    evals[0].w[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x090F19D99CE7C7CBD2AB54BCF631F8324AB57830230E83D1687E1F1E4C858203_cppui_modular255);
    evals[0].w[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x26856BA6B59A2681924FCBFD4CC2DD32822329A106A425E66916243DAFE26650_cppui_modular255);
    evals[0].w[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x03FBBD73CE4C853751F4433DA353C232974A4215E0ECCEDFD080F870133F4A9C_cppui_modular255);
    evals[0].w[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x21720F40E6FEE3ED1198BA7DF9E4A732CEB7F386C48270F4D118FD8F769C2EE9_cppui_modular255);
    evals[0].w[6] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x3EE8610DFFB142A2D13D31BE50758C330625A4F7A8181309D1B102AED9F91336_cppui_modular255);
    evals[0].w[7] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1C5EB2DB1863A15890E1A8FEA70671331B4CBD6C8260BC03391BD6E13D55F782_cppui_modular255);
    evals[0].w[8] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x39D504A83116000E5086203EFD97563352BA6EDD65F65E1839B3DC00A0B2DBCF_cppui_modular255);
    evals[0].w[9] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x174B567549C85EC4102A977F54283B3367E18752403F0711A11EB033040FC01B_cppui_modular255);
    evals[0].w[10] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x34C1A842627ABD79CFCF0EBFAAB920339F4F38C323D4A926A1B6B552676CA468_cppui_modular255);
    evals[0].w[11] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1237FA0F7B2D1C2F8F738600014A0533B4765137FE1D522009218984CAC988B4_cppui_modular255);
    evals[0].w[12] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x2FAE4BDC93DF7AE54F17FD4057DAEA33EBE402A8E1B2F43509B98EA42E266D01_cppui_modular255);
    evals[0].w[13] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0D249DA9AC91D99B0EBC7480AE6BCF34010B1B1DBBFB9D2E712462D69183514D_cppui_modular255);
    evals[0].w[14] = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0D69C9B3BE918CB3DE88610F89D800916F23984B5BDFB8AE753C34C234BB1407_cppui_modular255);//lgebra::random_element<BlueprintFieldType>());
    evals[1].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x175762EC87AE06A44B63D3F5626B76591A06D32BB6A2FCCA8A62A36C1D7A59E7_cppui_modular255);
    evals[1].s[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1F21634F6AEDCADE3D878584CC9EDBA4DA6A496DA05D824FB7E741305AAD2C45_cppui_modular255);
    evals[1].s[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1418CE39644E82C6411C9B3FD878FD781E3438B6B6B1106657AA48AE8F73F977_cppui_modular255);
    evals[1].s[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x13D3942A39464ACE1D4D56A687BBC392DCE24392E4CC6F34063C8B1BBC8E3D71_cppui_modular255);
    evals[1].s[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x31EFFF757DF39A98EB88BBBB86607EAE2AC1856A6F172BF969178B21975AFF4C_cppui_modular255);
    evals[1].s[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0EBAE7C12211C4631FD3B3B04F112D99393CA706E09B4B98F2502A3720785BBC_cppui_modular255);
    evals[1].s[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);


    public_input.push_back(0x0EC5173646D6F7F31A1774DFCC7FB5B0EA356EE2275EC698F7BEBE691BB84E06_cppui_modular255);
    evals[1].w[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x30D45140D88575398696BB4F1FA770B2337A0DDED0586F664DCFDE63334BF64D_cppui_modular255);
    evals[1].w[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x12E38B4B6A33F27FF31601BE72CF2BB35A7813DF70051F180AB3CD704ADF9E93_cppui_modular255);
    evals[1].w[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x34F2C555FBE26FC65F95482DC5F6E6B4A3BCB2DC18FEC7E560C4ED6A627346DA_cppui_modular255);
    evals[1].w[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1701FF608D90ED0CCC148E9D191EA1B5CABAB8DCB8AB77971DA8DC777A06EF20_cppui_modular255);
    evals[1].w[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x3911396B1F3F6A533893D50C6C465CB713FF57D961A5206473B9FC71919A9767_cppui_modular255);
    evals[1].w[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1B207375B0EDE799A5131B7BBF6E17B83AFD5DDA0151D016309DEB7EA92E3FAD_cppui_modular255);
    evals[1].w[6] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x3D2FAD80429C64E0119261EB1295D2B98441FCD6AA4B78E386AF0B78C0C1E7F4_cppui_modular255);
    evals[1].w[7] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1F3EE78AD44AE2267E11A85A65BD8DBAAB4002D749F828954392FA85D855903A_cppui_modular255);
    evals[1].w[8] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x014E219565F95F6CEA90EEC9B8E548BBD23E08D7E9A4D8470076E992EFE93880_cppui_modular255);
    evals[1].w[9] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x235D5B9FF7A7DCB3571035390C0D03BD1B82A7D4929E81145688098D077CE0C7_cppui_modular255);
    evals[1].w[10] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x056C95AA895659F9C38F7BA85F34BEBE4280ADD5324B30C6136BF89A1F10890D_cppui_modular255);
    evals[1].w[11] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x277BCFB51B04D740300EC217B25C79BF8BC54CD1DB44D993697D189436A43154_cppui_modular255);
    evals[1].w[12] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x098B09BFACB354869C8E0887058434C0B2C352D27AF18945266107A14E37D99A_cppui_modular255);
    evals[1].w[13] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x2B9A43CA3E61D1CD090D4EF658ABEFC1FC07F1CF23EB32127C72279B65CB81E1_cppui_modular255);
    evals[1].w[14] = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x28654BAD9D8CDFD846C0DB23E11CFE750DF683B9AC1F00BD1550778F27B28C70_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    evals[0].generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    evals[0].poseidon_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x33018173752351E61F3CE0C02C14FCC1C936E2A9FC8713268ED5871BA404ECAF_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    evals[1].generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui_modular255);//algebra::random_element<BlueprintFieldType>());
    evals[1].poseidon_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

    typename component_type::params_type params = {
        v,
        u,
        ft_eval0,
        ft_eval1,
        polys,
        p_eval,
        evals
    };

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_SUITE_END()