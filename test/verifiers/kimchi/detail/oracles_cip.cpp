//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/oracles_cip.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
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
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t alpha_powers_n = 5;
    constexpr static std::size_t public_input_size = 0;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;
    constexpr static std::size_t lookup_table_size = 1;
    constexpr static bool use_lookup = false;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 0;

    constexpr static const std::size_t eval_points_amount = 2;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    // using circuit_description = zk::components::kimchi_params_type::circuit_params::kimchi_circuit_description<false, false>;
    using kimchi_params =
        zk::components::kimchi_params_type<curve_type, commitment_params, witness_columns, perm_size, use_lookup, lookup_table_size,
                                           alpha_powers_n, public_input_size, prev_chal_size >;

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
    typename BlueprintFieldType::value_type expected_result = 0x354a5816578a0f9d8d9ddb7fa580573882cb771454a716e4838c1b29e24034a2_cppui255;

    public_input.push_back(0x1A27603517D952BB0060BB01DE0DA94CFC587748DD85D4987C14883E3BA51BAB_cppui255);//algebra::random_element<BlueprintFieldType>());
    v = var(0, public_input.size() - 1, false, var::column_type::public_input);
    //public_input.push_back(0x2E0BB5E9179A691E51FB7336CB161A330268EE64C745078D6FD460E02A76729D_cppui255);
    public_input.push_back(0x0CD95BF326F609A8D27F9CD8CFA5C1A0662C588EEA1E5B84CD517DC5BA09C502_cppui255);//algebra::random_element<BlueprintFieldType>());
    u = var(0, public_input.size() - 1, false, var::column_type::public_input);
    //    fteval0
    //        Fp256 "(064EEBAFAC40594BCEACD8091EBC8D085D3D3BEB2CA76A7E1D7935DC0CB73A66)"
    //        fteval1
    //            Fp256 "()"
    public_input.push_back(0x0C5FFA9CCCAB64B985EB4467CE3933E6F4BFF202AEA53ACD4E27C0C6BBE902B2_cppui255);
    ft_eval0 = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x16FE1AE7F56997161DB512632BE7BFA337F47F422E0D01AF06DE298DD8C429D5_cppui255);
    ft_eval1 = var(0, public_input.size() - 1, false, var::column_type::public_input);

    //    for (std::size_t i = 0; i < kimchi_params::prev_challenges_size; i++) {
    //        for (std::size_t j = 0; j < eval_points_amount; j++) {
    //            for (std::size_t k = 0; k < commitment_params::split_poly_eval_size; k++) {
    //    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);//0x2C27D4E04141972BE1147405F66D1EBAF82622DC3A0B97AF902988E38E76614F_cppui255);//algebra::random_element<BlueprintFieldType>());
    //    polys[0][0][0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    //    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);//0x2034A41141E8DAFD88D5625DC695D10351CD8DACB545B4D260560DE31EF123EF_cppui255);//algebra::random_element<BlueprintFieldType>());
    //    polys[0][1][0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    //            }
    //        }
    //    }
    //    polys
    //        Fp256 "(03B060BB64B9D6627C7336873BA524D7B752598E8B3390647BDF6B70B5BB93FF)"
    //        Fp256 "(39B7CA68618353B26F521A651FE3F9DD365401BC8B68B07FC6D656EB010A541B)"
    //        evals
    //            Fp256 "(38C5D08C61572A0F233A3732575F3A07AD484107EC7366FEB0903FCC30253C1A)"
    //        Fp256 "(2DEFB3CFB41140464BF709B147777123731468F528CF8F14C032CA136A477469)"
    //    for (std::size_t i = 0; i < eval_points_amount; i++) {
    //                )"
    //Fp256 "(069DE7D0EBB1985B05DAB9E13348C12530D374BAD474C76C4AB9FAC8EB557332)"
    p_eval[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    //    }
    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);//x35557EBE9125C357A755F10D90F82A78DE0522FCBA6A3C2039F7F4F95B24F1BC_cppui255);//algebra::random_element<BlueprintFieldType>());
    p_eval[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);//0x175762EC87AE06A44B63D3F5626B76591A06D32BB6A2FCCA8A62A36C1D7A59E7_cppui255);//algebra::random_element<BlueprintFieldType>());

    //    for (std::size_t i = 0; i < eval_points_amount; i++) {
    //        for (std::size_t j = 0; j < kimchi_params::witness_columns; j++) {
    //            public_input.push_back(algebra::random_element<BlueprintFieldType>());
    //            evals[i].w[j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    //        }

    public_input.push_back(0x1480D3E4FD095CEC3688F88B105EE6F2365DCFAAA28CCB6B87DAB7E71E58010B_cppui255);//lgebra::random_element<BlueprintFieldType>());
    evals[0].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui255);
    evals[0].s[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x05EDDC1E6C268DF398F068F06C51794D6F672E27FB800DFF6C5C35E5C3D84207_cppui255);
    evals[0].s[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1B03A1DBEA987367FDEF97CC27F7441C4845E93AD1583167DA4A1A9CCFFB1E71_cppui255);
    evals[0].s[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x11347E33DF1631D59D66F6149D99DD22FD23B185D7D89CFE0909877C494D7916_cppui255);
    evals[0].s[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0E1372B72364C37883171F80BC89F2AC7043464C8C30E1D2B5D94105035A6C6E_cppui255);
    evals[0].s[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x336A5683971A09A68D33D77B41947F8CAFFE3923190B51D443E515761A32889B_cppui255);
    evals[0].s[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);


    public_input.push_back(0x0C2F522FB163AE4A8D2890C57ABF95E55EF7DDD27A928EFAD0D3FA447D40BC29_cppui255);
    evals[0].w[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x3F0169364239FF2352BFFEF6D2A206A6DC8FAA526C51EB51FC7610F6E73DFAE5_cppui255);
    evals[0].w[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x2BCBED001BA14933A1766C68E09BF19C133AB20B87A9D0DB68321A99C4C7A157_cppui255);
    evals[0].w[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1430DC77EBF0048A4E26DDB817DD34D3F253AA9894C7D442B8BC06C7683D0188_cppui255);
    evals[0].w[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x3B79EBE49FAEF6F123C168CF484296A84186EF1FB9FFFA528B0AAC0761F535AD_cppui255);
    evals[0].w[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x16C6D43CFFB252215D05E1A05DBA2EEAADB3FAAF88B8AABDBD4E8860B9623530_cppui255);
    evals[0].w[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1C0801C94EA28AAD68CEA9C9524106D39DC1A3491435A23D35EEBE56DB3AB116_cppui255);
    evals[0].w[6] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x21545E083F1282D939751D5E0D4EF173C7528C9E38349FE5E02BAB4686B542D4_cppui255);
    evals[0].w[7] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x2E8F53F919EBB22022424A175A051F6FBDB2B57E06E1AC8A8201FBDD02CEE2FD_cppui255);
    evals[0].w[8] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1B5A53763A06BFAF8BAAF566FE885CD31355B2AC4F0F04B13F05610DE1EBAB5E_cppui255);
    evals[0].w[9] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x212CC53B694BA1B3ED2D6C514B97325D62BF301F18E76B7DF94F04B7875C7E64_cppui255);
    evals[0].w[10] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x22C1E6932B0336B13262867483DEE4C6B8E798C24F4245051254A64C61EAC604_cppui255);
    evals[0].w[11] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x356428F289E597185A60ED494351FF93B5802480DC375E4B2C6ECAB816B69524_cppui255);
    evals[0].w[12] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x08066B51E8C7F77F825F541E02C51A608FD217435FDF7E75AD5BBE36CB826443_cppui255);
    evals[0].w[13] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x1AA8ADB147AA57E6AA5DBAF2C238352D8C6AA301ECD497BBC775E2A2804E3363_cppui255);
    evals[0].w[14] = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x1635A182C3B5623D5E7CF31D244F389FB478B0612B27937A39D48B473DB68931_cppui255);//lgebra::random_element<BlueprintFieldType>());
    evals[1].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x069DE7D0EBB1985B05DAB9E13348C12530D374BAD474C76C4AB9FAC8EB557332_cppui255);
    evals[1].s[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x177B2B5F39976BE667F5D6768480F1555F52395613AF100529C99844DA28DCC9_cppui255);
    evals[1].s[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x2941C2A82AC0067D3DD6A2C47EDD675D5B7BA071414A8324BA4CFAA1816B163F_cppui255);
    evals[1].s[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x05EA2B93EF3D2CD3E8DDDA175F2446A8390E35219DFBA39111C8CDBFA3038FCE_cppui255);
    evals[1].s[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x15C6FB1ACD775DF5E860906CDDF37C4E6B82CDC1A67F02F129DEAE98A11620D6_cppui255);
    evals[1].s[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x338D629CA1F64B37674CA7B5AF91015CA50A5D335E7076E25D9F4C230C99395D_cppui255);
    evals[1].s[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);


    public_input.push_back(0x144FF7F30B8C75C60E63614EA792F9A41E41C2DBE40F816A602160960C071F56_cppui255);
    evals[1].w[0] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x114768369E43EA7A13DE72AC855AE7D31DC52B34EB45BB96EA1BDFF54FEC4AB8_cppui255);
    evals[1].w[1] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x006259A5F4A9A82296077396D476F9E59392BDDA93E63B9A582EF9BBA452A7A2_cppui255);
    evals[1].w[2] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x3F9EBB3D514729A24B0C87FB434FC043F48195FA45E510BA5817F0ED05DED76B_cppui255);
    evals[1].w[3] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x06F0CA9962E207949F85C22ADCBE8F27E632D14B843F2C65E264752B6100049E_cppui255);
    evals[1].w[4] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x3885B6A574C4B6B89867EE499534E0F4937C7D71BA724A857F5E7F797059E879_cppui255);
    evals[1].w[5] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0554E97666ABA1659D7D107E3F709F546625481B1A5684BE24EFE9B3CBBC300F_cppui255);
    evals[1].w[6] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x06C748D2C049B08C50633EBF7F7A0C68A03677CE382BF6697B7D285F30215616_cppui255);
    evals[1].w[7] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0B252004A6768951624E56F1D98B1DDB006B2284FE1C08B258D95B92BF40266F_cppui255);
    evals[1].w[8] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x029236F173E5278B30CB9DAD8C87CEDE865AD1293B9BBF991F1743E8D1FD6638_cppui255);
    evals[1].w[9] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x28C63DB702FFC629457818259603A154886B11D1D1FB7065037F51212E5BE2D3_cppui255);
    evals[1].w[10] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x0219DC4D947F1109C90CD6C0112559A5D04528C2B264062A98DC5E7BBF85F269_cppui255);
    evals[1].w[11] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x246CB73F3BB0A9AC5FA65DED8A1617E0CB8231146F0DF67467ED5E85242DF2B6_cppui255);
    evals[1].w[12] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x06BF9230E2E2424EF63FE51B0306D61BA478A06A226AEDA29DD12DA188D5F302_cppui255);
    evals[1].w[13] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(0x29126D228A13DAF18CD96C487BF794569FB5A8BBDF14DDEC6CE22DAAED7DF34F_cppui255);
    evals[1].w[14] = var(0, public_input.size() - 1, false, var::column_type::public_input);

    //        for (std::size_t j = 0; j < kimchi_params::permut_size - 1; j++) {
    //            public_input.push_back(algebra::random_element<BlueprintFieldType>());
    //            evals[i].s[j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    //        }

    // TODO: lookups
    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);//algebra::random_element<BlueprintFieldType>());
    evals[0].generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);//algebra::random_element<BlueprintFieldType>());
    evals[0].poseidon_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);//algebra::random_element<BlueprintFieldType>());
    evals[1].generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(0x0000000000000000000000000000000000000000000000000000000000000000_cppui255);//algebra::random_element<BlueprintFieldType>());
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
        std::cout<<assignment.var_value(real_res.output).data<<std::endl;
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}
//
//BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_kimchi_detail_oracles_cip_test) {
//
//    using curve_type = algebra::curves::vesta;
//    using BlueprintFieldType = typename curve_type::scalar_field_type;
//    constexpr std::size_t WitnessColumns = 15;
//    constexpr std::size_t PublicInputColumns = 1;
//    constexpr std::size_t ConstantColumns = 1;
//    constexpr std::size_t SelectorColumns = 30;
//    using ArithmetizationParams =
//        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
//    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
//    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
//    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
//    constexpr std::size_t Lambda = 40;
//
//    using var = zk::snark::plonk_variable<BlueprintFieldType>;
//
//    constexpr static std::size_t alpha_powers_n = 5;
//    constexpr static std::size_t public_input_size = 3;
//    constexpr static std::size_t max_poly_size = 32;
//    constexpr static std::size_t eval_rounds = 5;
//
//    constexpr static std::size_t witness_columns = 15;
//    constexpr static std::size_t perm_size = 7;
//    constexpr static std::size_t lookup_table_size = 1;
//    constexpr static bool use_lookup = false;
//
//    constexpr static std::size_t srs_len = 10;
//    constexpr static const std::size_t prev_chal_size = 1;
//
//    constexpr static const std::size_t eval_points_amount = 2;
//
//    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
//    using kimchi_params =
//        zk::components::kimchi_params_type<curve_type, commitment_params, witness_columns, perm_size, use_lookup, lookup_table_size,
//                                           alpha_powers_n, public_input_size, prev_chal_size>;
//
//    using component_type =
//        zk::components::oracles_cip<ArithmetizationType, kimchi_params,1, 0, 1, 2, 3, 4,
//                                       5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
//
//    std::vector<typename BlueprintFieldType::value_type> public_input;
//
//    // component input
//    var v;
//    var u;
//    var ft_eval0;
//    var ft_eval1;
//    std::array<
//        std::array<
//        std::array<var, commitment_params::split_poly_eval_size>,
//        eval_points_amount>,
//        kimchi_params::prev_challenges_size> polys;
//    std::array<var, eval_points_amount> p_eval;
//    std::array<zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>,
//        eval_points_amount> evals;
//
//    public_input.push_back(algebra::random_element<BlueprintFieldType>());
//    v = var(0, public_input.size() - 1, false, var::column_type::public_input);
//
//    public_input.push_back(algebra::random_element<BlueprintFieldType>());
//    u = var(0, public_input.size() - 1, false, var::column_type::public_input);
//
//    public_input.push_back(algebra::random_element<BlueprintFieldType>());
//    ft_eval0 = var(0, public_input.size() - 1, false, var::column_type::public_input);
//
//    public_input.push_back(algebra::random_element<BlueprintFieldType>());
//    ft_eval1 = var(0, public_input.size() - 1, false, var::column_type::public_input);
//
//    for (std::size_t i = 0; i < kimchi_params::prev_challenges_size; i++) {
//        for (std::size_t j = 0; j < eval_points_amount; j++) {
//            for (std::size_t k = 0; k < commitment_params::split_poly_eval_size; k++) {
//                public_input.push_back(algebra::random_element<BlueprintFieldType>());
//                polys[i][j][k] = var(0, public_input.size() - 1, false, var::column_type::public_input);
//            }
//        }
//    }
//
//    for (std::size_t i = 0; i < eval_points_amount; i++) {
//        public_input.push_back(algebra::random_element<BlueprintFieldType>());
//        p_eval[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
//    }
//
//    for (std::size_t i = 0; i < eval_points_amount; i++) {
//        for (std::size_t j = 0; j < kimchi_params::witness_columns; j++) {
//            public_input.push_back(algebra::random_element<BlueprintFieldType>());
//            evals[i].w[j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
//        }
//
//        public_input.push_back(algebra::random_element<BlueprintFieldType>());
//        evals[i].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
//
//        for (std::size_t j = 0; j < kimchi_params::permut_size - 1; j++) {
//            public_input.push_back(algebra::random_element<BlueprintFieldType>());
//            evals[i].s[j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
//        }
//
//        // TODO: lookups
//
//        public_input.push_back(algebra::random_element<BlueprintFieldType>());
//        evals[i].generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);
//
//        public_input.push_back(algebra::random_element<BlueprintFieldType>());
//        evals[i].poseidon_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);
//    }
//
//
//    typename component_type::params_type params = {
//        v,
//        u,
//        ft_eval0,
//        ft_eval1,
//        polys,
//        p_eval,
//        evals
//    };
//
//    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};
//
//    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
//                                                                                                 result_check);
//}

BOOST_AUTO_TEST_SUITE_END()