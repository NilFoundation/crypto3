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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_detail_constraints_generic_scalars_test

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
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/constraints/generic_scalars.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/binding.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>

#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/evaluation_proof.hpp>

#include "test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_detail_constraints_generic_scalars_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_constraints_generic_scalars_generic_input_test_suite) {

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

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    using component_type =
        zk::components::generic_scalars<ArithmetizationType, kimchi_params, 0, 1, 2,
                                             3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    // params:
    // std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>,
    //     KimchiParamsType::eval_points_amount> evals;
    // std::array<var, KimchiParamsType::alpha_powers_n> alphas;
    // std::size_t start_idx;

    std::array<typename BlueprintFieldType::value_type, witness_columns>
        eval0_w = {
            0x2A016E5F91F6C33552FC86A7A88C034E5CF1301E4982545A15AB709ECE150E09_cppui256,
            0x1D1B8F16A3DF52F90BA4856A11D397FDD175DEBBDC84F9D9FD71C46E5CB311CC_cppui256,
            0x034EB5403A85D023EFD87CE7E37CD027921DBC8F5A59C6338A12965B2E1D2D9B_cppui256,
            0x3D708DC37C2985BD9E8F39D40FFB35A8C1D1D4106AC17CEA1668C944007FE789_cppui256,
            0x23ACD65BE15FC86FB7FC4FD45701CF7F348C13DD6DFF400DF808BE97006E06C8_cppui256,
            0x3F6D999688174F2CC9C37FBFDA241825F50505E56EF660E29FBC52F06008F2EF_cppui256,
            0x054FF59489820600DB800466FDF3063D387CAFC5464741417FAD07A00E2B558A_cppui256,
            0x078062AB9E022D286A47F28A6A57C368598416D076C558A8288A05AD9A1451DE_cppui256,
            0x09B0CFC2B282544FF90FE0ADD6BC80937A8B7DDBA743700ED16703BB25FD4E32_cppui256,
            0x0BE13CD9C7027B7787D7CED143213DBE9B92E4E6D7C187757A4401C8B1E64A86_cppui256,
            0x0E11A9F0DB82A29F169FBCF4AF85FAE9BC9A4BF2083F9EDC2320FFD63DCF46DA_cppui256,
            0x10421707F002C9C6A567AB181BEAB814DDA1B2FD38BDB642CBFDFDE3C9B8432E_cppui256,
            0x1272841F0482F0EE342F993B884F753FFEA91A08693BCDA974DAFBF155A13F82_cppui256,
            0x14A2F13619031815C2F7875EF4B4326B1FB0811399B9E5101DB7F9FEE18A3BD6_cppui256,
            0x16D35E4D2D833F3D51BF75826118EF9640B7E81ECA37FC76C694F80C6D73382A_cppui256,
        };

    typename BlueprintFieldType::value_type eval0_z = 0x38C5D08C61572A0F233A3732575F3A07AD484107EC7366FEB0903FCC30253C1A_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval0_s = {
        0x01751A5CCC6A9B9BDF660296AF5F7C80229DC97F3646FFC3729D827E80DF39DF_cppui256,
        0x264CBA1EFD870553869EC32E652FE2FC5DB4DF0C8B8550816F1947F66858B238_cppui256,
        0x21D7D3F53426BA3024217C852D5B1944031F52E784E95CA0539A9F88FB3F3FBE_cppui256,
        0x260E6148F06FA79CD3C8C4A379955A8823017E730AD3624A578304A44B5113AC_cppui256,
        0x2E901B006A7D080B6566A472AC9DEA73BB53A57A190B1A21ECEB698A869374BA_cppui256,
        0x2E70F1D4AE3E1DE24337D33C4F61C88A628368CA7FBE9BF67C16F0944C64B7DE_cppui256,
    };

    typename BlueprintFieldType::value_type eval_generic_selector = 0x2C1E20B5D662CE38070228313FD0D968116779CC3CD2FFF662707412EEBD04C7_cppui256;

    std::array<typename BlueprintFieldType::value_type, witness_columns>
        eval1_w = {
            0x144FF7F30B8C75C60E63614EA792F9A41E41C2DBE40F816A602160960C071F56_cppui256,
            0x114768369E43EA7A13DE72AC855AE7D31DC52B34EB45BB96EA1BDFF54FEC4AB8_cppui256,
            0x006259A5F4A9A82296077396D476F9E59392BDDA93E63B9A582EF9BBA452A7A2_cppui256,
            0x3F9EBB3D514729A24B0C87FB434FC043F48195FA45E510BA5817F0ED05DED76B_cppui256,
            0x06F0CA9962E207949F85C22ADCBE8F27E632D14B843F2C65E264752B6100049E_cppui256,
            0x3885B6A574C4B6B89867EE499534E0F4937C7D71BA724A857F5E7F797059E879_cppui256,
            0x0554E97666ABA1659D7D107E3F709F546625481B1A5684BE24EFE9B3CBBC300F_cppui256,
            0x06C748D2C049B08C50633EBF7F7A0C68A03677CE382BF6697B7D285F30215616_cppui256,
            0x0B252004A6768951624E56F1D98B1DDB006B2284FE1C08B258D95B92BF40266F_cppui256,
            0x029236F173E5278B30CB9DAD8C87CEDE865AD1293B9BBF991F1743E8D1FD6638_cppui256,
            0x28C63DB702FFC629457818259603A154886B11D1D1FB7065037F51212E5BE2D3_cppui256,
            0x0219DC4D947F1109C90CD6C0112559A5D04528C2B264062A98DC5E7BBF85F269_cppui256,
            0x246CB73F3BB0A9AC5FA65DED8A1617E0CB8231146F0DF67467ED5E85242DF2B6_cppui256,
            0x06BF9230E2E2424EF63FE51B0306D61BA478A06A226AEDA29DD12DA188D5F302_cppui256,
            0x29126D228A13DAF18CD96C487BF794569FB5A8BBDF14DDEC6CE22DAAED7DF34F_cppui256
        };

    typename BlueprintFieldType::value_type eval1_z = 0x1635A182C3B5623D5E7CF31D244F389FB478B0612B27937A39D48B473DB68931_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval1_s = {
        0x069DE7D0EBB1985B05DAB9E13348C12530D374BAD474C76C4AB9FAC8EB557332_cppui256,
        0x177B2B5F39976BE667F5D6768480F1555F52395613AF100529C99844DA28DCC9_cppui256,
        0x2941C2A82AC0067D3DD6A2C47EDD675D5B7BA071414A8324BA4CFAA1816B163F_cppui256,
        0x05EA2B93EF3D2CD3E8DDDA175F2446A8390E35219DFBA39111C8CDBFA3038FCE_cppui256,
        0x15C6FB1ACD775DF5E860906CDDF37C4E6B82CDC1A67F02F129DEAE98A11620D6_cppui256,
        0x338D629CA1F64B37674CA7B5AF91015CA50A5D335E7076E25D9F4C230C99395D_cppui256,
    };

    std::array<std::array<typename BlueprintFieldType::value_type, witness_columns>, 2> eval_w = {eval0_w, eval1_w};
    std::array<typename BlueprintFieldType::value_type, 2> eval_z = {eval0_z, eval1_z};
    std::array<std::array<typename BlueprintFieldType::value_type, perm_size>, 2> eval_s = {eval0_s, eval1_s};

    typename BlueprintFieldType::value_type alpha_val =
        0x220B73274823F8B0E46273FA8546B238F1E58529E061A811AB584A97C146AF87_cppui256;

    std::array<typename BlueprintFieldType::value_type, component_type::output_size>
        expected_result ={ 0x3EA2D6B15BFDB5C984671ECF5BC14CB50F04F1DADECEA0CBD36C92B61F15312E_cppui256,
            0x35E37366760C3D2A9C95BFEE8BE746548D84ED80E7C88ED535B5BEF0518EC54B_cppui256,
            0x1A47E6230B00888729DEB23939B141C3A032851A8D06D8821CBA9388367D6577_cppui256,
            0x3D2FFD65B4D7E78F53072A50E814894D76580CF03F8DF994097C3FD3179D53FE_cppui256,
            0x2C1E20B5D662CE38070228313FD0D968116779CC3CD2FFF662707412EEBD04C7_cppui256,
            0x19D709063B3A3E32EDB448F15674D93910478C69E394BC85A73128501155BCB0_cppui256,
            0x37F4062FEFF15FFAE25149ADE7DFE424E2FC8330DF09FF8B4416BAF093464667_cppui256,
            0x124D8A07FB6BFD8E8E61FF9BD400C12067B5A8D214D4DFCA30206A763D088B4C_cppui256,
            0x0C400758CECEEAE5A929CA341595ADA15AA0C8C582CDF3A424CCBFE0C92DE235_cppui256,
            0x0EF41780273377126FC396C87B03CA6AB9488BA955C5C2EC2253F6A9459C1A9E_cppui256
        };

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(0);
    var zero = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<
                        BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;

    for (std::size_t i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < witness_columns; j++) {
            public_input.push_back(eval_w[i][j]);
            var w = var(0, public_input.size() - 1, false, var::column_type::public_input);
            evals[i].w[j] = w;
        }

        public_input.push_back(eval_z[i]);
        var z = var(0, public_input.size() - 1, false, var::column_type::public_input);
        evals[i].z = z;

        for (std::size_t j = 0; j < perm_size; j++) {
            public_input.push_back(eval_s[i][j]);
            var s = var(0, public_input.size() - 1, false, var::column_type::public_input);
            evals[i].s[j] = s;
        }

        public_input.push_back(eval_generic_selector);
        var generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);
        evals[i].generic_selector = generic_selector;
    }

    std::array<var, circuit_description::alpha_powers_n> alpha_powers;
    for (std::size_t i = 0; i < circuit_description::alpha_powers_n; i++) {
        public_input.push_back(alpha_val.pow(i));
        alpha_powers[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    typename component_type::params_type params = {
        evals, alpha_powers, 0};

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        for (std::size_t i = 0; i < expected_result.size(); i++) {
            assert(expected_result[i] == assignment.var_value(real_res.output[i]));
        }
    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_SUITE_END()