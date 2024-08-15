//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_ft_eval_test

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
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/oracles_scalar/ft_eval.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"

#include "test_plonk_component.hpp"
#include "../proof_data.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_ft_eval_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_ft_eval_test) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 10;
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
    constexpr static const std::size_t srs_len = 1;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;

    using component_type = zk::components::
        ft_eval<ArithmetizationType, curve_type, kimchi_params, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof();

    typename BlueprintFieldType::value_type omega_value =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui_modular256;
    std::size_t domain_size_value = 512;

    std::vector<BlueprintFieldType::value_type> shifts = {
        0x0000000000000000000000000000000000000000000000000000000000000001_cppui_modular256,
        0x00B9CDC8FD0BD4B27E2A74AF7AEBD5734D52D75BDF85EBF1CAD03413E914A2E3_cppui_modular256,
        0x0033BFCF8112720332825BD83D44D92CADC0C30466E8102C419C30FA2665695A_cppui_modular256,
        0x0087F4BB29954E16960F2DE3A1FA5AC7B62146DB348C7C9F0E8BF10B2C8E8411_cppui_modular256,
        0x00EC71373B9F6CF15ED1949647365DB60B2E26C3A8ABBA5BB06BF23E9DBE5893_cppui_modular256,
        0x00F39197CC4C55084C68D31F64F1A172406B585CB86445F00C248C721C496D10_cppui_modular256,
        0x00B8DD039799DBEE12D2E6A4299A83E067353C0143C5DFD203190C239159EEA3_cppui_modular256,
    };
    typename BlueprintFieldType::value_type zeta_value =
        0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui_modular256;

    typename BlueprintFieldType::value_type joint_combiner_value = 0;
    typename BlueprintFieldType::value_type beta_value = 0x000000000000000000000000000000005D27C70754796C79C9D9958673CF2ABA_cppui_modular256;
    typename BlueprintFieldType::value_type gamma_value = 0x00000000000000000000000000000000C2278ADB337FA07CDFB689C4651FFD6D_cppui_modular256;
    typename BlueprintFieldType::value_type alpha_value =
        0x322D5D64C86AFB168AC57D2D8AB3512647B4802C8DC4DE07DB2C51E094C4D9B7_cppui_modular256;

    std::array<std::array<BlueprintFieldType::value_type, witness_columns>, 2> w = {{
        {{ 0x0C2F522FB163AE4A8D2890C57ABF95E55EF7DDD27A928EFAD0D3FA447D40BC29_cppui_modular256,
        0x3F0169364239FF2352BFFEF6D2A206A6DC8FAA526C51EB51FC7610F6E73DFAE5_cppui_modular256,
        0x2BCBED001BA14933A1766C68E09BF19C133AB20B87A9D0DB68321A99C4C7A157_cppui_modular256,
        0x1430DC77EBF0048A4E26DDB817DD34D3F253AA9894C7D442B8BC06C7683D0188_cppui_modular256,
        0x3B79EBE49FAEF6F123C168CF484296A84186EF1FB9FFFA528B0AAC0761F535AD_cppui_modular256,
        0x16C6D43CFFB252215D05E1A05DBA2EEAADB3FAAF88B8AABDBD4E8860B9623530_cppui_modular256,
        0x1C0801C94EA28AAD68CEA9C9524106D39DC1A3491435A23D35EEBE56DB3AB116_cppui_modular256,
        0x21545E083F1282D939751D5E0D4EF173C7528C9E38349FE5E02BAB4686B542D4_cppui_modular256,
        0x2E8F53F919EBB22022424A175A051F6FBDB2B57E06E1AC8A8201FBDD02CEE2FD_cppui_modular256,
        0x1B5A53763A06BFAF8BAAF566FE885CD31355B2AC4F0F04B13F05610DE1EBAB5E_cppui_modular256,
        0x212CC53B694BA1B3ED2D6C514B97325D62BF301F18E76B7DF94F04B7875C7E64_cppui_modular256,
        0x22C1E6932B0336B13262867483DEE4C6B8E798C24F4245051254A64C61EAC604_cppui_modular256,
        0x356428F289E597185A60ED494351FF93B5802480DC375E4B2C6ECAB816B69524_cppui_modular256,
        0x08066B51E8C7F77F825F541E02C51A608FD217435FDF7E75AD5BBE36CB826443_cppui_modular256,
        0x1AA8ADB147AA57E6AA5DBAF2C238352D8C6AA301ECD497BBC775E2A2804E3363_cppui_modular256,}},

        {{0x144FF7F30B8C75C60E63614EA792F9A41E41C2DBE40F816A602160960C071F56_cppui_modular256,
        0x114768369E43EA7A13DE72AC855AE7D31DC52B34EB45BB96EA1BDFF54FEC4AB8_cppui_modular256,
        0x006259A5F4A9A82296077396D476F9E59392BDDA93E63B9A582EF9BBA452A7A2_cppui_modular256,
        0x3F9EBB3D514729A24B0C87FB434FC043F48195FA45E510BA5817F0ED05DED76B_cppui_modular256,
        0x06F0CA9962E207949F85C22ADCBE8F27E632D14B843F2C65E264752B6100049E_cppui_modular256,
        0x3885B6A574C4B6B89867EE499534E0F4937C7D71BA724A857F5E7F797059E879_cppui_modular256,
        0x0554E97666ABA1659D7D107E3F709F546625481B1A5684BE24EFE9B3CBBC300F_cppui_modular256,
        0x06C748D2C049B08C50633EBF7F7A0C68A03677CE382BF6697B7D285F30215616_cppui_modular256,
        0x0B252004A6768951624E56F1D98B1DDB006B2284FE1C08B258D95B92BF40266F_cppui_modular256,
        0x029236F173E5278B30CB9DAD8C87CEDE865AD1293B9BBF991F1743E8D1FD6638_cppui_modular256,
        0x28C63DB702FFC629457818259603A154886B11D1D1FB7065037F51212E5BE2D3_cppui_modular256,
        0x0219DC4D947F1109C90CD6C0112559A5D04528C2B264062A98DC5E7BBF85F269_cppui_modular256,
        0x246CB73F3BB0A9AC5FA65DED8A1617E0CB8231146F0DF67467ED5E85242DF2B6_cppui_modular256,
        0x06BF9230E2E2424EF63FE51B0306D61BA478A06A226AEDA29DD12DA188D5F302_cppui_modular256,
        0x29126D228A13DAF18CD96C487BF794569FB5A8BBDF14DDEC6CE22DAAED7DF34F_cppui_modular256}},
    }};

    std::array<std::array<BlueprintFieldType::value_type, perm_size - 1>, 2> s = {{
        {{0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui_modular256,
        0x05EDDC1E6C268DF398F068F06C51794D6F672E27FB800DFF6C5C35E5C3D84207_cppui_modular256,
        0x1B03A1DBEA987367FDEF97CC27F7441C4845E93AD1583167DA4A1A9CCFFB1E71_cppui_modular256,
        0x11347E33DF1631D59D66F6149D99DD22FD23B185D7D89CFE0909877C494D7916_cppui_modular256,
        0x0E1372B72364C37883171F80BC89F2AC7043464C8C30E1D2B5D94105035A6C6E_cppui_modular256,
        0x336A5683971A09A68D33D77B41947F8CAFFE3923190B51D443E515761A32889B_cppui_modular256,}},

        {{0x069DE7D0EBB1985B05DAB9E13348C12530D374BAD474C76C4AB9FAC8EB557332_cppui_modular256,
        0x177B2B5F39976BE667F5D6768480F1555F52395613AF100529C99844DA28DCC9_cppui_modular256,
        0x2941C2A82AC0067D3DD6A2C47EDD675D5B7BA071414A8324BA4CFAA1816B163F_cppui_modular256,
        0x05EA2B93EF3D2CD3E8DDDA175F2446A8390E35219DFBA39111C8CDBFA3038FCE_cppui_modular256,
        0x15C6FB1ACD775DF5E860906CDDF37C4E6B82CDC1A67F02F129DEAE98A11620D6_cppui_modular256,
        0x338D629CA1F64B37674CA7B5AF91015CA50A5D335E7076E25D9F4C230C99395D_cppui_modular256,}},
    }};

    std::array<BlueprintFieldType::value_type, 2> z = {
        0x1480D3E4FD095CEC3688F88B105EE6F2365DCFAAA28CCB6B87DAB7E71E58010B_cppui_modular256,
        0x1635A182C3B5623D5E7CF31D244F389FB478B0612B27937A39D48B473DB68931_cppui_modular256,
    };

    typename BlueprintFieldType::value_type expected_result = 0x0C5FFA9CCCAB64B985EB4467CE3933E6F4BFF202AEA53ACD4E27C0C6BBE902B2_cppui_modular256;



    std::vector<typename BlueprintFieldType::value_type> public_input = {};

    constexpr const std::size_t alpha_powers_n = index_terms_list::alpha_powers_n;
    std::array<var, alpha_powers_n> alpha_powers;
    for (std::size_t i = 0; i < alpha_powers_n; i++) {
        public_input.push_back(power(alpha_value, i));
        alpha_powers[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    public_input.push_back(beta_value);
    var beta(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_value);
    var gamma(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_value);
    var joint_combiner(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_value);
    var omega(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_value);
    var zeta(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_value.pow(domain_size_value));
    var zeta_n(0, public_input.size() - 1, false, var::column_type::public_input);

    std::array<var, 2> public_eval;

    verifier_index.omega = omega;
    verifier_index.domain_size = domain_size_value;

    for (std::size_t i = 0; i < shifts.size(); i++) {
        public_input.push_back(shifts[i]);
        verifier_index.shift[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    std::array<zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>, 2> evals;

    for (std::size_t i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < witness_columns; j++) {
            public_input.push_back(w[i][j]);
            evals[i].w[j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
        }

        for (std::size_t j = 0; j < perm_size; j++) {
            public_input.push_back(s[i][j]);
            evals[i].s[j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
        }

        public_input.push_back(z[i]);
        evals[i].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    typename component_type::params_type params = {verifier_index,  alpha_powers,
                                                   evals, gamma,      beta,
                                                   zeta,  zeta_n,     joint_combiner,
                                                   public_eval};

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        params, public_input, result_check);
}

BOOST_AUTO_TEST_SUITE_END()