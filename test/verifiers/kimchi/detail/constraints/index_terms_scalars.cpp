//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_detail_index_terms_scalar_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/constraints/index_terms_scalars.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/binding.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>

#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/lookup_test.hpp"

#include "test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_detail_index_terms_scalar_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_index_terms_scalar_ec_test_suite) {

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
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
    constexpr static const std::size_t prev_chal_size = 0;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    using component_type =
        zk::components::index_terms_scalars<ArithmetizationType, kimchi_params, 0, 1, 2,
                                             3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    std::array<typename BlueprintFieldType::value_type, witness_columns>
        eval0_w = {
            0x0C2F522FB163AE4A8D2890C57ABF95E55EF7DDD27A928EFAD0D3FA447D40BC29_cppui256,
            0x3F0169364239FF2352BFFEF6D2A206A6DC8FAA526C51EB51FC7610F6E73DFAE5_cppui256,
            0x2BCBED001BA14933A1766C68E09BF19C133AB20B87A9D0DB68321A99C4C7A157_cppui256,
            0x1430DC77EBF0048A4E26DDB817DD34D3F253AA9894C7D442B8BC06C7683D0188_cppui256,
            0x3B79EBE49FAEF6F123C168CF484296A84186EF1FB9FFFA528B0AAC0761F535AD_cppui256,
            0x16C6D43CFFB252215D05E1A05DBA2EEAADB3FAAF88B8AABDBD4E8860B9623530_cppui256,
            0x1C0801C94EA28AAD68CEA9C9524106D39DC1A3491435A23D35EEBE56DB3AB116_cppui256,
            0x21545E083F1282D939751D5E0D4EF173C7528C9E38349FE5E02BAB4686B542D4_cppui256,
            0x2E8F53F919EBB22022424A175A051F6FBDB2B57E06E1AC8A8201FBDD02CEE2FD_cppui256,
            0x1B5A53763A06BFAF8BAAF566FE885CD31355B2AC4F0F04B13F05610DE1EBAB5E_cppui256,
            0x212CC53B694BA1B3ED2D6C514B97325D62BF301F18E76B7DF94F04B7875C7E64_cppui256,
            0x22C1E6932B0336B13262867483DEE4C6B8E798C24F4245051254A64C61EAC604_cppui256,
            0x356428F289E597185A60ED494351FF93B5802480DC375E4B2C6ECAB816B69524_cppui256,
            0x08066B51E8C7F77F825F541E02C51A608FD217435FDF7E75AD5BBE36CB826443_cppui256,
            0x1AA8ADB147AA57E6AA5DBAF2C238352D8C6AA301ECD497BBC775E2A2804E3363_cppui256
        };
    
    typename BlueprintFieldType::value_type eval0_z = 0x1480D3E4FD095CEC3688F88B105EE6F2365DCFAAA28CCB6B87DAB7E71E58010B_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval0_s = {
        0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256,
        0x05EDDC1E6C268DF398F068F06C51794D6F672E27FB800DFF6C5C35E5C3D84207_cppui256,
        0x1B03A1DBEA987367FDEF97CC27F7441C4845E93AD1583167DA4A1A9CCFFB1E71_cppui256,
        0x11347E33DF1631D59D66F6149D99DD22FD23B185D7D89CFE0909877C494D7916_cppui256,
        0x0E1372B72364C37883171F80BC89F2AC7043464C8C30E1D2B5D94105035A6C6E_cppui256,
        0x336A5683971A09A68D33D77B41947F8CAFFE3923190B51D443E515761A32889B_cppui256
    };

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
        0x322D5D64C86AFB168AC57D2D8AB3512647B4802C8DC4DE07DB2C51E094C4D9B7_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x000000000000000000000000000000005D27C70754796C79C9D9958673CF2ABA_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x00000000000000000000000000000000C2278ADB337FA07CDFB689C4651FFD6D_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256;

    typename BlueprintFieldType::value_type omega_val = 
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;


    std::array<typename BlueprintFieldType::value_type, 19> expected_result = {
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x017EEEF7695889AFB5311D7B36B31455AFF02B103BDA9BABF5BC29107B8F3AB7_cppui256, // varBaseMul 
        0x259D030170979C4754D0CEBF9E6AE529563BEB3A27C7003F57CCD4F80F875E4B_cppui256, // endoMul
        0x0F297E2FA4E61DD377911C6B14C03F5CABC1114813C5D5C4CDCBDFBE84C526DB_cppui256, // endoMulScalar
        0x0EF5278F0AD55CDE149D4E396A01E9B72A0D73FB4CF033C570B1B7E0C24C5FCE_cppui256, // completeAdd
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

        evals[i].poseidon_selector = zero;
        evals[i].generic_selector = zero;
    }

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    var joint_combiner = zero;

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    typename component_type::params_type params = { 
        zeta, alpha, beta, gamma, joint_combiner,
        evals, omega, domain_size};

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        for (std::size_t i = 0; i < expected_result.size(); ++i) {
            assert(expected_result[i] == assignment.var_value(real_res.output[i]));
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_index_terms_scalar_lookup_test_suite) {

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
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
    constexpr static const std::size_t prev_chal_size = 0;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_lookup_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    using component_type =
        zk::components::index_terms_scalars<ArithmetizationType, kimchi_params, 0, 1, 2,
                                             3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    std::array<typename BlueprintFieldType::value_type, witness_columns>
        eval0_w = {
            0x333AEBFBB633C5DAC78A664A97F382E44C7A3BA4129409B01465FDB51FBA6159_cppui256,
            0x229705503FFBD3EA924B51FCE0710B063063B9554809B21630FA2265C608A930_cppui256,
            0x13D016250A5B9CE89D5E6E22E0380EAC6C61DE4DDE38FC84EB8A08B1C8C4AD3C_cppui256,
            0x32117E44C1F03F26F3481897755A9422E1280E4A9D21E5D00FCC436323657D7A_cppui256,
            0x0F68E895335D3BBCE935310D52AA1406C20558F286D06CE3FDF70B9E74AF2877_cppui256,
            0x19E176931CC0BB2D6CA0CFF8CC6A7C02CCD0137FA0F443CEA01C0F69E727E2B1_cppui256,
            0x2E9559BD9D6C15B5632A9E5E0BB2C4FC5BFFD29C2B41366AE197545C5094B357_cppui256,
            0x1F81313571BFF50D79E013B3F622BE5FC78724A8546F77C75B68CA780015E2C6_cppui256,
            0x25D45FAB67F88E14B7EC510C28297DBA94DC373AA850AB17C49437DA44B53E68_cppui256,
            0x2C278E215E31271BF5F88E645A303D15623149CCFC31DE682DBFA53C89549A0A_cppui256,
            0x327ABC975469C0233404CBBC8C36FC702F865C5F501311B896EB129ECDF3F5AC_cppui256,
            0x38CDEB0D4AA2592A72110914BE3DBBCAFCDB6EF1A3F44509001680011293514E_cppui256,
            0x3F21198340DAF231B01D466CF0447B25CA308183F7D578596941ED635732ACF0_cppui256,
            0x057447F937138B38EE2983C5224B3A80753EFB1A4269B28E394029D89BD20891_cppui256,
            0x0BC7766F2D4C24402C35C11D5451F9DB42940DAC964AE5DEA26B973AE0716433_cppui256,
        };
    
    typename BlueprintFieldType::value_type eval0_z = 0x134EBAD0F9C35BE923C101FBDDE3E6223FE9688D939FD620137F2BA1473CEE2E_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval0_s = {
        0x38F09DAE5B20B0CE58B9146FA85FBD460B0560AC4A84C269A6B116B90CAD9930_cppui256,
        0x14D2BCE16FBE86ADC87964FCB51A1D5DE50D20EFE036FE5CD1AC1A3CA30F0CFE_cppui256,
        0x00EE6F2F707C48EB45BEB0B8DB361BBD7E965362E0CE8EF02A86C61942B6EC34_cppui256,
        0x21497448D1A0FE3B4066DAF2476EE883962B5ABF7FFEBB54F2AF2AECBE591846_cppui256,
        0x3BAA01F94DFF5E931CAC909968174CFF50EA6ED08377422EB5E56F5F43ADFCB2_cppui256,
        0x2EF00DA590D3C70C042C6A36B7C0FD4F359979E5325A1AA04EF3239D65944055_cppui256,
    };

    constexpr const std::size_t lookup_size = 4;
    std::array<typename BlueprintFieldType::value_type, lookup_size> eval0_lookup_sorted = {
        0x09BF9BB8DC4499B5E044B8F9725BD1F76D2B96D40E030CE45BFC8513C7878585_cppui256,
        0x392178C04F97404121297069CDD6C7D1CAD07541AC82B6055EE72CB44E312ECE_cppui256,
        0x22D44A9961BAEB007DE32FFDE0ACC05D545609F271F2C9994B309A96EE341689_cppui256,
        0x2101DB892E0BFF916221891846B5208F85DC8AFADF3CEF66EC40AA026D7E2616_cppui256,
    };

    typename BlueprintFieldType::value_type eval0_lookup_aggregated = 
        0x2491DCAD05BC2541E67009FD6430FD3E3F761F6777745636741FBE38BF40178A_cppui256;;    

    typename BlueprintFieldType::value_type eval0_lookup_table = 
        0x3061EA493FBB49E185D2C7B05A5F918B243FC5FF0BF157EE88C117C1C5FF250F_cppui256;

    std::array<typename BlueprintFieldType::value_type, witness_columns>
        eval1_w = {
            0x1E62E030CDBC0C7188D33E5CDF44CB9F627F51A218E31B3DE5DC042D3985933A_cppui256,
            0x35A92D4340842C373BAD02F6EB1EEA07DFEBD5F375AC8EBAFAE9FE39E1FE1C7D_cppui256,
            0x3371121F8357D809F17C1DD8A213D22316F2F17856750CFEBA7A4FBA8C88B2BF_cppui256,
            0x0E017A1556A517DFEE62C99B2676A0A6084213E8664A18BEAB37D0EF12057DB0_cppui256,
            0x3D09624DEA00B11359E51D17B08F5407A1EC500F074D015BF701B0AF6B3A4A1A_cppui256,
            0x14D9A308E0A2CAAE9570769666FBC6BFF2775CB2A19DEFA50F5974E5D9F476DB_cppui256,
            0x2A7D07B5B324E6C311C3CD5DAB4DAED7CEC8E18B0291EC789814FC16726D0F10_cppui256,
            0x28A9C3CF223D9F510AD33071132CA3554BDD14E05E541DD81E554C357E864CF6_cppui256,
            0x17D8769C9C06FD70F8D32E73F6049D93D11F72C5D34E44C1B17E48853F3D42EC_cppui256,
            0x0707296A15D05B90E6D32C76D8DC97D25661D0AB48486BAB44A744D4FFF438E2_cppui256,
            0x3635DC378F99B9B0D4D32A79BBB49210FDEAC78CC68F8BB070FD7211C0AB2ED9_cppui256,
            0x25648F05096317D0C2D3287C9E8C8C4F832D25723B89B29A04266E61816224CF_cppui256,
            0x149341D2832C75F0B0D3267F8164868E086F8357B083D983974F6AB142191AC5_cppui256,
            0x03C1F49FFCF5D4109ED32482643C80CC8DB1E13D257E006D2A78670102D010BB_cppui256,
            0x32F0A76D76BF32308CD3228547147B0B353AD81EA3C5207256CE943DC38706B2_cppui256,
        };
    
    typename BlueprintFieldType::value_type eval1_z = 0x3C6E48DF402AA8AD73AEE593E6A45E617A6FA5F0FD6537195830BDFAD5007FB2_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval1_s = {
        0x2FB75D341DB2B66FD0065443D9B82C300A41DC7634D6F22B42A202C7C6EF6CFC_cppui256,
        0x1BF54A529308426DC3223933D80FA71FD9D5D5BFE3FB24B003B0D136BCF81505_cppui256,
        0x0757119D804CFB7B01FDF885E9FC678171B8F91B10D9D04496074912E139823D_cppui256,
        0x3E0F44ACEC3F8EF9F2333B1DD953B283147266DFF7F74E0F63D79E305DA37165_cppui256,
        0x30E36F8F7BFA41EFD55E63F55DA4E1BDF91A7346B271550FD209678CEA1A8AC3_cppui256,
        0x381319F662909FA6C285987D1008BE056C3C31D19220AAADE93D92228C2A4B33_cppui256,
    };

    std::array<typename BlueprintFieldType::value_type, lookup_size> eval1_lookup_sorted = {
        0x0E825D8D5AC24EBC0C7AAD891B5F2AEC4A9880E98D318FB20580DCD7833A30B1_cppui256,
        0x30D59443C883D3A96862BB9AAA2066387D5CC76A14CF208817617FBB21F39AFB_cppui256,
        0x2B321B4F0969B1DEB9AFAD31F1E1CA18A45B1A9B4AE177613630EAD1184A35E1_cppui256,
        0x08DF00E4FA6F4A9261CCF816AF7792D42CEF4E7E6942C8DC3171A0002538DEB5_cppui256,
    };

    typename BlueprintFieldType::value_type eval1_lookup_aggregated = 
        0x297BAEF6E597DAB1C9D2694509368B8D3A5FE32AE7B2AF577633806DB48952A3_cppui256;    

    typename BlueprintFieldType::value_type eval1_lookup_table = 
        0x12A589E01D18A29D5D176B45C9EF899EF6ADDF3A6594EAD2461666E05876B2E9_cppui256;

    std::array<std::array<typename BlueprintFieldType::value_type, witness_columns>, 2> eval_w = {eval0_w, eval1_w};
    std::array<typename BlueprintFieldType::value_type, 2> eval_z = {eval0_z, eval1_z};
    std::array<std::array<typename BlueprintFieldType::value_type, perm_size>, 2> eval_s = {eval0_s, eval1_s};
    std::array<std::array<typename BlueprintFieldType::value_type, lookup_size>, 2> eval_lookup_sorted = {eval0_lookup_sorted, eval1_lookup_sorted};
    std::array<typename BlueprintFieldType::value_type, 2> eval_lookup_aggregated = {eval0_lookup_aggregated, eval1_lookup_aggregated};
    std::array<typename BlueprintFieldType::value_type, 2> eval_lookup_table = {eval0_lookup_table, eval1_lookup_table};


    typename BlueprintFieldType::value_type alpha_val =
        0x093707BDEAB062634AFCBC9251180B77691009161382D1638490414AD45A33BE_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000082A48F2CCDBC01E4F4ADB977A324D6F6_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x000000000000000000000000000000007F486CD9B2A0B5C2198305055395F920_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x38F09DAE5B20B0CE58B9146FA85FBD460B0560AC4A84C269A6B116B90CAD9930_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x38C743A28755C1E00F0771302FE6A07A2130C21884C1A7AF1800DD8FD9FC6547_cppui256;

    typename BlueprintFieldType::value_type omega_val = 
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;


    std::array<typename BlueprintFieldType::value_type, 20> expected_result = {
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x0000000000000000000000000000000000000000000000000000000000000000_cppui256,
        0x3C298FAAF54E18672778EBEBAC6157CEE2D95F16122B92D0BAAD88BB8C2E0E1C_cppui256, // varBaseMul 
        0x2C4C103BC45214A6E78FB9CF5E6F7B8980C36AE4A2455988028C3C907D8C7F08_cppui256, // endoMul
        0x18BDD6D3E3CFAEC53B93C6AD4B9B167FB44B5DFD1A92D34C93BBD1C9F713978D_cppui256, // endoMulScalar
        0x2B2CCD26ACF301C648598FDF4FE0DF29BBD189A233E5BFDEC169B4545F151046_cppui256, // completeAdd
        0x3D6B79823727C40A68B323E82437399AC3DB02009F7680E211415847A6A2DF53_cppui256, // lookup
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

        for (std::size_t j = 0; j < lookup_size; j++) {
            public_input.push_back(eval_lookup_sorted[i][j]);
            var lookup_sorted = var(0, public_input.size() - 1, false, var::column_type::public_input);
            evals[i].lookup.sorted[j] = lookup_sorted;
        }

        public_input.push_back(eval_lookup_aggregated[i]);
        var lookup_aggregated = var(0, public_input.size() - 1, false, var::column_type::public_input);
        evals[i].lookup.aggreg = lookup_aggregated;

        public_input.push_back(eval_lookup_table[i]);
        var lookup_table = var(0, public_input.size() - 1, false, var::column_type::public_input);
        evals[i].lookup.table = lookup_table;

        evals[i].poseidon_selector = zero;
        evals[i].generic_selector = zero;
    }

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    typename component_type::params_type params = { 
        zeta, alpha, beta, gamma, joint_combiner,
        evals, omega, domain_size};

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        for (std::size_t i = 0; i < expected_result.size(); ++i) {
            assert(expected_result[i] == assignment.var_value(real_res.output[i]));
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_SUITE_END()