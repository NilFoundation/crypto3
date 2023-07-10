//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_auxiliary_transcript_test

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
#include <../test/verifiers/kimchi/sponge/aux_transcript_fq.hpp>

#include "test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_transcript_0) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 17;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;

    constexpr size_t num_absorb = 15; 
    constexpr size_t num_challenges = 1;        //works
    constexpr size_t num_challenges_fq = 0;     //works
    constexpr bool digest = false;               //works
    using component_type = zk::components::aux_fq<num_absorb, num_challenges, num_challenges_fq, digest, ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    
    std::vector<var> input_fr;
    std::vector<std::array<var, 2>> input_g = {{var(0, 0, false, var::column_type::public_input),
            var(0, 1, false, var::column_type::public_input)}, 
            {var(0, 2, false, var::column_type::public_input),
            var(0, 3, false, var::column_type::public_input)}, 
            {var(0, 4, false, var::column_type::public_input),
            var(0, 5, false, var::column_type::public_input)}, 
            {var(0, 6, false, var::column_type::public_input),
            var(0, 7, false, var::column_type::public_input)}, 
            {var(0, 8, false, var::column_type::public_input),
            var(0, 9, false, var::column_type::public_input)}, 
            {var(0, 10, false, var::column_type::public_input),
            var(0, 11, false, var::column_type::public_input)}, 
            {var(0, 12, false, var::column_type::public_input),
            var(0, 13, false, var::column_type::public_input)}, 
            {var(0, 14, false, var::column_type::public_input),
            var(0, 15, false, var::column_type::public_input)}, 
            {var(0, 16, false, var::column_type::public_input),
            var(0, 17, false, var::column_type::public_input)}, 
            {var(0, 18, false, var::column_type::public_input),
            var(0, 19, false, var::column_type::public_input)}, 
            {var(0, 20, false, var::column_type::public_input),
            var(0, 21, false, var::column_type::public_input)}, 
            {var(0, 22, false, var::column_type::public_input),
            var(0, 23, false, var::column_type::public_input)}, 
            {var(0, 24, false, var::column_type::public_input),
            var(0, 25, false, var::column_type::public_input)}, 
            {var(0, 26, false, var::column_type::public_input),
            var(0, 27, false, var::column_type::public_input)}, 
            {var(0, 28, false, var::column_type::public_input),
            var(0, 29, false, var::column_type::public_input)}};
    typename component_type::params_type params = {input_fr, input_g};
    std::vector<typename BlueprintFieldType::value_type> public_input = {0x1CF10D1482EB88632AEFED15C16082007B38DDC528626195CF6B040E2C7D5914_cppui256,
            0x15A406A92FA16DB6E24D125C8EC5365D76DD8BB188106C0063BA9EC51E0FB8E7_cppui256, 
            0x3B38AC47170B2DB158AE7C02E939B2877139040D240171F6A6BB01183902566E_cppui256,
            0x05AAC7FD92471BBFF23D5E4F9AD0B64783467A4809940FEBB7BD6C91A9E9E1C0_cppui256, 
            0x281BD2B891CF0795B1439B3AB149ED2A535B8E08C4430112D7D4BF53F3789BEF_cppui256,
            0x10B2FA452CAC5D11CC8040D5DD504222A2621FC378EFD7D08A01BAB3A3DE28DF_cppui256, 
            0x0158FEA0E6586A75F36FB621E9C9FC7A38970812F0F1753D3BB716655E3B9D79_cppui256,
            0x2A9688F370DCC43130D38AB7AD2B3FF2A925791F587B55AD138B1F067E874C59_cppui256, 
            0x0CA7898337AB528838EAD23D7CBCD4861F1E5E2E5D3B1BD3B733A832C7931547_cppui256,
            0x351C82EC1D20E977ABFC632BBA2330AF61270A00BC2D32B6F2E1DA93AA0D51F1_cppui256, 
            0x00DCE7DC20642A850002731F9B3820327CF5856B1D8C3B0EE6BD7BC03BC85FFD_cppui256,
            0x3B1BCBA06B0D33F08123EDD6DF725CC1F8CD2213EA867FF4020C2D18619BB2DB_cppui256, 
            0x0F7C2FF92D8F0776629F87BBF25702CEAA45B1893617F7C9AC10AACB080B6E10_cppui256,
            0x16E7207D6596C7FAFF46FB335E14DC57E08E150AB7F692607F3B8DCC9E6CDA93_cppui256, 
            0x2CD748E8C8806196ABE34DF032864491CADCF205AF70CB9152507BD16B912BEC_cppui256,
            0x2219EC3C1873373A6717E7BFA24827AD89BF949B0F240D7B9D8981C2006E400F_cppui256, 
            0x027E878BD478FC5DE36CA783CB60297C5F75CB638C71615A04714C52E9B15E8E_cppui256,
            0x2CCE580022C7D44E72BA8E7E608C3733A3F3EDC0304566097C07D6CCA172A1B4_cppui256, 
            0x0DC7C8FE3A9007F09283D29C5BE99AACEB9DA6996CD691BBAC5D075BDD6DA223_cppui256,
            0x1FA4B95451090B8A36D503BFDBF086D4462745626B4BA4490AF42A7A6B5FD449_cppui256, 
            0x20254A64C61A3C1882EC3E9FCA0ABAE814B0EB0477C3396E562C1006054347F3_cppui256,
            0x23CDCBDE9DCBD33AD86BF48181B1616FC76D24A18711A3953D184E772D936418_cppui256, 
            0x00DB22BCFC9A1D1A10A53716A7E7D4022DBF101B8767B68E78837CB8263BE097_cppui256,
            0x3E283D2F0D90CAC87B3FCD95E7A8933FB2B2B43EF07FA577CA566527481AB6C9_cppui256, 
            0x0D24814B6FE1C8C42FC05834B95212E473B76C8B9588D1272BFAE8FA0E2B9384_cppui256,
            0x11C75275709440AC01B74C4E64E2606F7826294F868F6B0265008E758C148369_cppui256, 
            0x007997CB753B919B586243FCAF6E5886676F180C2220BAC055AE9739CA4A1B4B_cppui256,
            0x166859AE2ECE3520D33C2D146F6DBCFC819779C288E9D81C3F7369DF5642EF31_cppui256, 
            0x04E774B3DE1A78D6C9408D7B10D9E4614FC8AE4DFE4BFE6762278EE72BB9E25D_cppui256,
            0x178AC19F836752BAF356D9E9C3C35470F27A52C16B7572EEF2C61A43B4D0499B_cppui256};
    typename BlueprintFieldType::value_type result = 0x0000000000000000000000000000000006906F18EE1C02C944C3186D54A8D03E_cppui256;
    auto result_check = [&result](AssignmentType &assignment, 
        component_type::result_type &real_res) {
        assert(result == assignment.var_value(real_res.squeezed));
    };
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "kimchi transcript_fq: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_transcript_1) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 20;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;

    constexpr size_t num_absorb = 0; 
    constexpr size_t num_challenges = 0;        //works
    constexpr size_t num_challenges_fq = 0;     //works
    constexpr bool digest = true;              //works
    using component_type = zk::components::aux_fq<num_absorb, num_challenges, num_challenges_fq, digest, ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    
    std::vector<var> input_fr;
    std::vector<std::array<var, 2>> input_g;
    typename component_type::params_type params = {input_fr, input_g};
    std::vector<typename BlueprintFieldType::value_type> public_input;
    typename BlueprintFieldType::value_type result = 0x3A3374A061464EC0AAC7E0FF04346926C579D542F9D205A670CE4C18C004E5C1_cppui256;
    auto result_check = [&result](AssignmentType &assignment, 
        component_type::result_type &real_res) {
        assert(result == assignment.var_value(real_res.squeezed));
    };
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "kimchi transcript_fq: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_transcript_2) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 20;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;

    constexpr size_t num_absorb = 0; 
    constexpr size_t num_challenges = 3;        //works
    constexpr size_t num_challenges_fq = 0;     //works
    constexpr bool digest = false;               //works
    using component_type = zk::components::aux_fq<num_absorb, num_challenges, num_challenges_fq, digest, ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    
    std::vector<var> input_fr;
    std::vector<std::array<var, 2>> input_g;
    typename component_type::params_type params = {input_fr, input_g};
    std::vector<typename BlueprintFieldType::value_type> public_input = 
        {};
    typename BlueprintFieldType::value_type result = 0x00000000000000000000000000000000AFEB6EEE7D0BD8B45C33CA8DDFC9DFE9_cppui256;
    auto result_check = [&result](AssignmentType &assignment, 
        component_type::result_type &real_res) {
        assert(result == assignment.var_value(real_res.squeezed));
    };
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "kimchi transcript_fq: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_transcript_3) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 20;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;

    constexpr size_t num_absorb = 1; 
    constexpr size_t num_challenges = 1;        //works
    constexpr size_t num_challenges_fq = 0;     //works
    constexpr bool digest = false;              //works
    using component_type = zk::components::aux_fq<num_absorb, num_challenges, num_challenges_fq, digest, ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
	
    
    std::vector<typename BlueprintFieldType::value_type> public_input;
    typename BlueprintFieldType::value_type result = 0x000000000000000000000000000000003972C78FB41D347300A463E54826F2AB_cppui256;
    std::vector<var> input_fr;
    std::vector<std::array<var, 2>> input_g;

    public_input.push_back(1);
    input_fr.push_back(var(0, 0, false, var::column_type::public_input));

    typename component_type::params_type params = {input_fr, input_g};

    auto result_check = [&result](AssignmentType &assignment, 
        component_type::result_type &real_res) {
        assert(result == assignment.var_value(real_res.squeezed));
    };
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "kimchi transcript_fq: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
