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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_verifier_scalar_test

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
#include <nil/blueprint/components/systems/snark/plonk/kimchi/batch_verify_scalar_field.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/binding.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>

#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"

#include "test_plonk_component.hpp"
#include "proof_data.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_batch_verifier_scalar_field_test_suite)

template<typename CurveType, typename BlueprintFieldType, typename KimchiParamsType, std::size_t EvelRounds>
void prepare_proof(zk::snark::pickles_proof<CurveType> &original_proof,
                   zk::components::kimchi_proof_scalar<BlueprintFieldType, KimchiParamsType, EvelRounds> &circuit_proof,
                   std::vector<typename BlueprintFieldType::value_type> &public_input) {
    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    // eval_proofs
    for (std::size_t point_idx = 0; point_idx < 2; point_idx++) {
        // w
        for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
            public_input.push_back(original_proof.evals[point_idx].w[i]);
            circuit_proof.proof_evals[point_idx].w[i] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        // z
        public_input.push_back(original_proof.evals[point_idx].z);
        circuit_proof.proof_evals[point_idx].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // s
        for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
            public_input.push_back(original_proof.evals[point_idx].s[i]);
            circuit_proof.proof_evals[point_idx].s[i] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        // lookup
        if (KimchiParamsType::use_lookup) {
            // TODO
        }
        // generic_selector
        public_input.push_back(original_proof.evals[point_idx].generic_selector);
        circuit_proof.proof_evals[point_idx].generic_selector =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        // poseidon_selector
        public_input.push_back(original_proof.evals[point_idx].poseidon_selector);
        circuit_proof.proof_evals[point_idx].poseidon_selector =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    // ft_eval
    public_input.push_back(algebra::random_element<BlueprintFieldType>());
    circuit_proof.ft_eval = var(0, public_input.size() - 1, false, var::column_type::public_input);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_batch_verifier_scalar_field_test_suite) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
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
    constexpr static std::size_t eval_rounds = 3;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr std::size_t srs_len = 5;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
    typename BlueprintFieldType::value_type zeta =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    typename BlueprintFieldType::value_type omega =
        0x1B1A85952300603BBF8DD3068424B64608658ACBB72CA7D2BB9694ADFA504418_cppui256;
    // verifier_index.zkpm = {0x2C46205451F6C3BBEA4BABACBEE609ECF1039A903C42BFF639EDC5BA33356332_cppui256,
    //     0x1764D9CB4C64EBA9A150920807637D458919CB6948821F4D15EB1994EADF9CE3_cppui256,
    //     0x0140117C8BBC4CE4644A58F7007148577782213065BB9699BF5C391FBE1B3E6D_cppui256,
    //     0x0000000000000000000000000000000000000000000000000000000000000001_cppui256};
    std::size_t domain_size = 128;
    verifier_index.domain_size = domain_size;
    verifier_index.omega = var(0, 6, false, var::column_type::public_input);

    constexpr std::size_t batch_size = 2;

    using component_type = zk::components::batch_verify_scalar_field<ArithmetizationType,
                                                                     curve_type,
                                                                     kimchi_params,
                                                                     commitment_params,
                                                                     batch_size,
                                                                     0,
                                                                     1,
                                                                     2,
                                                                     3,
                                                                     4,
                                                                     5,
                                                                     6,
                                                                     7,
                                                                     8,
                                                                     9,
                                                                     10,
                                                                     11,
                                                                     12,
                                                                     13,
                                                                     14>;

    zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof();

    typename BlueprintFieldType::value_type joint_combiner = 0;
    typename BlueprintFieldType::value_type beta = 0;
    typename BlueprintFieldType::value_type gamma = 0;
    typename BlueprintFieldType::value_type alpha =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type fq_digest =
        0x01D4E77CCD66755BDDFDBB6E4E8D8D17A6708B9CB56654D12070BD7BF4A5B33B_cppui256;

    zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds> proof;
    std::array<var, eval_rounds> challenges;

    std::vector<typename BlueprintFieldType::value_type> public_input = {};

    std::array<
        zk::components::
            batch_evaluation_proof_scalar<BlueprintFieldType, ArithmetizationType, kimchi_params, commitment_params>,
        batch_size>
        batches;

    for (std::size_t i = 0; i < batch_size; i++) {
        typename BlueprintFieldType::value_type cip = 12;
        public_input.push_back(cip);
        batches[i].cip = var(0, public_input.size() - 1, false, var::column_type::public_input);

        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_sponge_output
            fq_output;

        std::array<var, eval_rounds> challenges;
        for (std::size_t j = 0; j < eval_rounds; j++) {
            public_input.emplace_back(10);
            challenges[j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        fq_output.challenges = challenges;

        // joint_combiner
        public_input.push_back(algebra::random_element<BlueprintFieldType>());
        fq_output.joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // beta
        public_input.push_back(algebra::random_element<BlueprintFieldType>());
        fq_output.beta = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // gamma
        public_input.push_back(algebra::random_element<BlueprintFieldType>());
        fq_output.gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // alpha
        public_input.push_back(algebra::random_element<BlueprintFieldType>());
        fq_output.alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // zeta
        public_input.push_back(algebra::random_element<BlueprintFieldType>());
        fq_output.zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // fq_digest
        public_input.push_back(algebra::random_element<BlueprintFieldType>());
        fq_output.fq_digest = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // c
        public_input.emplace_back(250);
        fq_output.c = var(0, public_input.size() - 1, false, var::column_type::public_input);

        batches[i].fq_output = fq_output;

        public_input.push_back(zeta);
        public_input.push_back(zeta * omega);
        batches[i].eval_points = {var(0, public_input.size() - 2, false, var::column_type::public_input),
                                  var(0, public_input.size() - 1, false, var::column_type::public_input)};

        public_input.push_back(algebra::random_element<BlueprintFieldType>());
        batches[i].r = var(0, public_input.size() - 1, false, var::column_type::public_input);

        public_input.push_back(algebra::random_element<BlueprintFieldType>());
        public_input.push_back(algebra::random_element<BlueprintFieldType>());
        batches[i].opening = {var(0, public_input.size() - 2, false, var::column_type::public_input),
                              var(0, public_input.size() - 1, false, var::column_type::public_input)};
    }

    typename component_type::params_type params = {batches};

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
}

BOOST_AUTO_TEST_SUITE_END()