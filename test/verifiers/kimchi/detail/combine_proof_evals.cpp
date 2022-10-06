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

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/combine_proof_evals.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"
#include "verifiers/kimchi/index_terms_instances/chacha_test.hpp"

#include "test_plonk_component.hpp"
#include "../proof_data.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_combine_proof_evals_test_suite)

template<typename CurveType, typename BlueprintFieldType, typename KimchiParamsType, std::size_t EvelRounds>
void prepare_proof(zk::snark::pickles_proof<CurveType> &original_proof,
                   zk::components::kimchi_proof_scalar<BlueprintFieldType, KimchiParamsType, EvelRounds> &circuit_proof,
                   std::vector<typename BlueprintFieldType::value_type> &public_input) {
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

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
            for (std::size_t i = 0; i < KimchiParamsType::circuit_params::lookup_columns; i++) {
                public_input.push_back(original_proof.evals[point_idx].lookup.sorted[i]);
                circuit_proof.proof_evals[point_idx].lookup.sorted[i] =
                    var(0, public_input.size() - 1, false, var::column_type::public_input);
            }

            public_input.push_back(original_proof.evals[point_idx].lookup.aggreg);
            circuit_proof.proof_evals[point_idx].lookup.aggreg = 
                var(0, public_input.size() - 1, false, var::column_type::public_input);

            public_input.push_back(original_proof.evals[point_idx].lookup.table);
            circuit_proof.proof_evals[point_idx].lookup.table = 
                var(0, public_input.size() - 1, false, var::column_type::public_input);

            if (KimchiParamsType::circuit_params::lookup_runtime) {
                public_input.push_back(original_proof.evals[point_idx].lookup.runtime);
                circuit_proof.proof_evals[point_idx].lookup.runtime = 
                    var(0, public_input.size() - 1, false, var::column_type::public_input);
            }
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
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_combine_proof_evals_test) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 10;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;
    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;
    constexpr static std::size_t srs_len = 10;

    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_chacha_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    using component_type = zk::components::combine_proof_evals<ArithmetizationType, kimchi_params, 0, 1, 2, 3, 4, 5, 6,
                                                               7, 8, 9, 10, 11, 12, 13, 14>;

    zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof_chacha();

    typename BlueprintFieldType::value_type zeta_value =
        0x3CE960ABCAC273BBEEBA92D1EF87514B51187BFE5E8797B5DE97B01FF7C64484_cppui256;

    std::vector<typename BlueprintFieldType::value_type> public_input = {zeta_value, 1, 0};

    var zeta(0, 0, false, var::column_type::public_input);
    var one(0, 1, false, var::column_type::public_input);
    var zero(0, 2, false, var::column_type::public_input);

    zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds> proof;

    prepare_proof<curve_type, BlueprintFieldType, kimchi_params, eval_rounds>(kimchi_proof, proof, public_input);

    typename component_type::params_type params = {proof.proof_evals[0], zeta};

    auto result_check = [&kimchi_proof, &zeta_value](AssignmentType &assignment,
                                                     component_type::result_type &real_res) {
        // w
        for (std::size_t i = 0; i < kimchi_proof.evals[0].w.size(); i++) {
            assert(kimchi_proof.evals[0].w[i] * zeta_value == assignment.var_value(real_res.output.w[i]));
        }
        // z
        assert(kimchi_proof.evals[0].z * zeta_value == assignment.var_value(real_res.output.z));
        // s
        for (std::size_t i = 0; i < kimchi_proof.evals[0].s.size(); i++) {
            assert(kimchi_proof.evals[0].s[i] * zeta_value == assignment.var_value(real_res.output.s[i]));
        }
        // lookup
        if (kimchi_params::use_lookup) {
            for (std::size_t i = 0; i < kimchi_proof.evals[0].lookup.sorted.size(); i++) {
                assert(kimchi_proof.evals[0].lookup.sorted[i] * zeta_value == assignment.var_value(real_res.output.lookup.sorted[i]));
            }
            assert(kimchi_proof.evals[0].lookup.aggreg * zeta_value == assignment.var_value(real_res.output.lookup.aggreg));
            assert(kimchi_proof.evals[0].lookup.table * zeta_value == assignment.var_value(real_res.output.lookup.table));
            if (kimchi_params::circuit_params::lookup_runtime) {
                assert(kimchi_proof.evals[0].lookup.runtime * zeta_value == assignment.var_value(real_res.output.lookup.runtime));
            }
        }
        // generic_selector
        assert(kimchi_proof.evals[0].generic_selector * zeta_value == assignment.var_value(real_res.output.generic_selector));
        // poseidon_selector
        assert(kimchi_proof.evals[0].poseidon_selector * zeta_value == assignment.var_value(real_res.output.poseidon_selector));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_SUITE_END()