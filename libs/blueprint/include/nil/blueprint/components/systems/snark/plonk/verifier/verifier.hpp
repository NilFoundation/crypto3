//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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
// @file Placeholder verifier circuit component
//---------------------------------------------------------------------------//

#ifndef BLUEPRINT_COMPONENTS_FLEXIBLE_VERIFIER_PLACEHOLDER_VERIFIER_HPP
#define BLUEPRINT_COMPONENTS_FLEXIBLE_VERIFIER_PLACEHOLDER_VERIFIER_HPP

#include <map>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/profiling.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/systems/snark/plonk/verifier/proof_wrapper.hpp>
#include <nil/blueprint/components/systems/snark/plonk/verifier/proof_input_type.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/poseidon.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/swap.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/constant_pow.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/colinear_checks.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/x_index.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename BlueprintFieldType, typename SrcParams>
            class plonk_flexible_verifier: public plonk_component<BlueprintFieldType>{
            public:
                using placeholder_info_type = nil::crypto3::zk::snark::placeholder_info<SrcParams>;
                using component_type =  plonk_component<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;
                using var = typename component_type::var;

                using poseidon_component_type = plonk_flexible_poseidon<BlueprintFieldType>;
                using swap_component_type = plonk_flexible_swap<BlueprintFieldType>;
                using colinear_checks_component_type = plonk_flexible_colinear_checks<BlueprintFieldType>;
                using constant_pow_component_type = plonk_flexible_constant_pow<BlueprintFieldType>;
                using x_index_component_type = plonk_flexible_x_index<BlueprintFieldType>;

                std::size_t rows_amount;
                std::size_t fri_params_r;
                std::size_t fri_params_lambda;
                value_type fri_omega;
                std::size_t fri_domain_size;
                std::size_t fri_initial_merkle_proof_size;
                placeholder_info_type placeholder_info;

                struct challenges{
                    var eta;
                    var perm_beta;
                    var perm_gamma;
                    var lookup_theta;
                    var lookup_gamma;
                    var lookup_beta;
                    std::vector<var> lookup_alphas;
                    var gate_theta;
                    std::array<var, 8> alphas;
                    std::vector<var> fri_alphas;
                    std::vector<var> fri_xs;
                    var lpc_theta;
                    var xi;
                };

                struct input_type {
                    std::vector<var> proof;
                    std::vector<var> commitments;
                    std::vector<var> fri_roots;
                    std::vector<std::vector<var>> merkle_tree_positions;
                    std::vector<std::vector<var>> initial_proof_values;
                    std::vector<std::vector<var>> initial_proof_hashes;
                    std::vector<std::vector<var>> round_proof_values;
                    std::vector<std::vector<var>> round_proof_hashes;
                    var challenge;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.reserve(proof.size());
                        result.insert(result.end(), proof.begin(), proof.end());

                        return result;
                    }

                    input_type(detail::placeholder_proof_input_type<SrcParams> proof_input){
                        proof = proof_input.vector();
                        commitments = proof_input.commitments();
                        fri_roots = proof_input.fri_roots();
                        challenge = proof_input.challenge();
                        merkle_tree_positions = proof_input.merkle_tree_positions();
                        initial_proof_values = proof_input.initial_proof_values();
                        initial_proof_hashes = proof_input.initial_proof_hashes();
                        round_proof_values = proof_input.round_proof_values();
                        round_proof_hashes = proof_input.round_proof_hashes();
                    }
                };
                struct result_type {
                    static constexpr std::size_t output_size = 1;
                    std::array<var, output_size> output = {var(0, 0, false)};

                    result_type(std::uint32_t start_row_index) {
                        output[0] = var(0, start_row_index, false);
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.insert(result.end(), output.begin(), output.end());
                        return result;
                    }
                };

                using manifest_type = plonk_component_manifest;

                static const std::size_t gates_amount = 0;

                class gate_manifest_type : public component_gate_manifest {
                    std::size_t num_gates;
                public:
                    gate_manifest_type(std::size_t witness_amount, std::size_t domain_size){
                        std::cout << "Verifier gate_manifet_type constructor with witness = " << witness_amount << std::endl;
                        num_gates = poseidon_component_type::get_gate_manifest(witness_amount).get_gates_amount();
                        std::size_t constant_pow_gates = constant_pow_component_type::get_gate_manifest(
                            witness_amount, (BlueprintFieldType::modulus - 1)/domain_size
                        ).get_gates_amount();
                        std::cout << "Constant component gates " << constant_pow_gates << std::endl;
                        num_gates += constant_pow_gates;
                        std::cout << "X-index gates " << 1 << std::endl;
                        num_gates += 1;
                        std::cout << "Colinear checks component gate " << 1 << std::endl;
                        num_gates += 1;
                    }
                    std::uint32_t gates_amount() const override {
                        std::cout << "Verifier gates_amount " << num_gates << std::endl;
                        return num_gates;
                    }
                };

                static gate_manifest get_gate_manifest(
                    std::size_t witness_amount,
                    SrcParams src_params,
                    const typename SrcParams::constraint_system_type &constraint_system,
                    const typename nil::crypto3::zk::snark::placeholder_public_preprocessor<typename SrcParams::field_type, SrcParams>::preprocessed_data_type::common_data_type &common_data,
                    const typename SrcParams::commitment_scheme_params_type &fri_params
                ) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount, fri_params.D[0]->size()));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(5)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(
                    std::size_t witness_amount,
                    SrcParams src_params,
                    const typename SrcParams::constraint_system_type &constraint_system,
                    const typename nil::crypto3::zk::snark::placeholder_public_preprocessor<typename SrcParams::field_type, SrcParams>::preprocessed_data_type::common_data_type &common_data,
                    const typename SrcParams::commitment_scheme_params_type &fri_params
                ) {
                    auto &desc = common_data.desc;
                    auto placeholder_info = nil::crypto3::zk::snark::prepare_placeholder_info<SrcParams>(
                        constraint_system,
                        common_data
                    );

                    auto vk0 = common_data.vk.constraint_system_with_params_hash;
                    auto vk1 = common_data.vk.fixed_values_commitment;
                    auto fri_params_r = fri_params.r;
                    auto fri_params_lambda = fri_params.lambda;
                    auto fri_omega = fri_params.D[0]->get_domain_element(1);
                    auto fri_domain_size = fri_params.D[0]->size();
                    auto fri_initial_merkle_proof_size = log2(fri_params.D[0]->m) - 1;

                    using poseidon_component_type = typename plonk_flexible_verifier::poseidon_component_type;
                    std::size_t poseidon_rows = poseidon_component_type::get_rows_amount(witness_amount);

                    using constant_pow_component_type = typename plonk_flexible_verifier::constant_pow_component_type;
                    std::size_t constant_pow_rows = constant_pow_component_type::get_rows_amount(witness_amount, (BlueprintFieldType::modulus - 1)/fri_domain_size);

                    using x_index_component_type = typename plonk_flexible_verifier::x_index_component_type;
                    std::size_t x_index_rows = x_index_component_type::get_rows_amount(witness_amount, fri_initial_merkle_proof_size);

                    using colinear_checks_component_type = typename plonk_flexible_verifier::colinear_checks_component_type;
                    std::size_t colinear_checks_rows = colinear_checks_component_type::get_rows_amount(witness_amount, fri_params_r);

                    auto rows_amount = poseidon_rows * 15 + poseidon_rows * fri_params_r + poseidon_rows * fri_params_lambda; //challenges
                    for( std::size_t i = 0; i < placeholder_info.batches_num; i++){
                        rows_amount += poseidon_rows * placeholder_info.batches_sizes[i] * fri_params_lambda;
                        rows_amount += poseidon_rows * fri_initial_merkle_proof_size * fri_params_lambda;
                    }
                    for( std::size_t i = 0; i < fri_params.r-1; i++){
                        rows_amount += poseidon_rows * fri_params_lambda * (fri_initial_merkle_proof_size - i);
                    }
                    rows_amount += constant_pow_rows * fri_params_lambda;
                    rows_amount += x_index_rows * fri_params_lambda;
                    rows_amount += colinear_checks_rows * fri_params_lambda;
                    return rows_amount;
                }

                template <
                    typename WitnessContainerType,
                    typename ConstantContainerType,
                    typename PublicInputContainerType
                >
                plonk_flexible_verifier(
                    WitnessContainerType witnesses,
                    ConstantContainerType constants,
                    PublicInputContainerType public_inputs,
                    SrcParams src_params,
                    const typename SrcParams::constraint_system_type &constraint_system,
                    const typename nil::crypto3::zk::snark::placeholder_public_preprocessor<typename SrcParams::field_type, SrcParams>::preprocessed_data_type::common_data_type &common_data,
                    const typename SrcParams::commitment_scheme_params_type &fri_params
                ):  component_type(witnesses, constants, public_inputs, get_manifest())
                {
                    auto &desc = common_data.desc;
                    placeholder_info = nil::crypto3::zk::snark::prepare_placeholder_info<SrcParams>(
                        constraint_system,
                        common_data
                    );

                    vk0 = common_data.vk.constraint_system_with_params_hash;
                    vk1 = common_data.vk.fixed_values_commitment;
                    fri_params_r = fri_params.r;
                    fri_params_lambda = fri_params.lambda;
                    fri_omega = fri_params.D[0]->get_domain_element(1);
                    fri_domain_size = fri_params.D[0]->size();
                    fri_initial_merkle_proof_size = log2(fri_params.D[0]->m) - 1;

                    using poseidon_component_type = typename plonk_flexible_verifier::poseidon_component_type;
                    using constant_pow_component_type = typename plonk_flexible_verifier::constant_pow_component_type;
                    using x_index_component_type = typename plonk_flexible_verifier::x_index_component_type;
                    using colinear_checks_component_type = typename plonk_flexible_verifier::colinear_checks_component_type;

                    poseidon_component_type poseidon_instance(
                        witnesses, constants, public_inputs
                    );
                    std::size_t poseidon_rows = poseidon_instance.rows_amount;

                    x_index_component_type x_index_instance(
                        witnesses, constants, public_inputs,
                        fri_initial_merkle_proof_size, fri_omega
                    );
                    std::size_t x_index_rows = x_index_instance.rows_amount;

                    constant_pow_component_type constant_pow_instance(
                        witnesses, constants, public_inputs,
                        (BlueprintFieldType::modulus - 1)/fri_domain_size
                    );
                    std::size_t constant_pow_rows = constant_pow_instance.rows_amount;

                    colinear_checks_component_type colinear_checks_instance(
                        witnesses, constants, public_inputs,
                        fri_params_r
                    );
                    std::size_t colinear_checks_rows = colinear_checks_instance.rows_amount;

                    rows_amount = poseidon_rows * 15 + poseidon_rows * fri_params_r + poseidon_rows * fri_params_lambda; //challenges
                    for( std::size_t i = 0; i < placeholder_info.batches_num; i++){
                        rows_amount += poseidon_rows * placeholder_info.batches_sizes[i] * fri_params_lambda;
                        rows_amount += poseidon_rows * fri_initial_merkle_proof_size * fri_params_lambda;
                    }
                    for( std::size_t i = 0; i < fri_params.r-1; i++){
                        rows_amount += poseidon_rows * fri_params_lambda * (fri_initial_merkle_proof_size - i);
                    }
                    rows_amount += constant_pow_rows * fri_params_lambda;
                    rows_amount += x_index_rows * fri_params_lambda;
                    rows_amount += colinear_checks_rows * fri_params_lambda;
                    // Change after implementing minimized permutation_argument
                }

                std::vector<std::uint32_t> all_witnesses() const{
                    return this->_W;
                }

                typename BlueprintFieldType::value_type vk0;
                typename BlueprintFieldType::value_type vk1;
            };

            template<typename BlueprintFieldType, typename SrcParams>
            typename plonk_flexible_verifier<BlueprintFieldType, SrcParams>::result_type
            generate_assignments(
                const plonk_flexible_verifier<BlueprintFieldType, SrcParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_flexible_verifier<BlueprintFieldType, SrcParams>::input_type instance_input,
                const std::uint32_t start_row_index
            ) {
                using component_type = plonk_flexible_verifier<BlueprintFieldType, SrcParams>;

                using swap_component_type = typename component_type::swap_component_type;
                using swap_input_type = typename swap_component_type::input_type;

                using poseidon_component_type = typename component_type::poseidon_component_type;
                using constant_pow_component_type = typename component_type::constant_pow_component_type;
                using x_index_component_type = typename component_type::x_index_component_type;
                using colinear_checks_component_type = typename component_type::colinear_checks_component_type;
                using var = typename component_type::var;

                std::size_t poseidon_rows = 0;
                std::size_t constant_pow_rows = 0;
                std::size_t swap_rows = 0;

                typename component_type::challenges challenges;
                constant_pow_component_type constant_pow_instance(
                    component.all_witnesses(), std::array<std::uint32_t, 1>({component.C(0)}), std::array<std::uint32_t, 0>(),
                    (BlueprintFieldType::modulus - 1)/component.fri_domain_size
                );

                std::size_t row = start_row_index;
                std::cout << "Generate assignments" << std::endl;

                const typename component_type::result_type result(start_row_index);
                // Set constants
                assignment.constant(component.C(0),start_row_index) = typename BlueprintFieldType::value_type(0);
                assignment.constant(component.C(0),start_row_index+1) = typename BlueprintFieldType::value_type(1);
                assignment.constant(component.C(0),start_row_index+2) = component.vk0;
                assignment.constant(component.C(0),start_row_index+3) = component.vk1;

                var zero_var = var(component.C(0), start_row_index, false, var::column_type::constant);
                var vk0_var = var(component.C(0), start_row_index+2, false, var::column_type::constant);
                var vk1_var = var(component.C(0), start_row_index+3, false, var::column_type::constant);

                typename poseidon_component_type::input_type poseidon_input = {zero_var, vk0_var, vk1_var};
                poseidon_component_type poseidon_instance(component.all_witnesses(), std::array<std::uint32_t, 1>({component.C(0)}), std::array<std::uint32_t, 0>());
                std::cout << "Poseidon prepared" << std::endl;
                auto poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);

                std::vector<std::pair<var, var>> swapped_vars;

                challenges.eta = poseidon_output.output_state[2];
                auto variable_value_var = instance_input.commitments[0];
                row += poseidon_instance.rows_amount;
                poseidon_rows += poseidon_instance.rows_amount;

                poseidon_input = {challenges.eta, variable_value_var, zero_var};
                poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                challenges.perm_beta = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;
                poseidon_rows += poseidon_instance.rows_amount;

                poseidon_input = {challenges.perm_beta, zero_var, zero_var};
                poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                challenges.perm_gamma = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;
                poseidon_rows += poseidon_instance.rows_amount;

                // TODO: if use_lookups
                poseidon_input = {challenges.perm_gamma, instance_input.commitments[1], zero_var};
                poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                challenges.gate_theta = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;
                poseidon_rows += poseidon_instance.rows_amount;

                for(std::size_t i = 0; i < 8; i++){
                    poseidon_input = {poseidon_output.output_state[2], zero_var, zero_var};
                    poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                    challenges.alphas[i] = poseidon_output.output_state[2];
                    row += poseidon_instance.rows_amount;
                    poseidon_rows += poseidon_instance.rows_amount;
                }

                poseidon_input = {poseidon_output.output_state[2], instance_input.commitments[2], zero_var};
                poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                poseidon_rows += poseidon_instance.rows_amount;
                challenges.xi = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;
                BOOST_ASSERT(var_value(assignment, challenges.xi) == var_value(assignment, instance_input.challenge));

                poseidon_input = {poseidon_output.output_state[2], vk1_var, instance_input.commitments[0]};
                poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                row += poseidon_instance.rows_amount;
                poseidon_rows += poseidon_instance.rows_amount;

                poseidon_input = {poseidon_output.output_state[2], instance_input.commitments[1], instance_input.commitments[2]};
                poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                challenges.lpc_theta = poseidon_output.output_state[2];
                std::cout << "lpc_theta = " << var_value(assignment, challenges.lpc_theta) << std::endl;
                row += poseidon_instance.rows_amount;
                poseidon_rows += poseidon_instance.rows_amount;

                // TODO: if use_lookups state[1] should be equal to sorted polynomial commitment
                // poseidon_input = {poseidon_output.output_state[2], zero_var, zero_var};
                // poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                // row += poseidon_instance.rows_amount;

                for( std::size_t i = 0; i < component.fri_params_r; i+=1){
                    poseidon_input = {poseidon_output.output_state[2], instance_input.fri_roots[i], zero_var};
                    poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                    challenges.fri_alphas.push_back(poseidon_output.output_state[2]);
                    std::cout << "alpha_challenge = " << var_value(assignment, challenges.fri_alphas[i]) << std::endl;
                    row += poseidon_instance.rows_amount;
                    poseidon_rows += poseidon_instance.rows_amount;
                }

                for( std::size_t i = 0; i < component.fri_params_lambda; i+=1){
                    poseidon_input = {poseidon_output.output_state[2], zero_var, zero_var};
                    poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                    challenges.fri_xs.push_back(poseidon_output.output_state[2]);
                    std::cout << "x_challenge = " << var_value(assignment, challenges.fri_xs[i]) << std::endl;
                    row += poseidon_instance.rows_amount;
                    poseidon_rows += poseidon_instance.rows_amount;
                }

                std::size_t challenge_poseidon_rows = poseidon_rows;

                std::vector<var> xs;
                for( std::size_t i = 0; i < component.fri_params_lambda; i++){
                    typename constant_pow_component_type::input_type constant_pow_input = {challenges.fri_xs[i]};
                    typename constant_pow_component_type::result_type constant_pow_output = generate_assignments(
                        constant_pow_instance, assignment, constant_pow_input, row
                    );
                    xs.push_back(constant_pow_output.y);
                    row+= constant_pow_instance.rows_amount;
                    constant_pow_rows += constant_pow_instance.rows_amount;
                }

                x_index_component_type x_index_instance(
                    component.all_witnesses(), std::array<std::uint32_t, 1>({component.C(0)}), std::array<std::uint32_t, 0>(),
                    component.fri_initial_merkle_proof_size, component.fri_omega
                );
                for( std::size_t i = 0; i < component.fri_params_lambda; i++){
                    typename x_index_component_type::input_type x_index_input;
                    x_index_input.x = xs[i];
                    for( std::size_t j = 0; j < component.fri_initial_merkle_proof_size; j++){
                        x_index_input.b.push_back(instance_input.merkle_tree_positions[i][j]);
                    }
                    typename x_index_component_type::result_type x_index_output = generate_assignments(
                        x_index_instance, assignment, x_index_input, row
                    );
                    row += x_index_instance.rows_amount;
                }

                std::size_t colinear_checks_rows = 0;
                colinear_checks_component_type colinear_checks_instance(
                    component.all_witnesses(), std::array<std::uint32_t, 1>({component.C(0)}),
                    std::array<std::uint32_t, 0>(), component.fri_params_r
                );
                for( std::size_t i = 0; i < component.fri_params_lambda; i++){
                    typename colinear_checks_component_type::input_type colinear_checks_input(component.fri_params_r);
                    colinear_checks_input.x = xs[i];
                    colinear_checks_input.ys.push_back(zero_var); // Fix after 1st round will be ready
                    colinear_checks_input.ys.push_back(zero_var); // Fix after 1st round will be ready
                    colinear_checks_input.bs.push_back(zero_var); // Set it to x_index component output
                    for( std::size_t j = 0; j < component.fri_params_r; j++){
                        colinear_checks_input.ys.push_back(instance_input.round_proof_values[i][2*j]);
                        colinear_checks_input.ys.push_back(instance_input.round_proof_values[i][2*j + 1]);
                        colinear_checks_input.alphas.push_back(challenges.fri_alphas[j]);
                        colinear_checks_input.bs.push_back(instance_input.merkle_tree_positions[i][instance_input.merkle_tree_positions[i].size() - j - 1]);
                    }
                    typename colinear_checks_component_type::result_type colinear_checks_output = generate_assignments(
                        colinear_checks_instance, assignment, colinear_checks_input, row
                    );
                    row += colinear_checks_instance.rows_amount;
                    colinear_checks_rows += colinear_checks_instance.rows_amount;
                }


                // Query proof check
                // Construct Merkle leaves
                std::size_t merkle_leaf_rows = 0;
                std::size_t merkle_proof_rows = 0;
                for( std::size_t i = 0; i < component.fri_params_lambda; i++){
                    // Initial proof merkle leaf
                    std::size_t cur = 0;
                    std::size_t cur_hash = 0;
                    std::cout << "Query " << i << std::endl;
                    for( std::size_t j = 0; j < component.placeholder_info.batches_num; j++){
                        poseidon_input.input_state[0] = zero_var;
                        for( std::size_t k = 0; k < component.placeholder_info.batches_sizes[j]; k++, cur+=2){
                            poseidon_input.input_state[1] = instance_input.initial_proof_values[i][cur];
                            poseidon_input.input_state[2] = instance_input.initial_proof_values[i][cur+1];
                            poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                            poseidon_input.input_state[0] = poseidon_output.output_state[2];
                            row += poseidon_instance.rows_amount;
                            poseidon_rows += poseidon_instance.rows_amount;
                            merkle_leaf_rows += poseidon_instance.rows_amount;
                        }
                        var hash_var = poseidon_output.output_state[2];
//                        std::cout << "First hash i = " << i << "; cur_hash = " << cur_hash << " = " << instance_input.initial_proof_hashes[i][cur_hash] << " = " << var_value(assignment, instance_input.initial_proof_hashes[i][cur_hash]) << std::endl;
                        for( std::size_t k = 0; k < component.fri_initial_merkle_proof_size; k++){
                            swap_input_type swap_input;
                            swap_input.inp = {instance_input.merkle_tree_positions[i][k], instance_input.initial_proof_hashes[i][cur_hash], hash_var};
                            auto swap_result = assignment.template add_input_to_batch<swap_component_type>(
                                                    swap_input, 0);
                            poseidon_input = {zero_var, swap_result.output[0], swap_result.output[1]};
                            poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
//                            std::cout << "\t("
//                                << var_value(assignment, poseidon_input.input_state[1]) << ", "
//                                << var_value(assignment, poseidon_input.input_state[2]) << ", "
//                                << ") => " << var_value(assignment, poseidon_output.output_state[2]) << std::endl;
                            hash_var = poseidon_output.output_state[2];
                            cur_hash++;
                            row += poseidon_instance.rows_amount;
                            poseidon_rows += poseidon_instance.rows_amount;
                            merkle_proof_rows += poseidon_instance.rows_amount;
                        }
                    }
                    // Round proofs
                    cur = 0;
                    cur_hash = 0;
                    var hash_var;
                    var y0;
                    var y1;
                    for( std::size_t j = 0; j < component.fri_params_r; j++){
                        if(j != 0){
                            poseidon_input = {zero_var, y0, y1};
                            poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                            hash_var = poseidon_output.output_state[2];
                            row += poseidon_instance.rows_amount;
                            poseidon_rows += poseidon_instance.rows_amount;
                            merkle_proof_rows += poseidon_instance.rows_amount;
                            for( std::size_t k = 0; k < component.fri_initial_merkle_proof_size - j; k++){
                                swap_input_type swap_input;
                                swap_input.inp = {instance_input.merkle_tree_positions[i][k], instance_input.round_proof_hashes[i][cur_hash], hash_var};
                                auto swap_result = assignment.template add_input_to_batch<swap_component_type>(
                                                        swap_input, 0);
                                poseidon_input = {zero_var, swap_result.output[0], swap_result.output[1]};
                                poseidon_output = generate_assignments(poseidon_instance, assignment, poseidon_input, row);
                                row += poseidon_instance.rows_amount;
                                poseidon_rows += poseidon_instance.rows_amount;
                                merkle_proof_rows += poseidon_instance.rows_amount;
                                hash_var = poseidon_output.output_state[2];
                                cur_hash++;
                            }
                        }
                        else {
                            // TODO remove it when 1st round will be ready
                            cur_hash += component.fri_initial_merkle_proof_size;
                        }
                        y0 = instance_input.round_proof_values[i][cur*2];
                        y1 = instance_input.round_proof_values[i][cur*2 + 1];
                        cur++;
                    }
                }

                std::cout << "Generated assignments real rows for " << component.all_witnesses().size() << " witness  = " << row - start_row_index << std::endl << std::endl << std::endl;
                std::cout << "Poseidon rows = " << poseidon_rows << std::endl;
                std::cout << "Challenge rows = " << challenge_poseidon_rows << std::endl;
                std::cout << "Merkle leaf rows = " << merkle_leaf_rows << std::endl;
                std::cout << "Merkle proof rows = " << merkle_proof_rows << std::endl;
                std::cout << "Constant pow rows = " << constant_pow_rows << std::endl;
                std::cout << "Swap rows = " << swap_rows << std::endl;
                std::cout << "Colinear checks rows = " << colinear_checks_rows << std::endl;
                return result;
            }


            template<typename BlueprintFieldType, typename SrcParams>
            const typename plonk_flexible_verifier<BlueprintFieldType, SrcParams>::result_type
            generate_circuit(
                const plonk_flexible_verifier<BlueprintFieldType, SrcParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_flexible_verifier<BlueprintFieldType, SrcParams>::input_type &instance_input,
                const std::size_t start_row_index
            ) {
                std::cout << "Generate circuit" << std::endl;
                using component_type = plonk_flexible_verifier<BlueprintFieldType, SrcParams>;
                using var = typename component_type::var;
                using poseidon_component_type = typename component_type::poseidon_component_type;
                using swap_component_type = typename component_type::swap_component_type;
                using swap_input_type = typename swap_component_type::input_type;
                using constant_pow_component_type = typename component_type::constant_pow_component_type;
                using x_index_component_type = typename component_type::x_index_component_type;
                using colinear_checks_component_type = typename component_type::colinear_checks_component_type;
                typename component_type::challenges challenges;

                std::size_t row = start_row_index;

                const typename plonk_flexible_verifier<BlueprintFieldType, SrcParams>::result_type result(start_row_index);
                var zero_var = var(component.C(0), start_row_index, false, var::column_type::constant);
                var vk0_var = var(component.C(0), start_row_index+2, false, var::column_type::constant);
                var vk1_var = var(component.C(0), start_row_index+3, false, var::column_type::constant);

                typename poseidon_component_type::input_type poseidon_input = {zero_var, vk0_var, vk1_var};
                poseidon_component_type poseidon_instance(component.all_witnesses(), std::array<std::uint32_t, 1>({component.C(0)}), std::array<std::uint32_t, 0>());
                auto poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);

                constant_pow_component_type constant_pow_instance(
                    component.all_witnesses(), std::array<std::uint32_t, 1>({component.C(0)}), std::array<std::uint32_t, 0>(),
                    (BlueprintFieldType::modulus - 1)/component.fri_domain_size
                );

                challenges.eta = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;

                poseidon_input = {challenges.eta, instance_input.commitments[0], zero_var};
                poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                challenges.perm_beta = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;

                poseidon_input = {challenges.perm_beta, zero_var, zero_var};
                poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                challenges.perm_gamma = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;

                //TODO if use_lookups

                poseidon_input = {challenges.perm_gamma, instance_input.commitments[1], zero_var};
                poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                challenges.gate_theta = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;

                for(std::size_t i = 0; i < 8; i++){
                    poseidon_input = {poseidon_output.output_state[2], zero_var, zero_var};
                    poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                    challenges.alphas[i] = poseidon_output.output_state[2];
                    row += poseidon_instance.rows_amount;
                }
                poseidon_input = {poseidon_output.output_state[2], instance_input.commitments[2], zero_var};
                poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                challenges.xi = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;

                bp.add_copy_constraint({challenges.xi, instance_input.challenge});

                poseidon_input = {poseidon_output.output_state[2], vk1_var, instance_input.commitments[0]};
                poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                row += poseidon_instance.rows_amount;

                poseidon_input = {poseidon_output.output_state[2], instance_input.commitments[1], instance_input.commitments[2]};
                poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                challenges.lpc_theta = poseidon_output.output_state[2];
                row += poseidon_instance.rows_amount;

                // TODO: if use_lookups state[1] should be equal to sorted polynomial commitment
                // poseidon_input = {poseidon_output.output_state[2], zero_var, zero_var};
                // poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                // row += poseidon_instance.rows_amount;

                for( std::size_t i = 0; i < component.fri_params_r; i++){
                    poseidon_input = {poseidon_output.output_state[2], instance_input.fri_roots[i], zero_var};
                    poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                    challenges.fri_alphas.push_back(poseidon_output.output_state[2]);
                    row += poseidon_instance.rows_amount;
                }

                for( std::size_t i = 0; i < component.fri_params_lambda; i++){
                    poseidon_input = {poseidon_output.output_state[2], zero_var, zero_var};
                    poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                    challenges.fri_xs.push_back(poseidon_output.output_state[2]);
                    row += poseidon_instance.rows_amount;
                }

                std::vector<var> xs;
                for( std::size_t i = 0; i < component.fri_params_lambda; i++){
                    typename constant_pow_component_type::input_type constant_pow_input = {challenges.fri_xs[i]};
                    typename constant_pow_component_type::result_type constant_pow_output = generate_circuit(
                        constant_pow_instance, bp, assignment, constant_pow_input, row
                    );
                    xs.push_back(constant_pow_output.y);
                    row+= constant_pow_instance.rows_amount;
                }

                x_index_component_type x_index_instance(
                    component.all_witnesses(), std::array<std::uint32_t, 1>({component.C(0)}), std::array<std::uint32_t, 0>(),
                    component.fri_initial_merkle_proof_size, component.fri_omega
                );
                for( std::size_t i = 0; i < component.fri_params_lambda; i++){
                    typename x_index_component_type::input_type x_index_input;
                    x_index_input.x = xs[i];
                    for( std::size_t j = 0; j < component.fri_initial_merkle_proof_size; j++ ){
                        x_index_input.b.push_back(instance_input.merkle_tree_positions[i][j]);
                    }
                    typename x_index_component_type::result_type x_index_output  = generate_circuit(
                        x_index_instance, bp, assignment, x_index_input, row
                    );
                    row += x_index_instance.rows_amount;
                }

                colinear_checks_component_type colinear_checks_instance(
                    component.all_witnesses(), std::array<std::uint32_t, 1>({component.C(0)}),
                    std::array<std::uint32_t, 0>(), component.fri_params_r
                );
                for( std::size_t i = 0; i < component.fri_params_lambda; i++){
                    typename colinear_checks_component_type::input_type colinear_checks_input(component.fri_params_r);
                    colinear_checks_input.x = xs[i];
                    colinear_checks_input.ys.push_back(zero_var); // Fix after 1st round will be ready
                    colinear_checks_input.ys.push_back(zero_var); // Fix after 1st round will be ready
                    colinear_checks_input.bs.push_back(zero_var); // Set it to x_index component output
                    for( std::size_t j = 0; j < component.fri_params_r; j++){
                        colinear_checks_input.ys.push_back(instance_input.round_proof_values[i][2*j]);
                        colinear_checks_input.ys.push_back(instance_input.round_proof_values[i][2*j + 1]);
                        colinear_checks_input.alphas.push_back(challenges.fri_alphas[j]);
                        colinear_checks_input.bs.push_back(instance_input.merkle_tree_positions[i][instance_input.merkle_tree_positions[i].size() - j - 1]);
                    }
                    typename colinear_checks_component_type::result_type colinear_checks_output = generate_circuit(
                        colinear_checks_instance, bp, assignment, colinear_checks_input, row
                    );
                    row += colinear_checks_instance.rows_amount;
                }

                // Query proof check
                for( std::size_t i = 0; i < component.fri_params_lambda; i++){
                    std::cout << "Query proof " << i << std::endl;
                    // Initial proof merkle leaf
                    std::size_t cur = 0;
                    std::size_t cur_hash = 0;
                    for( std::size_t j = 0; j < component.placeholder_info.batches_num; j++){
                        poseidon_input.input_state[0] = zero_var;
                        for( std::size_t k = 0; k < component.placeholder_info.batches_sizes[j]; k++, cur+=2){
                            poseidon_input.input_state[1] = instance_input.initial_proof_values[i][cur];
                            poseidon_input.input_state[2] = instance_input.initial_proof_values[i][cur+1];
                            poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                            poseidon_input.input_state[0] = poseidon_output.output_state[2];
                            row += poseidon_instance.rows_amount;
                        }
                        var hash_var = poseidon_output.output_state[2];
                        for( std::size_t k = 0; k < component.fri_initial_merkle_proof_size; k++){
                            swap_input_type swap_input;
                            swap_input.inp = {instance_input.merkle_tree_positions[i][k], instance_input.initial_proof_hashes[i][cur_hash], hash_var};
                            auto swap_result = assignment.template add_input_to_batch<swap_component_type>(
                                                    swap_input, 1);
                            poseidon_input = {zero_var, swap_result.output[0], swap_result.output[1]};
                            poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                            hash_var = poseidon_output.output_state[2];
                            cur_hash++;
                            row += poseidon_instance.rows_amount;
                        }
                        if( j == 0 )
                            bp.add_copy_constraint({poseidon_output.output_state[2], vk1_var});
                        else
                            bp.add_copy_constraint({poseidon_output.output_state[2], instance_input.commitments[j-1]});
                    }
                    // Compute y-s for first round
                    std::size_t round_merkle_proof_size = component.fri_initial_merkle_proof_size;
                    // Round proofs
                    cur = 0;
                    cur_hash = 0;
                    var hash_var;
                    var y0;
                    var y1;

                    for( std::size_t j = 0; j < component.fri_params_r; j++){
                        if(j != 0){
                            poseidon_input = {zero_var, y0, y1};
                            poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                            hash_var = poseidon_output.output_state[2];
                            row += poseidon_instance.rows_amount;
                            for( std::size_t k = 0; k < component.fri_initial_merkle_proof_size - j; k++){
                                swap_input_type swap_input;
                                swap_input.inp = {instance_input.merkle_tree_positions[i][k], instance_input.round_proof_hashes[i][cur_hash], hash_var};
                                auto swap_result = assignment.template add_input_to_batch<swap_component_type>(
                                                        swap_input, 1);
                                poseidon_input = {zero_var, swap_result.output[0], swap_result.output[1]};
                                poseidon_output = generate_circuit(poseidon_instance, bp, assignment, poseidon_input, row);
                                row += poseidon_instance.rows_amount;
                                hash_var = poseidon_output.output_state[2];
                                cur_hash++;
                            }
                            bp.add_copy_constraint({poseidon_output.output_state[2], instance_input.fri_roots[j]});
                        } else {
                            cur_hash += component.fri_initial_merkle_proof_size;
                        }
                        y0 = instance_input.round_proof_values[i][cur*2];
                        y1 = instance_input.round_proof_values[i][cur*2 + 1];
                        cur++;
                    }
                }

                std::cout << "Circuit generated real rows = " << row - start_row_index << std::endl;
                return result;
            }
        }
    }
}

#endif
