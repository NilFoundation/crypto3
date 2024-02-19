//---------------------------------------------------------------------------//
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
// @file Declaration of interfaces for auxiliary components for the BATCH_VERIFY_SCALAR_FIELD component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_BATCH_VERIFY_SCALAR_FIELD_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_BATCH_VERIFY_SCALAR_FIELD_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/combined_inner_product.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>

#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/batch_scalar/random.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/batch_scalar/prepare_scalars.hpp>

#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/oracles_scalar/b_poly.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/oracles_scalar/b_poly_coefficients.hpp>

#include <nil/blueprint/components/algebra/curves/pasta/plonk/endo_scalar.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // batched polynomial commitment verification (scalar field)
            // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/poly-commitment/src/commitment.rs#L610
            // Input: list of batch evaluation proofs
            //      https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/verifier.rs#L881-L888
            // Output: list of scalars for MSM in batch verify base
            template<typename ArithmetizationType,
                     typename CurveType,
                     typename KimchiParamsType,
                     typename KimchiCommitmentParamsType,
                     std::size_t BatchSize,
                     std::size_t... WireIndexes>
            class batch_verify_scalar_field;

            template<typename BlueprintFieldType,
                     typename CurveType,

                     typename KimchiParamsType,
                     typename KimchiCommitmentParamsType,
                     std::size_t BatchSize,
                     std::size_t W0,
                     std::size_t W1,
                     std::size_t W2,
                     std::size_t W3,
                     std::size_t W4,
                     std::size_t W5,
                     std::size_t W6,
                     std::size_t W7,
                     std::size_t W8,
                     std::size_t W9,
                     std::size_t W10,
                     std::size_t W11,
                     std::size_t W12,
                     std::size_t W13,
                     std::size_t W14>
            class batch_verify_scalar_field<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                                   CurveType,
                                                   KimchiParamsType,
                                                   KimchiCommitmentParamsType,
                                                   BatchSize,
                                                   W0,
                                                   W1,
                                                   W2,
                                                   W3,
                                                   W4,
                                                   W5,
                                                   W6,
                                                   W7,
                                                   W8,
                                                   W9,
                                                   W10,
                                                   W11,
                                                   W12,
                                                   W13,
                                                   W14 > {

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams> ArithmetizationType;


                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

                using mul_component = multiplication<ArithmetizationType, W0, W1, W2>;
                using sub_component = subtraction<ArithmetizationType, W0, W1, W2>;
                using add_component = addition<ArithmetizationType, W0, W1, W2>;
                using mul_by_const_component = mul_by_constant<ArithmetizationType, W0, W1>;

                using random_component = random<ArithmetizationType,\
                    KimchiParamsType, BatchSize,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                using endo_scalar_component =
                    endo_scalar<ArithmetizationType, CurveType,
                        KimchiParamsType::scalar_challenge_size,
                            W0, W1, W2, W3, W4, W5, W6, W7, W8,
                            W9, W10, W11, W12, W13, W14>;

                using b_poly_component = b_poly<ArithmetizationType,
                    KimchiCommitmentParamsType::eval_rounds, W0, W1, W2, W3, W4, W5,
                    W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                using b_poly_coeff_component = b_poly_coefficients<ArithmetizationType,
                    KimchiCommitmentParamsType::eval_rounds, W0, W1, W2, W3, W4, W5,
                    W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                using kimchi_constants = kimchi_inner_constants<KimchiParamsType>;

                constexpr static std::size_t scalars_len() {
                    return kimchi_constants::final_msm_size(BatchSize);
                }

                using prepare_scalars_component =
                    prepare_scalars<ArithmetizationType, CurveType,
                        scalars_len(), W0, W1, W2, W3, W4, W5, W6, W7, W8,
                                                W9, W10, W11, W12, W13, W14>;

                using batch_proof = batch_evaluation_proof_scalar<BlueprintFieldType,
                    ArithmetizationType, KimchiParamsType, KimchiCommitmentParamsType>;

                constexpr static const std::size_t selector_seed = 0x0f28;

                constexpr static const std::size_t srs_len = KimchiCommitmentParamsType::srs_len;
                constexpr static const std::size_t eval_rounds = KimchiCommitmentParamsType::eval_rounds;

                constexpr static std::size_t rows() {
                    std::size_t row = 0;

                    row += random_component::rows_amount;
                    row += random_component::rows_amount;

                    for (std::size_t batch_id = 0; batch_id < BatchSize; batch_id++) {
                        for (std::size_t j = 0; j < eval_rounds; j++) {
                            row += endo_scalar_component::rows_amount;

                            row += sub_component::rows_amount;
                        }

                        row += endo_scalar_component::rows_amount;

                        for (std::size_t i = 0; i < KimchiParamsType::eval_points_amount; i++) {
                            row += b_poly_component::rows_amount;

                            row += mul_component::rows_amount;

                            row += add_component::rows_amount;

                            row += mul_component::rows_amount;
                        }

                        row += b_poly_coeff_component::rows_amount;

                        row += mul_by_const_component::rows_amount;

                        row += mul_component::rows_amount;

                        row += sub_component::rows_amount;

                        for (std::size_t i = 0; i < b_poly_coeff_component::polynomial_len; i++) {
                            row += mul_component::rows_amount;
                            row += add_component::rows_amount;
                        }

                        row += mul_component::rows_amount;

                        row += sub_component::rows_amount;

                        row += mul_component::rows_amount;

                        row += mul_component::rows_amount;

                        row += mul_component::rows_amount;
                        for (std::size_t i = 0; i < eval_rounds; i++) {
                            row += mul_component::rows_amount;

                            row += mul_component::rows_amount;
                        }

                        for (std::size_t i = 0; i < kimchi_constants::evaluations_in_batch_size; i++) {
                            for (std::size_t j = 0;
                                j < KimchiParamsType::commitment_params_type::shifted_commitment_split + 1;
                                j++) {
                                row += mul_component::rows_amount;

                                row += mul_component::rows_amount;
                            }
                        }

                        row += mul_component::rows_amount;

                        row += mul_component::rows_amount;

                        row += mul_component::rows_amount;
                    }

                    row += prepare_scalars_component::rows_amount;

                    return row;
                }

            public:
                constexpr static const std::size_t rows_amount = rows();

                constexpr static const std::size_t gates_amount = 0;

                struct params_type {
                    std::array<batch_proof, BatchSize> batches;
                };

                struct result_type {
                    std::array<var, scalars_len()> output;

                    result_type(std::size_t start_row_index) {
                    }
                };

                static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                    blueprint_public_assignment_table<ArithmetizationType> &assignment,
                    const params_type &params,
                    const std::size_t start_row_index){

                    generate_assignments_constant(bp, assignment, params, start_row_index);

                    std::size_t row = start_row_index;

                    var zero = var(0, start_row_index, false, var::column_type::constant);
                    var one = var(0, start_row_index + 1, false, var::column_type::constant);

                    std::array<var, scalars_len()> scalars;
                    std::size_t scalar_idx = KimchiCommitmentParamsType::srs_len
                        + kimchi_constants::srs_padding_size();

                    for (std::size_t i = 0;
                        i < KimchiCommitmentParamsType::srs_len + kimchi_constants::srs_padding_size();
                        i++) {
                            scalars[i] = zero;
                    }

                    var rand_base = random_component::generate_circuit(
                        bp, assignment, {params.batches}, row).output;
                    row += random_component::rows_amount;
                    var sg_rand_base = random_component::generate_circuit(
                        bp, assignment, {params.batches}, row).output;
                    row += random_component::rows_amount;

                    var rand_base_i = one;
                    var sg_rand_base_i = one;

                    for (std::size_t batch_id = 0; batch_id < params.batches.size(); batch_id++) {
                        var cip = params.batches[batch_id].cip;

                        std::array<std::array<var, eval_rounds>, 2> challenges;
                        for (std::size_t j = 0; j < eval_rounds; j++) {
                            challenges[0][j] = endo_scalar_component::generate_circuit(
                                bp, assignment,
                                {params.batches[batch_id].fq_output.challenges[j]},
                                row).output;
                            row += endo_scalar_component::rows_amount;

                            challenges[1][j] = generate_circuit<sub_component>(
                                bp, assignment, {zero, challenges[0][j]}, row).output;
                            row += sub_component::rows_amount;
                        }

                        var c = endo_scalar_component::generate_circuit(
                                bp, assignment,
                                {params.batches[batch_id].fq_output.c},
                                row).output;
                        row += endo_scalar_component::rows_amount;

                        var b0_scale = one;
                        var b0 = zero;

                        for (std::size_t i = 0; i < KimchiParamsType::eval_points_amount; i++) {
                            var term = b_poly_component::generate_circuit(
                                bp, assignment,
                                {challenges[0], params.batches[batch_id].eval_points[i],
                                one}, row).output;
                            row += b_poly_component::rows_amount;

                            var tmp = generate_circuit<mul_component>(
                                bp, assignment, {b0_scale, term}, row).output;
                            row += mul_component::rows_amount;

                            b0 = generate_circuit<add_component>(
                                bp, assignment, {b0, tmp}, row).output;
                            row += add_component::rows_amount;

                            b0_scale = generate_circuit<mul_component>(
                                bp, assignment, {b0_scale, params.batches[batch_id].r}, row).output;
                            row += mul_component::rows_amount;
                        }

                        auto s = b_poly_coeff_component::generate_circuit(
                            bp, assignment, {challenges[0], one}, row).output;
                        row += b_poly_coeff_component::rows_amount;

                        var neg_rand_base_i =
                            generate_circuit<mul_by_const_component>(
                                bp, assignment, {rand_base_i, -1}, row).output;
                        row += mul_by_const_component::rows_amount;

                        // neg_rand_base_i * opening.z1 - sg_rand_base_i
                        var tmp = generate_circuit<mul_component>(bp,
                            assignment, {neg_rand_base_i, params.batches[batch_id].opening.z1},
                            row).output;
                        row += mul_component::rows_amount;

                        tmp = generate_circuit<sub_component>(bp,
                            assignment, {tmp, sg_rand_base_i}, row).output;
                        row += sub_component::rows_amount;
                        scalars[scalar_idx++] = tmp;

                        for (std::size_t i = 0; i < s.size(); i++) {
                            var sg_s = generate_circuit<mul_component>(
                                bp, assignment, {sg_rand_base_i, s[i]},
                                row).output;
                            row += mul_component::rows_amount;

                            scalars[i] = generate_circuit<add_component>(
                                bp, assignment, {scalars[i], sg_s}, row).output;
                            row += add_component::rows_amount;
                        }

                        var rand_base_z2 = generate_circuit<mul_component>(
                            bp, assignment, {rand_base_i,
                            params.batches[batch_id].opening.z2},
                            row).output;
                        row += mul_component::rows_amount;

                        scalars[0] = generate_circuit<sub_component>(
                            bp, assignment, {scalars[0], rand_base_z2},
                            row).output;
                        row += sub_component::rows_amount;

                        // neg_rand_base_i * (opening.z1 * b0)
                        var z1_b0 = generate_circuit<mul_component>(
                            bp, assignment, {b0,
                            params.batches[batch_id].opening.z1},
                            row).output;
                        row += mul_component::rows_amount;
                        scalars[scalar_idx++] = generate_circuit<mul_component>(
                            bp, assignment, {z1_b0,
                            neg_rand_base_i},
                            row).output;
                        row += mul_component::rows_amount;

                        var c_rand_base_i = generate_circuit<mul_component>(
                                bp, assignment, {c,
                                rand_base_i},
                                row).output;
                        row += mul_component::rows_amount;
                        for (std::size_t i = 0; i < eval_rounds; i++) {
                            // rand_base_i_c_i * u_inv
                            scalars[scalar_idx++] = generate_circuit<mul_component>(
                                bp, assignment, {challenges[1][i],
                                c_rand_base_i},
                                row).output;
                            row += mul_component::rows_amount;

                            // rand_base_i_c_i * u
                            scalars[scalar_idx++] = generate_circuit<mul_component>(
                                bp, assignment, {challenges[0][i],
                                c_rand_base_i},
                                row).output;
                            row += mul_component::rows_amount;
                        }

                        var xi_i = one;
                        for (std::size_t i = 0; i < kimchi_constants::evaluations_in_batch_size; i++) {
                            // iterating over the polynomial segments + shifted part
                            for (std::size_t j = 0;
                                j < KimchiParamsType::commitment_params_type::shifted_commitment_split + 1;
                                j++) {

                                // rand_base_i_c_i * xi_i
                                scalars[scalar_idx++] = generate_circuit<mul_component>(
                                    bp, assignment, {xi_i,
                                    c_rand_base_i},
                                    row).output;
                                row += mul_component::rows_amount;

                                xi_i = generate_circuit<mul_component>(
                                    bp, assignment, {xi_i,
                                    params.batches[batch_id].xi},
                                    row).output;
                                row += mul_component::rows_amount;
                            }
                        }

                        // rand_base_i_c_i * combined_inner_product0
                        scalars[scalar_idx++] = generate_circuit<mul_component>(
                            bp, assignment, {cip,
                            c_rand_base_i},
                            row).output;
                        row += mul_component::rows_amount;

                        scalars[scalar_idx++] = rand_base_i;

                        rand_base_i = generate_circuit<mul_component>(
                            bp, assignment,
                            {rand_base_i, rand_base}, row).output;
                        row += mul_component::rows_amount;

                        sg_rand_base_i = generate_circuit<mul_component>(
                            bp, assignment,
                            {sg_rand_base_i, sg_rand_base}, row).output;
                        row += mul_component::rows_amount;
                    }

                    scalars = prepare_scalars_component::generate_circuit(bp, assignment,
                        {scalars}, row).output;
                    row += prepare_scalars_component::rows_amount;

                    assert(row == start_row_index + rows_amount);
                    assert(scalar_idx == kimchi_constants::final_msm_size(BatchSize) - 1);

                    result_type res(start_row_index);
                    res.output = scalars;
                    return res;
                }

                static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                        const params_type &params,
                                                        std::size_t start_row_index) {
                    std::size_t row = start_row_index;

                    typename BlueprintFieldType::value_type endo_factor =
                        0x12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9_cppui255;
                    std::size_t endo_num_bits = 128;

                    var zero = var(0, start_row_index, false, var::column_type::constant);
                    var one = var(0, start_row_index + 1, false, var::column_type::constant);

                    std::array<var, scalars_len()> scalars;
                    std::size_t scalar_idx = KimchiCommitmentParamsType::srs_len
                        + kimchi_constants::srs_padding_size();

                    for (std::size_t i = 0;
                        i < KimchiCommitmentParamsType::srs_len + kimchi_constants::srs_padding_size();
                        i++) {
                            scalars[i] = zero;
                    }

                    var rand_base = random_component::generate_assignments(
                        assignment, {params.batches}, row).output;
                    row += random_component::rows_amount;
                    var sg_rand_base = random_component::generate_assignments(
                        assignment, {params.batches}, row).output;
                    row += random_component::rows_amount;

                    var rand_base_i = one;
                    var sg_rand_base_i = one;

                    for (std::size_t batch_id = 0; batch_id < params.batches.size(); batch_id++) {
                        var cip = params.batches[batch_id].cip;

                        std::array<std::array<var, eval_rounds>, 2> challenges;
                        for (std::size_t j = 0; j < eval_rounds; j++) {
                            challenges[0][j] = endo_scalar_component::generate_assignments(
                                assignment,
                                {params.batches[batch_id].fq_output.challenges[j]},
                                row).output;
                            row += endo_scalar_component::rows_amount;

                            challenges[1][j] = sub_component::generate_assignments(
                                assignment, {zero, challenges[0][j]}, row).output;
                            row += sub_component::rows_amount;
                        }

                        var c = endo_scalar_component::generate_assignments(
                                assignment,
                                {params.batches[batch_id].fq_output.c},
                                row).output;
                        row += endo_scalar_component::rows_amount;

                        var b0_scale = one;
                        var b0 = zero;

                        for (std::size_t i = 0; i < KimchiParamsType::eval_points_amount; i++) {
                            var term = b_poly_component::generate_assignments(
                                assignment,
                                {challenges[0], params.batches[batch_id].eval_points[i],
                                one}, row).output;
                            row += b_poly_component::rows_amount;

                            var tmp = mul_component::generate_assignments(
                                assignment, {b0_scale, term}, row).output;
                            row += mul_component::rows_amount;

                            b0 = add_component::generate_assignments(
                                assignment, {b0, tmp}, row).output;
                            row += add_component::rows_amount;

                            b0_scale = mul_component::generate_assignments(
                                assignment, {b0_scale, params.batches[batch_id].r}, row).output;
                            row += mul_component::rows_amount;
                        }

                        auto s = b_poly_coeff_component::generate_assignments(
                            assignment, {challenges[0], one}, row).output;
                        row += b_poly_coeff_component::rows_amount;

                        var neg_rand_base_i = mul_by_const_component::generate_assignments(
                            assignment, {rand_base_i, -1}, row).output;
                        row += mul_by_const_component::rows_amount;

                        // neg_rand_base_i * opening.z1 - sg_rand_base_i
                        var tmp = mul_component::generate_assignments(
                            assignment, {neg_rand_base_i, params.batches[batch_id].opening.z1},
                            row).output;
                        row += mul_component::rows_amount;

                        tmp = sub_component::generate_assignments(
                            assignment, {tmp, sg_rand_base_i}, row).output;
                        row += sub_component::rows_amount;
                        scalars[scalar_idx++] = tmp;

                        for (std::size_t i = 0; i < s.size(); i++) {
                            var sg_s = mul_component::generate_assignments(
                                assignment, {sg_rand_base_i, s[i]},
                                row).output;
                            row += mul_component::rows_amount;

                            scalars[i] = add_component::generate_assignments(
                                assignment, {scalars[i], sg_s}, row).output;
                            row += add_component::rows_amount;
                        }

                        var rand_base_z2 = mul_component::generate_assignments(
                            assignment, {rand_base_i,
                            params.batches[batch_id].opening.z2},
                            row).output;
                        row += mul_component::rows_amount;

                        scalars[0] = sub_component::generate_assignments(
                            assignment, {scalars[0], rand_base_z2},
                            row).output;
                        row += sub_component::rows_amount;

                        // neg_rand_base_i * (opening.z1 * b0)
                        var z1_b0 = mul_component::generate_assignments(
                            assignment, {b0,
                            params.batches[batch_id].opening.z1},
                            row).output;
                        row += mul_component::rows_amount;
                        scalars[scalar_idx++] = mul_component::generate_assignments(
                            assignment, {z1_b0,
                            neg_rand_base_i},
                            row).output;
                        row += mul_component::rows_amount;

                        var c_rand_base_i = mul_component::generate_assignments(
                                assignment, {c,
                                rand_base_i},
                                row).output;
                        row += mul_component::rows_amount;
                        for (std::size_t i = 0; i < eval_rounds; i++) {
                            // rand_base_i_c_i * u_inv
                            scalars[scalar_idx++] = mul_component::generate_assignments(
                                assignment, {challenges[1][i],
                                c_rand_base_i},
                                row).output;
                            row += mul_component::rows_amount;

                            // rand_base_i_c_i * u
                            scalars[scalar_idx++] = mul_component::generate_assignments(
                                assignment, {challenges[0][i],
                                c_rand_base_i},
                                row).output;
                            row += mul_component::rows_amount;
                        }

                        var xi_i = one;
                        for (std::size_t i = 0; i < kimchi_constants::evaluations_in_batch_size; i++) {
                            // iterating over the polynomial segments + shifted part
                            for (std::size_t j = 0;
                                j < KimchiParamsType::commitment_params_type::shifted_commitment_split + 1;
                                j++) {

                                // rand_base_i_c_i * xi_i
                                scalars[scalar_idx++] = mul_component::generate_assignments(
                                    assignment, {xi_i,
                                    c_rand_base_i},
                                    row).output;
                                row += mul_component::rows_amount;

                                xi_i = mul_component::generate_assignments(
                                    assignment, {xi_i,
                                    params.batches[batch_id].xi},
                                    row).output;
                                row += mul_component::rows_amount;
                            }
                        }

                        // rand_base_i_c_i * combined_inner_product0
                        scalars[scalar_idx++] = mul_component::generate_assignments(
                            assignment, {cip,
                            c_rand_base_i},
                            row).output;
                        row += mul_component::rows_amount;

                        scalars[scalar_idx++] = rand_base_i;

                        rand_base_i = mul_component::generate_assignments(assignment,
                            {rand_base_i, rand_base}, row).output;
                        row += mul_component::rows_amount;

                        sg_rand_base_i = mul_component::generate_assignments(assignment,
                            {sg_rand_base_i, sg_rand_base}, row).output;
                        row += mul_component::rows_amount;
                    }

                    scalars = prepare_scalars_component::generate_assignments(assignment,
                        {scalars}, row).output;
                    row += prepare_scalars_component::rows_amount;

                    assert(row == start_row_index + rows_amount);
                    assert(scalar_idx == kimchi_constants::final_msm_size(BatchSize) - 1);

                    result_type res(start_row_index);
                    res.output = scalars;
                    return res;
                }

            private:

                static void generate_gates(
                    blueprint<ArithmetizationType> &bp,
                    blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                    const params_type &params,
                    const std::size_t first_selector_index) {

                }

                static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                              blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                              const params_type &params,
                                              const std::size_t start_row_index) {
                    std::size_t row = start_row_index;

                }

                static void
                    generate_assignments_constant(blueprint<ArithmetizationType> &bp,
                                              blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                              const params_type &params,
                                              std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        assignment.constant(0)[row] = 0;
                        row++;
                        assignment.constant(0)[row] = 1;
                        row++;
                }
            };

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_BATCH_VERIFY_SCALAR_FIELD_HPP