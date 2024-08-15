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
// @file Declaration of interfaces for auxiliary components for the BASE_FIELD component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_BASE_FIELD_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_BASE_FIELD_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/transcript_fq.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/types.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/multi_scalar_mul_15_wires.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/variable_base_scalar_mul.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/unified_addition.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/commitment.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/batch_verify_base_field.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/map_fq.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/column_type.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/index_term_type.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                // base field part of batch_verify
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/verifier.rs#L911
                // Input: list of mina-proofs (base field part),
                //     precalculated fq_data and fr_data (the data that used both by scalar and base verifiers)
                //     verifier index (public data)
                // Output: -
                template<typename ArithmetizationType, typename CurveType, typename KimchiParamsType,
                         typename KimchiCommitmentParamsType, std::size_t BatchSize, std::size_t... WireIndexes>
                class base_field;

                template<typename BlueprintFieldType, typename CurveType,
                         typename KimchiParamsType, typename KimchiCommitmentParamsType, std::size_t BatchSize,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class base_field<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, CurveType,
                                 KimchiParamsType, KimchiCommitmentParamsType, BatchSize, W0, W1, W2, W3, W4, W5, W6,
                                 W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>
                        ArithmetizationType;

                    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using const_mul_component = zk::components::mul_by_constant<ArithmetizationType, W0, W1>;
                    using table_comm_component =
                        zk::components::table_commitment<ArithmetizationType, KimchiParamsType, CurveType, W0, W1, W2, W3, W4, W5,
                                                         W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using proof_type = kimchi_proof_base<BlueprintFieldType, KimchiParamsType>;
                    using kimchi_constants = zk::components::kimchi_inner_constants<KimchiParamsType>;

                    constexpr static const std::size_t f_comm_base_size = kimchi_constants::f_comm_msm_size;

                    using msm_component =
                        zk::components::element_g1_multi_scalar_mul<ArithmetizationType, CurveType, f_comm_base_size,
                                                                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11,
                                                                    W12, W13, W14>;
                    using lagrange_msm_component =
                        zk::components::element_g1_multi_scalar_mul<ArithmetizationType, CurveType,
                                                                    KimchiParamsType::public_input_size, W0, W1, W2, W3,
                                                                    W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using scalar_mul_component =
                        zk::components::curve_element_variable_base_scalar_mul<ArithmetizationType, CurveType, W0, W1,
                                                                               W2, W3, W4, W5, W6, W7, W8, W9, W10, W11,
                                                                               W12, W13, W14>;
                    using add_component =
                        zk::components::curve_element_unified_addition<ArithmetizationType, CurveType, W0, W1, W2, W3,
                                                                       W4, W5, W6, W7, W8, W9, W10>;

                    using proof_binding =
                        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, KimchiParamsType>;

                    using map_fq_component = zk::components::map_fq<ArithmetizationType, CurveType, KimchiParamsType,
                                                                    KimchiCommitmentParamsType, BatchSize, 0, 1, 2, 3,
                                                                    4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

                    using batch_proof_type = typename zk::components::batch_evaluation_proof_base<
                        BlueprintFieldType, ArithmetizationType, KimchiParamsType, KimchiCommitmentParamsType>;

                    using verifier_index_type = kimchi_verifier_index_base<CurveType, KimchiParamsType>;

                    using index_terms_list = typename KimchiParamsType::circuit_params::index_terms_list;

                    using commitment_type = typename zk::components::kimchi_commitment_type<
                        BlueprintFieldType, KimchiCommitmentParamsType::shifted_commitment_split>;

                    using batch_verify_component =
                        zk::components::batch_verify_base_field<ArithmetizationType, CurveType, KimchiParamsType,
                                                                KimchiCommitmentParamsType, BatchSize, W0, W1, W2, W3,
                                                                W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using transcript_type = kimchi_transcript_fq<ArithmetizationType, CurveType, W0, W1, W2, W3, W4, W5,
                                                                 W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    constexpr static const std::size_t selector_seed = 0xff91;

                    constexpr static const std::size_t rows() {
                        std::size_t row = 0;

                        row++;

                        for (std::size_t i = 0; i < BatchSize; i++) {
                            row = row + lagrange_msm_component::rows_amount;

                            // Oracles
                            row += transcript_type::init_rows;

                            row += transcript_type::absorb_group_rows;

                            row += KimchiParamsType::circuit_params::witness_columns *
                                   KimchiParamsType::witness_commitment_size * transcript_type::absorb_group_rows;

                            if (KimchiParamsType::circuit_params::use_lookup) {
                                if (KimchiParamsType::circuit_params::lookup_runtime) {
                                    row += KimchiParamsType::lookup_runtime_commitment_size *
                                           transcript_type::absorb_group_rows;
                                }

                                if (KimchiParamsType::circuit_params::joint_lookup) {
                                    row += transcript_type::challenge_rows;
                                }

                                row += KimchiParamsType::circuit_params::lookup_columns *
                                       KimchiParamsType::lookup_sorted_commitment_size *
                                       transcript_type::absorb_group_rows;
                            }

                            row += transcript_type::challenge_rows;
                            row += transcript_type::challenge_rows;

                            if (KimchiParamsType::circuit_params::use_lookup) {
                                row += KimchiParamsType::lookup_aggregated_commitment_size *
                                       transcript_type::absorb_group_rows;
                            }

                            row += KimchiParamsType::z_commitment_size * transcript_type::absorb_group_rows;

                            row += transcript_type::challenge_rows;

                            row += KimchiParamsType::t_commitment_size * transcript_type::absorb_group_rows;

                            row += transcript_type::challenge_rows;

                            row += transcript_type::digest_rows;

                            // Oracles end

                            for (std::size_t j = 0; j < KimchiCommitmentParamsType::max_comm_size; j++) {
                                row += msm_component::rows_amount;
                            }

                            for (std::size_t j = 0; j < KimchiCommitmentParamsType::max_comm_size; j++) {
                                row += scalar_mul_component::rows_amount;
                                row += add_component::rows_amount;
                            }

                            for (std::size_t j = 0; j < KimchiParamsType::t_commitment_size; j++) {
                                row += scalar_mul_component::rows_amount;
                                row += add_component::rows_amount;
                            }
                            row += scalar_mul_component::rows_amount;
                            row += const_mul_component::rows_amount;

                            row += add_component::rows_amount;

                            if (KimchiParamsType::circuit_params::use_lookup) {
                                row += table_comm_component::rows_amount;
                            }
                        }

                        row += batch_verify_component::rows_amount;

                        row += map_fq_component::rows_amount;

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();

                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::array<proof_type, BatchSize> proofs;
                        verifier_index_type verifier_index;

                        typename proof_binding::template fr_data<var, BatchSize> fr_data;
                        typename proof_binding::template fq_data<var> fq_data;
                    };

                    struct result_type {

                        result_type(std::size_t start_row_index) {
                        }
                    };

                private:
                    template<typename CommitmentType>
                    static void parse_commitments(
                        std::array<std::vector<var_ec_point>, f_comm_base_size> &unshifted_commitments,
                        CommitmentType comm,
                        std::size_t &comm_idx) {

                        for (std::size_t k = 0; k < comm.parts.size(); k++) {
                            unshifted_commitments[comm_idx].push_back(comm.parts[k]);
                        }
                        comm_idx++;
                    }

                    static std::array<std::vector<var_ec_point>, f_comm_base_size>
                        prepare_f_comm(const params_type &params, std::size_t batch_idx) {

                        std::array<std::vector<var_ec_point>, f_comm_base_size> unshifted_commitments;
                        std::size_t comm_idx = 0;

                        typename proof_type::commitments_type comm = params.proofs[batch_idx].comm;
                        typename verifier_index_type::commitments_type index_comm = params.verifier_index.comm;

                        parse_commitments(unshifted_commitments,
                                          params.verifier_index.comm.sigma[KimchiParamsType::permut_size - 1],
                                          comm_idx);

                        // take generic_size coeff_comm
                        std::array<commitment_type, kimchi_constants::ft_generic_size> generic_comm;
                        for (std::size_t i = 0; i < generic_comm.size(); i++) {
                            generic_comm[i] = params.verifier_index.comm.coefficient[i];
                        }

                        for (std::size_t i = 0; i < kimchi_constants::ft_generic_size; i++) {
                            parse_commitments(unshifted_commitments, generic_comm[i], comm_idx);
                        }

                        for (std::size_t i = 0; i < index_terms_list::size; i++) {
                            index_term_type term = index_terms_list::terms[i];
                            switch (term.type) {
                                case column_type::Witness:
                                    parse_commitments(unshifted_commitments, comm.witness[term.index], comm_idx);
                                    break;
                                case column_type::Coefficient:
                                    parse_commitments(unshifted_commitments, index_comm.coefficient[term.index],
                                                      comm_idx);
                                    break;
                                case column_type::Z:
                                    parse_commitments(unshifted_commitments, comm.z, comm_idx);
                                    break;
                                case column_type::LookupSorted:
                                    parse_commitments(unshifted_commitments, comm.lookup_sorted[term.index], comm_idx);
                                    break;
                                case column_type::LookupAggreg: {
                                    parse_commitments(unshifted_commitments, comm.lookup_agg, comm_idx);
                                    break;
                                }
                                case column_type::LookupKindIndex: {
                                    parse_commitments(unshifted_commitments, index_comm.lookup_selectors[term.index],
                                                      comm_idx);
                                    break;
                                }
                                case column_type::LookupRuntimeSelector: {
                                    parse_commitments(unshifted_commitments, index_comm.runtime_tables_selector,
                                                      comm_idx);
                                    break;
                                }
                                case column_type::CompleteAdd: {
                                    parse_commitments(unshifted_commitments, index_comm.complete_add, comm_idx);
                                    break;
                                }
                                case column_type::VarBaseMul: {
                                    parse_commitments(unshifted_commitments, index_comm.var_base_mul, comm_idx);
                                    break;
                                }
                                case column_type::EndoMul: {
                                    parse_commitments(unshifted_commitments, index_comm.endo_mul, comm_idx);
                                    break;
                                }
                                case column_type::EndoMulScalar: {
                                    parse_commitments(unshifted_commitments, index_comm.endo_mul_scalar, comm_idx);
                                    break;
                                }
                                case column_type::Poseidon: {
                                    parse_commitments(unshifted_commitments, index_comm.psm, comm_idx);
                                    break;
                                }
                                case column_type::ChaCha0: {
                                    parse_commitments(unshifted_commitments, index_comm.chacha[0], comm_idx);
                                    break;
                                }
                                case column_type::ChaCha1: {
                                    parse_commitments(unshifted_commitments, index_comm.chacha[1], comm_idx);
                                    break;
                                }
                                case column_type::ChaCha2: {
                                    parse_commitments(unshifted_commitments, index_comm.chacha[2], comm_idx);
                                    break;
                                }
                                case column_type::ChaChaFinal: {
                                    parse_commitments(unshifted_commitments, index_comm.chacha[3], comm_idx);
                                    break;
                                }
                                case column_type::RangeCheck0: {
                                    parse_commitments(unshifted_commitments, index_comm.range_check[0], comm_idx);
                                    break;
                                }
                                case column_type::RangeCheck1: {
                                    parse_commitments(unshifted_commitments, index_comm.range_check[1], comm_idx);
                                    break;
                                }
                                case column_type::LookupTable:
                                    break;
                                case column_type::LookupRuntimeTable:
                                    break;
                            }
                        }

                        assert(comm_idx == f_comm_base_size);

                        return unshifted_commitments;
                    }

                public:
                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        std::array<batch_proof_type, BatchSize> batch_proofs;
                        var zero(0, row, false, var::column_type::constant);
                        row++;

                        for (std::size_t i = 0; i < BatchSize; i++) {

                            // p_comm is always the commitment of size 1
                            auto p_comm_unshifted =
                                lagrange_msm_component::generate_assignments(
                                    assignment, {params.fr_data.neg_pub, params.verifier_index.lagrange_bases}, row)
                                    .output;
                            row = row + lagrange_msm_component::rows_amount;

                            // Oracles
                            transcript_type transcript;
                            transcript.init_assignment(assignment, zero, row);
                            row += transcript_type::init_rows;

                            transcript.absorb_g_assignment(assignment, p_comm_unshifted, row);
                            row += transcript_type::absorb_group_rows;

                            for (std::size_t j = 0; j < params.proofs[i].comm.witness.size(); j++) {
                                for (std::size_t k = 0; k < params.proofs[i].comm.witness[j].parts.size(); k++) {
                                    transcript.absorb_g_assignment(assignment,
                                                                   params.proofs[i].comm.witness[j].parts[k], row);
                                    row += transcript_type::absorb_group_rows;
                                }
                            }

                            var joint_combiner;

                            if (KimchiParamsType::circuit_params::use_lookup) {
                                if (KimchiParamsType::circuit_params::lookup_runtime) {
                                    for (std::size_t k = 0; k < params.proofs[i].comm.lookup_runtime.parts.size();
                                         k++) {
                                        transcript.absorb_g_assignment(
                                            assignment, params.proofs[i].comm.lookup_runtime.parts[k], row);
                                        row += transcript_type::absorb_group_rows;
                                    }
                                }

                                if (KimchiParamsType::circuit_params::joint_lookup) {
                                    joint_combiner = transcript.challenge_assignment(assignment, row);
                                    row += transcript_type::challenge_rows;
                                } else {
                                    joint_combiner = zero;
                                }

                                for (std::size_t j = 0; j < params.proofs[i].comm.lookup_sorted.size(); j++) {
                                    for (std::size_t k = 0; k < params.proofs[i].comm.lookup_sorted[j].parts.size();
                                         k++) {
                                        transcript.absorb_g_assignment(
                                            assignment, params.proofs[i].comm.lookup_sorted[j].parts[k], row);
                                        row += transcript_type::absorb_group_rows;
                                    }
                                }
                            }

                            var beta = transcript.challenge_assignment(assignment, row);
                            row += transcript_type::challenge_rows;

                            var gamma = transcript.challenge_assignment(assignment, row);
                            row += transcript_type::challenge_rows;

                            if (KimchiParamsType::circuit_params::use_lookup) {
                                for (std::size_t k = 0; k < params.proofs[i].comm.lookup_agg.parts.size(); k++) {
                                    transcript.absorb_g_assignment(assignment,
                                                                   params.proofs[i].comm.lookup_agg.parts[k], row);
                                    row += transcript_type::absorb_group_rows;
                                }
                            }

                            for (std::size_t k = 0; k < params.proofs[i].comm.z.parts.size(); k++) {
                                transcript.absorb_g_assignment(assignment, params.proofs[i].comm.z.parts[k], row);
                                row += transcript_type::absorb_group_rows;
                            }

                            var alpha = transcript.challenge_assignment(assignment, row);
                            row += transcript_type::challenge_rows;

                            for (std::size_t k = 0; k < params.proofs[i].comm.t.parts.size(); k++) {
                                transcript.absorb_g_assignment(assignment, params.proofs[i].comm.t.parts[k], row);
                                row += transcript_type::absorb_group_rows;
                            }

                            var zeta = transcript.challenge_assignment(assignment, row);
                            row += transcript_type::challenge_rows;

                            var digest = transcript.digest_assignment(assignment, row);
                            row += transcript_type::digest_rows;

                            // Oracles end

                            // f_comm
                            std::array<std::vector<var_ec_point>, f_comm_base_size> f_comm_bases =
                                prepare_f_comm(params, i);

                            std::array<var_ec_point, KimchiCommitmentParamsType::max_comm_size> f_comm;
                            for (std::size_t j = 0; j < KimchiCommitmentParamsType::max_comm_size; j++) {
                                std::array<var_ec_point, f_comm_base_size> bases;
                                std::array<var, f_comm_base_size> scalars;
                                for (std::size_t k = 0; k < f_comm_base_size; k++) {
                                    if (j < f_comm_bases[k].size()) {
                                        bases[k] = f_comm_bases[k][j];
                                        scalars[k] = params.proofs[i].scalars[k];
                                    } else {
                                        bases[k] = {zero, zero};
                                        scalars[k] = zero;
                                    }
                                }
                                auto res = msm_component::generate_assignments(assignment, {scalars, bases}, row);
                                f_comm[j] = {res.output.X, res.output.Y};
                                row += msm_component::rows_amount;
                            }

                            // chuncked_f_comm
                            var_ec_point chuncked_f_comm = {zero, zero};

                            for (std::size_t j = 0; j < f_comm.size(); j++) {
                                auto res0 = scalar_mul_component::generate_assignments(
                                    assignment,
                                    {{chuncked_f_comm.X, chuncked_f_comm.Y}, params.fr_data.zeta_to_srs_len[i]}, row);
                                row += scalar_mul_component::rows_amount;
                                auto res1 = add_component::generate_assignments(
                                    assignment, {{res0.X, res0.Y}, {f_comm[j].X, f_comm[j].Y}}, row);
                                row += add_component::rows_amount;
                                chuncked_f_comm = {res1.X, res1.Y};
                            }

                            // chunked_t_comm
                            var_ec_point chunked_t_comm = {zero, zero};
                            ;
                            for (std::size_t j = 0; j < params.proofs[i].comm.t.parts.size(); j++) {
                                auto res0 = scalar_mul_component::generate_assignments(
                                    assignment,
                                    {{chunked_t_comm.X, chunked_t_comm.Y}, params.fr_data.zeta_to_srs_len[i]}, row);
                                row += scalar_mul_component::rows_amount;

                                auto res1 = add_component::generate_assignments(
                                    assignment,
                                    {{res0.X, res0.Y},
                                     {params.proofs[i].comm.t.parts[j].X, params.proofs[i].comm.t.parts[j].Y}},
                                    row);
                                row += add_component::rows_amount;
                                chunked_t_comm = {res1.X, res1.Y};
                            }

                            // ft_comm

                            auto scaled_t_comm = scalar_mul_component::generate_assignments(
                                assignment,
                                {{chunked_t_comm.X, chunked_t_comm.Y}, params.fr_data.zeta_to_domain_size_minus_1},
                                row);
                            row += scalar_mul_component::rows_amount;

                            typename BlueprintFieldType::value_type minus_1 = -1;
                            var const_res_unshifted =
                                const_mul_component::generate_assignments(assignment, {scaled_t_comm.Y, minus_1}, row)
                                    .output;
                            row += const_mul_component::rows_amount;

                            var_ec_point neg_scaled_t_comm = {scaled_t_comm.X, const_res_unshifted};

                            auto ft_comm_part = add_component::generate_assignments(
                                assignment,
                                {{neg_scaled_t_comm.X, neg_scaled_t_comm.Y}, {chuncked_f_comm.X, chuncked_f_comm.Y}},
                                row);
                            row += add_component::rows_amount;
                            commitment_type ft_comm = {{{ft_comm_part.X, ft_comm_part.Y}}};
                            for (std::size_t j = 1;
                                 j < KimchiParamsType::commitment_params_type::shifted_commitment_split;
                                 j++) {
                                ft_comm.parts[j] = {zero, zero};
                            }

                            // evaluations

                            std::array<commitment_type, kimchi_constants::evaluations_in_batch_size> evaluations;
                            std::size_t eval_idx = 0;

                            for (auto chal : params.proofs[i].comm.prev_challenges) {
                                evaluations[eval_idx++] = chal;
                            }

                            commitment_type p_comm = {{{p_comm_unshifted.X, p_comm_unshifted.Y}}};
                            for (std::size_t j = 1;
                                 j < KimchiParamsType::commitment_params_type::shifted_commitment_split;
                                 j++) {
                                ft_comm.parts[j] = {zero, zero};
                            }
                            evaluations[eval_idx++] = p_comm;
                            evaluations[eval_idx++] = ft_comm;
                            evaluations[eval_idx++] = params.proofs[i].comm.z;
                            evaluations[eval_idx++] = params.verifier_index.comm.generic;
                            evaluations[eval_idx++] = params.verifier_index.comm.psm;

                            for (std::size_t j = 0; j < params.proofs[i].comm.witness.size(); j++) {
                                evaluations[eval_idx++] = params.proofs[i].comm.witness[j];
                            }
                            for (std::size_t j = 0; j < params.verifier_index.comm.sigma.size() - 1; j++) {
                                evaluations[eval_idx++] = params.verifier_index.comm.sigma[j];
                            }

                            if (KimchiParamsType::circuit_params::use_lookup) {
                                for (std::size_t j = 0; j < params.proofs[i].comm.lookup_sorted.size(); j++) {
                                    evaluations[eval_idx++] = params.proofs[i].comm.lookup_sorted[j];
                                }

                                evaluations[eval_idx++] = params.proofs[i].comm.lookup_agg;

                                evaluations[eval_idx++] = table_comm_component::generate_assignments(
                                                              assignment,
                                                              {params.verifier_index.comm.lookup_table, params.fr_data.joint_combiner_powers_prepared,
                                                               params.proofs[i].comm.lookup_runtime},
                                                              row)
                                                              .output;
                                row += table_comm_component::rows_amount;

                                if (KimchiParamsType::circuit_params::lookup_runtime) {
                                    evaluations[eval_idx++] = params.proofs[i].comm.lookup_runtime;
                                }
                            }

                            assert(eval_idx == kimchi_constants::evaluations_in_batch_size);

                            batch_proof_type p = {{evaluations}, params.proofs[i].o, transcript};

                            batch_proofs[i] = p;
                        }
                        typename batch_verify_component::params_type batch_params = {
                            batch_proofs, params.verifier_index, params.fr_data};
                        batch_verify_component::generate_assignments(assignment, batch_params, row);
                        row += batch_verify_component::rows_amount;

                        typename proof_binding::template fq_data<var> fq_data_recalculated;
                        map_fq_component::generate_assignments(assignment, {params.fq_data, fq_data_recalculated}, row);
                        row += map_fq_component::rows_amount;

                        assert(row == start_row_index + rows_amount);
                        return result_type(start_row_index);
                    }

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        generate_assignments_constant(assignment, params, start_row_index);

                        std::size_t row = start_row_index;
                        var zero(0, row, false, var::column_type::constant);
                        row++;

                        std::array<batch_proof_type, BatchSize> batch_proofs;
                        for (std::size_t i = 0; i < BatchSize; i++) {
                            auto p_comm_unshifted =
                                lagrange_msm_component::generate_circuit(
                                    bp, assignment, {params.fr_data.neg_pub, params.verifier_index.lagrange_bases}, row)
                                    .output;
                            row = row + lagrange_msm_component::rows_amount;

                            std::size_t row_tmp = row;

                            // Oracles
                            transcript_type transcript;
                            transcript.init_circuit(bp, assignment, zero, row);
                            row += transcript_type::init_rows;

                            transcript.absorb_g_circuit(bp, assignment, p_comm_unshifted, row);
                            row += transcript_type::absorb_group_rows;

                            for (std::size_t j = 0; j < params.proofs[i].comm.witness.size(); j++) {
                                for (std::size_t k = 0; k < params.proofs[i].comm.witness[j].parts.size(); k++) {
                                    transcript.absorb_g_circuit(bp, assignment,
                                                                params.proofs[i].comm.witness[j].parts[k], row);
                                    row += transcript_type::absorb_group_rows;
                                }
                            }

                            var joint_combiner;

                            if (KimchiParamsType::circuit_params::use_lookup) {
                                if (KimchiParamsType::circuit_params::lookup_runtime) {
                                    for (std::size_t k = 0; k < params.proofs[i].comm.lookup_runtime.parts.size();
                                         k++) {
                                        transcript.absorb_g_circuit(bp, assignment,
                                                                    params.proofs[i].comm.lookup_runtime.parts[k], row);
                                        row += transcript_type::absorb_group_rows;
                                    }
                                }

                                if (KimchiParamsType::circuit_params::joint_lookup) {
                                    joint_combiner = transcript.challenge_circuit(bp, assignment, row);
                                    row += transcript_type::challenge_rows;
                                } else {
                                    joint_combiner = zero;
                                }

                                for (std::size_t j = 0; j < params.proofs[i].comm.lookup_sorted.size(); j++) {
                                    for (std::size_t k = 0; k < params.proofs[i].comm.lookup_sorted[j].parts.size();
                                         k++) {
                                        transcript.absorb_g_circuit(
                                            bp, assignment, params.proofs[i].comm.lookup_sorted[j].parts[k], row);
                                        row += transcript_type::absorb_group_rows;
                                    }
                                }
                            }

                            var beta = transcript.challenge_circuit(bp, assignment, row);
                            row += transcript_type::challenge_rows;

                            var gamma = transcript.challenge_circuit(bp, assignment, row);
                            row += transcript_type::challenge_rows;

                            if (KimchiParamsType::circuit_params::use_lookup) {
                                for (std::size_t k = 0; k < params.proofs[i].comm.lookup_agg.parts.size(); k++) {
                                    transcript.absorb_g_circuit(bp, assignment,
                                                                params.proofs[i].comm.lookup_agg.parts[k], row);
                                    row += transcript_type::absorb_group_rows;
                                }
                            }

                            for (std::size_t k = 0; k < params.proofs[i].comm.z.parts.size(); k++) {
                                transcript.absorb_g_circuit(bp, assignment, params.proofs[i].comm.z.parts[k], row);
                                row += transcript_type::absorb_group_rows;
                            }

                            var alpha = transcript.challenge_circuit(bp, assignment, row);
                            row += transcript_type::challenge_rows;

                            for (std::size_t k = 0; k < params.proofs[i].comm.t.parts.size(); k++) {
                                transcript.absorb_g_circuit(bp, assignment, params.proofs[i].comm.t.parts[k], row);
                                row += transcript_type::absorb_group_rows;
                            }

                            var zeta = transcript.challenge_circuit(bp, assignment, row);
                            row += transcript_type::challenge_rows;

                            var digest = transcript.digest_circuit(bp, assignment, row);
                            row += transcript_type::digest_rows;

                            // Oracles end

                            std::array<std::vector<var_ec_point>, f_comm_base_size> f_comm_bases =
                                prepare_f_comm(params, i);

                            std::array<var_ec_point, KimchiCommitmentParamsType::max_comm_size> f_comm;
                            for (std::size_t j = 0; j < KimchiCommitmentParamsType::max_comm_size; j++) {
                                std::array<var_ec_point, f_comm_base_size> bases;
                                std::array<var, f_comm_base_size> scalars;
                                for (std::size_t k = 0; k < f_comm_base_size; k++) {
                                    if (j < f_comm_bases[k].size()) {
                                        bases[k] = f_comm_bases[k][j];
                                        scalars[k] = params.proofs[i].scalars[k];
                                    } else {
                                        bases[k] = {zero, zero};
                                        scalars[k] = zero;
                                    }
                                }
                                auto res = msm_component::generate_circuit(bp, assignment, {scalars, bases}, row);
                                f_comm[j] = {res.output.X, res.output.Y};
                                row += msm_component::rows_amount;
                            }

                            // chuncked_f_comm
                            var_ec_point chuncked_f_comm = {zero, zero};

                            for (std::size_t j = 0; j < f_comm.size(); j++) {
                                auto res0 = scalar_mul_component::generate_circuit(
                                    bp, assignment,
                                    {{chuncked_f_comm.X, chuncked_f_comm.Y}, params.fr_data.zeta_to_srs_len[i]}, row);
                                row += scalar_mul_component::rows_amount;
                                auto res1 = zk::components::generate_circuit<add_component>(
                                    bp, assignment, {{res0.X, res0.Y}, {f_comm[j].X, f_comm[j].Y}}, row);
                                row += add_component::rows_amount;
                                chuncked_f_comm = {res1.X, res1.Y};
                            }

                            // chunked_t_comm
                            var_ec_point chunked_t_comm = {zero, zero};
                            ;
                            for (std::size_t j = 0; j < params.proofs[i].comm.t.parts.size(); j++) {
                                auto res0 = scalar_mul_component::generate_circuit(
                                    bp, assignment,
                                    {{chunked_t_comm.X, chunked_t_comm.Y}, params.fr_data.zeta_to_srs_len[i]}, row);
                                row += scalar_mul_component::rows_amount;

                                auto res1 = zk::components::generate_circuit<add_component>(
                                    bp, assignment,
                                    {{res0.X, res0.Y},
                                     {params.proofs[i].comm.t.parts[j].X, params.proofs[i].comm.t.parts[j].Y}},
                                    row);
                                row += add_component::rows_amount;
                                chunked_t_comm = {res1.X, res1.Y};
                            }

                            // ft_comm

                            auto scaled_t_comm = scalar_mul_component::generate_circuit(
                                bp, assignment,
                                {{chunked_t_comm.X, chunked_t_comm.Y}, params.fr_data.zeta_to_domain_size_minus_1},
                                row);
                            row += scalar_mul_component::rows_amount;

                            typename BlueprintFieldType::value_type minus_1 = -1;
                            var const_res_unshifted = zk::components::generate_circuit<const_mul_component>(
                                                          bp, assignment, {scaled_t_comm.Y, minus_1}, row)
                                                          .output;
                            row += const_mul_component::rows_amount;

                            var_ec_point neg_scaled_t_comm = {scaled_t_comm.X, const_res_unshifted};

                            auto ft_comm_part = zk::components::generate_circuit<add_component>(
                                bp, assignment,
                                {{neg_scaled_t_comm.X, neg_scaled_t_comm.Y}, {chuncked_f_comm.X, chuncked_f_comm.Y}},
                                row);
                            row += add_component::rows_amount;
                            commitment_type ft_comm = {{{ft_comm_part.X, ft_comm_part.Y}}};
                            for (std::size_t j = 1;
                                 j < KimchiParamsType::commitment_params_type::shifted_commitment_split;
                                 j++) {
                                ft_comm.parts[j] = {zero, zero};
                            }

                            // evaluations
                            std::array<commitment_type, kimchi_constants::evaluations_in_batch_size> evaluations;
                            std::size_t eval_idx = 0;
                            for (auto chal : params.proofs[i].comm.prev_challenges) {
                                evaluations[eval_idx++] = chal;
                            }

                            commitment_type p_comm = {{{p_comm_unshifted.X, p_comm_unshifted.Y}}};
                            for (std::size_t j = 1;
                                 j < KimchiParamsType::commitment_params_type::shifted_commitment_split;
                                 j++) {
                                ft_comm.parts[j] = {zero, zero};
                            }
                            evaluations[eval_idx++] = p_comm;
                            evaluations[eval_idx++] = ft_comm;
                            evaluations[eval_idx++] = params.proofs[i].comm.z;
                            evaluations[eval_idx++] = params.verifier_index.comm.generic;
                            evaluations[eval_idx++] = params.verifier_index.comm.psm;

                            for (std::size_t j = 0; j < params.proofs[i].comm.witness.size(); j++) {
                                evaluations[eval_idx++] = params.proofs[i].comm.witness[j];
                            }
                            for (std::size_t j = 0; j < params.verifier_index.comm.sigma.size() - 1; j++) {
                                evaluations[eval_idx++] = params.verifier_index.comm.sigma[j];
                            }

                            if (KimchiParamsType::circuit_params::use_lookup) {
                                for (std::size_t j = 0; j < params.proofs[i].comm.lookup_sorted.size(); j++) {
                                    evaluations[eval_idx++] = params.proofs[i].comm.lookup_sorted[j];
                                }

                                evaluations[eval_idx++] = params.proofs[i].comm.lookup_agg;

                                evaluations[eval_idx++] = table_comm_component::generate_circuit(
                                                              bp, assignment,
                                                              {params.verifier_index.comm.lookup_table, params.fr_data.joint_combiner_powers_prepared,
                                                               params.proofs[i].comm.lookup_runtime},
                                                              row)
                                                              .output;
                                row += table_comm_component::rows_amount;

                                if (KimchiParamsType::circuit_params::lookup_runtime) {
                                    evaluations[eval_idx++] = params.proofs[i].comm.lookup_runtime;
                                }
                            }

                            assert(eval_idx == kimchi_constants::evaluations_in_batch_size);

                            batch_proof_type p = {{evaluations}, params.proofs[i].o, transcript};

                            batch_proofs[i] = p;
                        }
                        typename batch_verify_component::params_type batch_params = {
                            batch_proofs, params.verifier_index, params.fr_data};
                        batch_verify_component::generate_circuit(bp, assignment, batch_params, row);
                        row += batch_verify_component::rows_amount;

                        typename proof_binding::template fq_data<var> fq_data_recalculated;
                        map_fq_component::generate_circuit(bp, assignment, {params.fq_data, fq_data_recalculated}, row);
                        row += map_fq_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        return result_type(start_row_index);
                    }

                private:
                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                    }

                    static void generate_assignments_constant(
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        assignment.constant(0)[row] = 0;
                    }
                };

            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_BASE_FIELD_HPP
