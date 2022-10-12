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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFY_HETEROGENOUS_BASE_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFY_HETEROGENOUS_BASE_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/base_details/batch_dlog_accumulator_check_base.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // base field part of verify_generogenous
                // https://github.com/MinaProtocol/mina/blob/09348bccf281d54e6fa9dd2d8bbd42e3965e1ff5/src/lib/pickles/verify.ml#L30
                template<typename ArithmetizationType, typename CurveType, typename KimchiParamsType, 
                    std::size_t BatchSize, std::size_t... WireIndexes>
                class verify_generogenous_base;

                template<typename ArithmetizationParams, typename CurveType, typename KimchiParamsType,  
                         std::size_t BatchSize, std::size_t W0, std::size_t W1,
                         std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7,
                         std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12,
                         std::size_t W13, std::size_t W14>
                class verify_generogenous_base<
                    snark::plonk_constraint_system<typename CurveType::base_field_type, ArithmetizationParams>,
                    CurveType, KimchiParamsType, BatchSize,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    using BlueprintFieldType = typename CurveType::base_field_type;

                    using ArithmetizationType = snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

                    using KimchiCommitmentParamsType = typename KimchiParamsType::commitment_params_type;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;

                    using batch_verify_component =
                        zk::components::batch_dlog_accumulator_check_base<ArithmetizationType, CurveType, KimchiParamsType,
                                                                W0, W1, W2, W3,
                                                                W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    
                    using kimchi_verify_component = zk::components::base_field<ArithmetizationType,
                        CurveType, KimchiParamsType, KimchiCommitmentParamsType, BatchSize,
                        W0, W1, W2, W3,
                                W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using verifier_index_type = kimchi_verifier_index_base<CurveType, KimchiParamsType>;

                    constexpr static std::size_t rows() {
                        std::size_t row = 0;

                        row += batch_verify_component::rows_amount;

                        row += kimchi_verify_component::rows_amount;

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::vector<var_ec_point> comms;

                        std::array<proof_type, BatchSize> proofs;
                        verifier_index_type verifier_index;

                        typename proof_binding::template fr_data<var, BatchSize> fr_data;
                        typename proof_binding::template fq_data<var> fq_data;
                    };

                    struct result_type {
                        var output;
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {
                        std::size_t row = start_row_index;

                        batch_verify_component::generate_circuit(bp, assignmet,
                            {params.comms, params.verifier_index, params.fr_output}, row);
                        row += batch_verify_component::rows_amount;

                        kimchi_verify_component::generate_circuit(bp, assignmet,
                            {params.proofs, params.verifier_index, params.ft_data, params.fq_data}, row);
                        row += kimchi_verify_component::rows_amount;

                        return result_type();
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        batch_verify_component::generate_assignments(assignmet,
                            {params.comms, params.verifier_index, params.fr_output}, row);
                        row += batch_verify_component::rows_amount;

                        kimchi_verify_component::generate_assignments(assignmet,
                            {params.proofs, params.verifier_index, params.ft_data, params.fq_data}, row);
                        row += kimchi_verify_component::rows_amount;
                        
                        return result_type();
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFY_HETEROGENOUS_BASE_HPP