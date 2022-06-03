//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_ORACLES_BASE_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_ORACLES_BASE_COMPONENT_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/sponge.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/endo_scalar.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/exponentiation.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/pickles/constants.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class oracles_base;

                template<typename ArithmetizationParams,
                         typename CurveType,
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
                class oracles_base<
                    snark::plonk_constraint_system<typename CurveType::scalar_field_type, ArithmetizationParams>,
                    CurveType,
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
                    W14> {

                    using BlueprintFieldType = typename CurveType::scalar_field_type;

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    using endo_scalar_component = zk::components::endo_scalar<ArithmetizationType,
                                                                              CurveType,
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
                                                                              W14>;
                    using from_limbs = zk::components::from_limbs<ArithmetizationType, CurveType, W0, W1, W2>;
                    using exponentiation_component = zk::components::exponentiation<ArithmetizationType,
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
                                                                                    W14>;

                    struct field_op_component {
                        using mul = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                        // TODO: change to add / sub
                        using add = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                        using sub = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    };

                public:
                    constexpr static const std::size_t selector_seed = 0x0f08;
                    constexpr static const std::size_t rows_amount = 50;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        kimchi_verifier_index_scalar<CurveType> verifier_index;
                        kimchi_proof_scalar<BlueprintFieldType> proof;
                        typename BlueprintFieldType::value_type joint_combiner;
                        typename BlueprintFieldType::value_type
                            beta;    // beta and gamma can be combined from limbs in the base circuit
                        typename BlueprintFieldType::value_type gamma;
                        typename BlueprintFieldType::value_type alpha;
                        typename BlueprintFieldType::value_type zeta;
                        typename BlueprintFieldType::value_type fq_digest;    // TODO overflow check
                    };

                    struct result_type {
                        struct random_oracles {
                            var joint_combiner;
                            var beta;
                            var gamma;
                            var alpha_chal;
                            var alpha;
                            var zeta;
                            var v;
                            var u;
                            var zeta_chal;
                            var v_chal;
                            var u_chal;
                        };

                        kimchi_transcript<ArithmetizationType, CurveType, 
                            W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10,
                            W11, W12, W13, W14> transcript;
                        var digest;
                        random_oracles oracles;
                        std::array<var, KimchiParamsType::alpha_powers_n> alpha_powers;
                        std::array<var, eval_points_amount> p_eval;
                        std::array<var, eval_points_amount> powers_of_eval_points_for_chunks;
                        // polys std::array<var, KimchiCommitmentParamsType::eval_rounds> prev_challenges;
                        var zeta_pow_n;
                        var ft_eval0;

                        result_type() {
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         std::size_t component_start_row) {

                        generate_gates(bp, assignment, params, component_start_row);
                        generate_copy_constraints(bp, assignment, params, component_start_row);

                        return result_type(params, component_start_row);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t component_start_row) {

                        return result_type(params, component_start_row);
                    }

                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               std::size_t component_start_row = 0) {
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t component_start_row = 0) {

                        std::size_t row = component_start_row;

                        /*std::array<var, 2> alpha_pub_limbs = {var(0, row, false, var::column_type::public_input),
                                var(0, row + 1, false, var::column_type::public_input)};
                        std::array<var, 2> zeta_pub_limbs = {var(0, row + 2, false, var::column_type::public_input),
                                var(0, row + 3, false, var::column_type::public_input)};

                        row += 4;

                        copy_constraints_from_limbs(bp, assignment, alpha_pub_limbs, row);
                        row++;
                        // copy endo-scalar
                        row += endo_scalar_component::rows_amount;

                        copy_constraints_from_limbs(bp, assignment, zeta_pub_limbs, row);
                        row++;
                        // copy endo-scalar
                        row += endo_scalar_component::rows_amount;*/
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_ORACLES_BASE_COMPONENT_HPP
