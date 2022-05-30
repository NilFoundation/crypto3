//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_TRANSCRIPT_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_TRANSCRIPT_HPP

#include <vector>
#include <array>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/sponge.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/proof.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class kimchi_transcript;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
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
                class kimchi_transcript<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    const std::size_t CHALLENGE_LENGTH_IN_LIMBS = 2;
                    const std::size_t HIGH_ENTROPY_LIMBS = 2;

                    kimchi_sponge<ArithmetizationType, CurveType,
                       W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> sponge;
                    using pack = from_limbs<ArithmetizationType, CurveType, W0, W1, W2>;
                    using unpack = to_limbs<ArithmetizationType, CurveType, W0, W1, W2, W3, W4>;

                    std::vector<var> last_squeezed;
                    var result = var(W0, 0, false);

                    var pack_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                        std::size_t &component_start_row,
                                        std::array<var, 2> limbs) {
                        auto pack_res = pack::generate_assignments(assignment, limbs, component_start_row);
                        component_start_row += pack::rows_amount;
                        return pack_res.result;
                    }

                    var pack_circuit(blueprint<ArithmetizationType> &bp,
                                    blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                    std::size_t &component_start_row,
                                    std::array<var, 2> limbs) {
                        auto pack_res = pack::generate_circuit(bp, assignment, limbs, component_start_row);
                        component_start_row += pack::rows_amount;
                        return pack_res.result;
                    }

                    std::array<var, 4> unpack_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                    std::size_t &component_start_row,
                                                    var elem) {
                        auto unpack_res = unpack::generate_assignments(assignment, {elem}, component_start_row);
                        component_start_row += unpack::rows_amount;
                        return unpack_res.result;
                    }

                    std::array<var, 4> unpack_circuit(blueprint<ArithmetizationType> &bp,
                                                    blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                    std::size_t &component_start_row,
                                                    var elem) {
                        auto unpack_res = unpack::generate_circuit(bp, assignment, {elem}, component_start_row);
                        component_start_row += unpack::rows_amount;
                        return unpack_res.result;
                    }
                    
                public:
                    constexpr static const std::size_t rows_amount = 0;

                    void init_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                         std::size_t &component_start_row) {
                        sponge.init_assignment(assignment, component_start_row);
                        last_squeezed = {};
                        result = var(W0, component_start_row, false);
                        assignment.witness(W0)[component_start_row] = 0;

                        component_start_row++;
                    }

                    void init_circuit(blueprint<ArithmetizationType> &bp,
                                      blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                      const var &zero,
                                      std::size_t &component_start_row) {
                        sponge.init_circuit(bp, assignment, zero, component_start_row);
                        last_squeezed = {};
                        result = var(W0, component_start_row, false);
                        bp.add_copy_constraint({zero, result});

                        component_start_row++;
                    }

                    void absorb_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                           var absorbing_value,
                                           std::size_t &component_start_row) {
                        last_squeezed = {};
                        sponge.absorb_assignment(assignment, absorbing_value, component_start_row);
                    }

                    void absorb_evaluations_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                       var public_eval,
                                                       kimchi_proof_evaluations<CurveType>
                                                           private_eval,
                                                       std::size_t &component_start_row) {
                        std::vector<var> points = {public_eval, private_eval.z, private_eval.generic_selector, private_eval.poseidon_selector,
                                                private_eval.w[0], private_eval.w[1], private_eval.w[2], private_eval.w[3], private_eval.w[4],
                                                private_eval.w[5], private_eval.w[6], private_eval.w[7], private_eval.w[8], private_eval.w[9],
                                                private_eval.w[10], private_eval.w[11], private_eval.w[12], private_eval.w[13], private_eval.w[14],
                                                private_eval.s[0], private_eval.s[1], private_eval.s[2], private_eval.s[3], private_eval.s[4], private_eval.s[5]};
                        for (auto p : points) {
                            sponge.absorb_assignment(assignment, p, component_start_row);
                        }
                    }

                    void absorb_circuit(blueprint<ArithmetizationType> &bp,
                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                        const var &input,
                                        std::size_t &component_start_row) {
                        sponge.absorb_circuit(bp, assignment, input, component_start_row);
                    }

                    var challenge_assignment(
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            std::size_t &component_start_row) {
                        if (last_squeezed.size() >= CHALLENGE_LENGTH_IN_LIMBS) {
                            std::array<var, 2> limbs = {last_squeezed[0], last_squeezed[1]};
                            std::vector<var> remaining = {last_squeezed.begin() + CHALLENGE_LENGTH_IN_LIMBS, last_squeezed.end()};
                            last_squeezed = remaining;
                            return pack_assignment(assignment, component_start_row, limbs);
                        }
                        var sq = sponge.squeeze_assignment(assignment, component_start_row);
                        auto x = unpack_assignment(assignment, component_start_row, sq);
                        for (int i = 0 ; i < HIGH_ENTROPY_LIMBS; ++i) {
                            last_squeezed.push_back(x[i]);
                        }
                        return challenge_assignment(assignment, component_start_row);
                    }

                    var challenge_generate_constraints(blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            std::size_t &component_start_row) {
                        if (last_squeezed.size() >= CHALLENGE_LENGTH_IN_LIMBS) {
                            std::array<var, 2> limbs = {last_squeezed[0], last_squeezed[1]};
                            std::vector<var> remaining = {last_squeezed.begin() + CHALLENGE_LENGTH_IN_LIMBS, last_squeezed.end()};
                            last_squeezed = remaining;
                            return pack_circuit(bp, assignment, component_start_row, limbs);
                        }
                        var sq = sponge.squeeze_circuit(bp, assignment, component_start_row);
                        auto x = unpack_circuit(bp, assignment, component_start_row, sq);
                        for (int i = 0 ; i < HIGH_ENTROPY_LIMBS; ++i) {
                            last_squeezed.push_back(x[i]);
                        }
                        return challenge_generate_constraints(bp, assignment, component_start_row);
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_TRANSCRIPT_HPP
