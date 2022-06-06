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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_TRANSCRIPT_FQ_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_TRANSCRIPT_FQ_HPP

#include <vector>
#include <array>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/limbs.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/sponge.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/proof.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // Fiat-Shamir transfotmation (base field part)
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/oracle/src/sponge.rs#L98
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/oracle/src/sponge.rs#L128
                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class kimchi_transcript_fq;

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
                class kimchi_transcript_fq<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                    struct fr_value {
                        var fq_value;
                        var bit;
                        fr_value(var first, var second) : fq_value(first), bit(second) {}
                    };

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

                    std::array<var, 2> squeeze_limbs_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                    std::size_t &component_start_row) {
                        if (last_squeezed.size() >= CHALLENGE_LENGTH_IN_LIMBS) {
                            std::array<var, 2> limbs = {last_squeezed[0], last_squeezed[1]};
                            std::vector<var> remaining = {last_squeezed.begin() + CHALLENGE_LENGTH_IN_LIMBS, last_squeezed.end()};
                            last_squeezed = remaining;
                            return limbs;
                        }
                        var sq = sponge.squeeze_assignment(assignment, component_start_row);
                        auto x = unpack_assignment(assignment, component_start_row, sq);
                        for (int i = 0 ; i < HIGH_ENTROPY_LIMBS; ++i) {
                            last_squeezed.push_back(x[i]);
                        }
                        return squeeze_limbs_assignment(assignment, component_start_row);
                    }

                    std::array<var, 2> squeeze_limbs_circuit(blueprint<ArithmetizationType> &bp,
                                                    blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                    std::size_t &component_start_row) {
                        if (last_squeezed.size() >= CHALLENGE_LENGTH_IN_LIMBS) {
                            std::array<var, 2> limbs = {last_squeezed[0], last_squeezed[1]};
                            std::vector<var> remaining = {last_squeezed.begin() + CHALLENGE_LENGTH_IN_LIMBS, last_squeezed.end()};
                            last_squeezed = remaining;
                            return limbs;
                        }
                        var sq = sponge.squeeze_circuit(assignment, component_start_row);
                        auto x = unpack_circuit(assignment, component_start_row, sq);
                        for (int i = 0 ; i < HIGH_ENTROPY_LIMBS; ++i) {
                            last_squeezed.push_back(x[i]);
                        }
                        return squeeze_limbs_circuit(assignment, component_start_row);
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

                    void absorb_g_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                           std::vector<std::array<var, 2>> group_values,
                                           std::size_t &component_start_row) {
                        //accepts a vector of arrays {g.X, g.Y}
                        last_squeezed = {};
                        for (auto g : group_values) {
                            sponge.absorb_assignment(assignment, g[0], component_start_row);
                            sponge.absorb_assignment(assignment, g[1], component_start_row);
                        }
                    }

                    void absorb_g_circuit(blueprint<ArithmetizationType> &bp,
                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                        std::vector<std::array<var, 2>> group_values,
                                        std::size_t &component_start_row) {
                        last_squeezed = {};
                        for (auto g : group_values) {
                            sponge.absorb_circuit(bp, assignment, g[0], component_start_row);
                            sponge.absorb_circuit(bp, assignment, g[1], component_start_row);
                        }
                    }

                    void absorb_fr_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                            fr_value absorbing_value,
                                            std::size_t &component_start_row) {
                        last_squeezed = {};
                        if (CurveType::base_field_type::modulus < CurveType::scalar_field_type::modulus) {
                            sponge.absorb_assignment(assignment, absorbing_value.fq_value, component_start_row);
                            sponge.absorb_assignment(assignment, absorbing_value.bit, component_start_row);
                        } else {
                            sponge.absorb_assignment(assignment, absorbing_value.fq_value, component_start_row);
                        }
                    }

                    void absorb_fr_circuit(blueprint<ArithmetizationType> &bp,
                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                        fr_value absorbing_value,
                                        std::size_t &component_start_row) {
                        last_squeezed = {};
                        if (CurveType::base_field_type::modulus < CurveType::scalar_field_type::modulus) {
                            sponge.absorb_circuit(bp, assignment, absorbing_value.fq_value, component_start_row);
                            sponge.absorb_circuit(bp, assignment, absorbing_value.bit, component_start_row);
                        } else {
                            sponge.absorb_circuit(bp, assignment, absorbing_value.fq_value, component_start_row);
                        }
                    }

                    var challenge_assignment(
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            std::size_t &component_start_row) {
                        auto limbs = squeeze_limbs_assignment(assignment, component_start_row);
                        return pack_assignment(assignment, component_start_row, limbs);
                    }

                    var challenge_generate_constraints(blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            std::size_t &component_start_row) {
                        auto limbs = squeeze_limbs_circuit(bp, assignment, component_start_row);
                        return pack_circuit(bp, assignment, component_start_row, limbs);
                    }

                    var challenge_fq_assignment(
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            std::size_t &component_start_row) {
                        last_squeezed = {};
                        return sponge.squeeze_assignment(assignment, component_start_row);
                    }

                    var challenge_fq_generate_constraints(blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            std::size_t &component_start_row) {
                        last_squeezed  = {};
                        return sponge.squeeze_circuit(bp, assignment, component_start_row);
                    }

                    var digest_assignment(
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            std::size_t &component_start_row) {
                        last_squeezed = {};
                        var sq = sponge.squeeze_assignment(assignment, component_start_row);
                        auto x = unpack_assignment(assignment, component_start_row, sq);
                        return pack_assignment(assignment, component_start_row, {x[0], x[1]});
                    }

                    var digest_circuit(blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            std::size_t &component_start_row) {
                        last_squeezed = {};
                        var sq = sponge.squeeze_circuit(bp, assignment, component_start_row);
                        auto x = unpack_circuit(bp, assignment, component_start_row, sq);
                        return pack_circuit(bp, assignment, component_start_row, {x[0], x[1]});
                    }

                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_TRANSCRIPT_FQ_HPP
