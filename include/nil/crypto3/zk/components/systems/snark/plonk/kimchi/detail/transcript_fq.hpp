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
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/compare.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/proof.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

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
                        var bit;
                        var fq_value;
                        fr_value(var first, var second) : bit(first), fq_value(second) {}
                        fr_value(std::array<var, 2> vec) : bit(vec[0]), fq_value(vec[1]) {}
                    };

                    struct group_value {
                        var X;
                        var Y;
                        group_value(var first, var second) : X(first), Y(second) {}
                        group_value(std::array<var, 2> vec) : X(vec[0]), Y(vec[1]) {}
                    };

                    const std::size_t CHALLENGE_LENGTH_IN_LIMBS = 2;
                    const std::size_t HIGH_ENTROPY_LIMBS = 2;

                    using sponge_component = kimchi_sponge<ArithmetizationType, CurveType,
                       W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    sponge_component sponge;

                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;

                    using pack = from_limbs<ArithmetizationType, W0, W1, W2>;
                    using unpack = to_limbs<ArithmetizationType, W0, W1, W2, W3, W4>;
                    using compare = compare_with_const<ArithmetizationType, CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    // using compare = compare_with_const<ArithmetizationType, CurveType, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>;

                    std::vector<var> last_squeezed;

                    std::array<var, 2> squeeze_limbs_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                    std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        if (last_squeezed.size() >= CHALLENGE_LENGTH_IN_LIMBS) {
                            std::array<var, 2> limbs = {last_squeezed[0], last_squeezed[1]};
                            std::vector<var> remaining = {last_squeezed.begin() + CHALLENGE_LENGTH_IN_LIMBS, last_squeezed.end()};
                            last_squeezed = remaining;
                            return limbs;
                        }
                        var sq = sponge.squeeze_assignment(assignment, row);
                        row += sponge_component::squeeze_rows;
                        auto x = unpack::generate_assignments(assignment, {sq}, component_start_row).result;
                        row += unpack::rows_amount;
                        for (int i = 0 ; i < HIGH_ENTROPY_LIMBS; ++i) {
                            last_squeezed.push_back(x[i]);
                        }
                        return squeeze_limbs_assignment(assignment, row);
                    }

                    std::array<var, 2> squeeze_limbs_circuit(blueprint<ArithmetizationType> &bp,
                                                    blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                    std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        if (last_squeezed.size() >= CHALLENGE_LENGTH_IN_LIMBS) {
                            std::array<var, 2> limbs = {last_squeezed[0], last_squeezed[1]};
                            std::vector<var> remaining = {last_squeezed.begin() + CHALLENGE_LENGTH_IN_LIMBS, last_squeezed.end()};
                            last_squeezed = remaining;
                            return limbs;
                        }
                        var sq = sponge.squeeze_circuit(bp, assignment, row);
                        row += sponge_component::squeeze_rows;
                        auto x = unpack::generate_circuit(bp, assignment, {sq}, component_start_row).result;
                        row += unpack::rows_amount;
                        for (int i = 0 ; i < HIGH_ENTROPY_LIMBS; ++i) {
                            last_squeezed.push_back(x[i]);
                        }
                        return squeeze_limbs_circuit(bp, assignment, row);
                    }

                    constexpr static bool scalar_larger() {
                        using ScalarField = typename CurveType::scalar_field_type;
                        using BaseField = typename CurveType::base_field_type;

                        auto n1 = ScalarField::modulus;
                        auto n2 = BaseField::modulus;
                        return n1 > n2;
                    }
                    
                public:
                    constexpr static const std::size_t rows_amount = 0;
                    constexpr static const std::size_t init_rows = sponge_component::init_rows;
                    constexpr static const std::size_t absorb_rows = 2 * sponge_component::absorb_rows;
                    constexpr static const std::size_t challenge_rows = 
                        sponge_component::squeeze_rows + unpack::rows_amount 
                        + pack::rows_amount;
                    constexpr static const std::size_t challenge_fq_rows = sponge_component::squeeze_rows;
                    constexpr static const std::size_t digest_rows = challenge_rows + compare::rows_amount
                        + sub_component::rows_amount + mul_component::rows_amount;

                    void init_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                         var zero,
                                         const std::size_t component_start_row) {
                        sponge.init_assignment(assignment, zero, component_start_row);
                        last_squeezed = {};
                    }

                    void init_circuit(blueprint<ArithmetizationType> &bp,
                                      blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                      const var &zero,
                                      const std::size_t component_start_row) {
                        sponge.init_circuit(bp, assignment, zero, component_start_row);
                        last_squeezed = {};
                    }

                    void absorb_g_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                        group_value g,
                                        std::size_t component_start_row) {
                        //accepts {g.X, g.Y}
                        std::size_t row = component_start_row;
                        last_squeezed = {};
                        sponge.absorb_assignment(assignment, g.X, row);
                        row += sponge_component::absorb_rows;
                        sponge.absorb_assignment(assignment, g.Y, row);
                    }

                    void absorb_g_circuit(blueprint<ArithmetizationType> &bp,
                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                        group_value g,
                                        std::size_t component_start_row) {
                        //accepts {g.X, g.Y}
                        std::size_t row = component_start_row;
                        last_squeezed = {};
                        sponge.absorb_circuit(bp, assignment, g.X, row);
                        row += sponge_component::absorb_rows;
                        sponge.absorb_circuit(bp, assignment, g.Y, row);
                    }

                    void absorb_fr_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                            fr_value absorbing_value,
                                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        last_squeezed = {};
                        if (scalar_larger()) {
                            sponge.absorb_assignment(assignment, absorbing_value.fq_value, row);
                            row += sponge_component::absorb_rows;
                            sponge.absorb_assignment(assignment, absorbing_value.bit, row);
                        } else {
                            sponge.absorb_assignment(assignment, absorbing_value.fq_value, row);
                        }
                    }

                    void absorb_fr_circuit(blueprint<ArithmetizationType> &bp,
                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                        fr_value absorbing_value,
                                        std::size_t &component_start_row) {
                        std::size_t row = component_start_row;
                        last_squeezed = {};
                        if (scalar_larger()) {
                            sponge.absorb_circuit(bp, assignment, absorbing_value.fq_value, row);
                            row += sponge_component::absorb_rows;
                            sponge.absorb_circuit(bp, assignment, absorbing_value.bit, row);
                        } else {
                            sponge.absorb_circuit(bp, assignment, absorbing_value.fq_value, row);
                        }
                    }

                    var challenge_assignment(
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        auto limbs = squeeze_limbs_assignment(assignment, row);
                        row += sponge_component::squeeze_rows;
                        row += unpack::rows_amount;
                        return pack::generate_assignments(assignment, limbs, row).result;
                    }

                    var challenge_circuit(blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        auto limbs = squeeze_limbs_circuit(bp, assignment, row);
                        row += sponge_component::squeeze_rows;
                        row += unpack::rows_amount;
                        return pack::generate_circuit(bp, assignment, limbs, row).result;
                    }

                    var challenge_fq_assignment(
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            std::size_t component_start_row) {
                        last_squeezed = {};
                        return sponge.squeeze_assignment(assignment, component_start_row);
                    }

                    var challenge_fq_circuit(blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            std::size_t component_start_row) {
                        last_squeezed  = {};
                        return sponge.squeeze_circuit(bp, assignment, component_start_row);
                    }

                    var digest_assignment(
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            const var &one,
                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        last_squeezed = {};
                        var sq = sponge.squeeze_assignment(assignment, row);
                        row += sponge_component::squeeze_rows;
                        auto x = unpack::generate_assignments(assignment, {sq}, row).result;
                        row += unpack::rows_amount;
                        var packed = pack::generate_assignments(assignment, {x[0], x[1]}, row).result;
                        row += pack::rows_amount;
                        if (scalar_larger()) {
                            return packed;
                        }
                        var compare_result = compare::generate_assignments(assignment, packed, row).output;
                        row += compare::rows_amount;
                        var bool_result = sub_component::generate_assignments(assignment, {one, compare_result}, row).output;
                        row += sub_component::rows_amount;
                        return mul_component::generate_assignments(assignment, {bool_result, packed}, row).output;
                    }

                    var digest_circuit(blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const var &one,
                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        last_squeezed = {};
                        var sq = sponge.squeeze_circuit(bp, assignment, row);
                        row += sponge_component::squeeze_rows;
                        auto x = unpack::generate_circuit(bp, assignment, {sq}, row).result;
                        row += unpack::rows_amount;
                        var packed = pack::generate_circuit(bp, assignment, {x[0], x[1]}, row).result;
                        row += pack::rows_amount;
                        if (scalar_larger()) {
                            return packed;
                        }
                        var compare_result = compare::generate_circuit(bp, assignment, packed, row).output;
                        row += compare::rows_amount;
                        var bool_result = zk::components::generate_circuit<sub_component>(bp, assignment, {one, compare_result}, row).output;
                        row += sub_component::rows_amount;
                        return zk::components::generate_circuit<mul_component>(bp, assignment, {bool_result, packed}, row).output;
                    }

                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_TRANSCRIPT_FQ_HPP
