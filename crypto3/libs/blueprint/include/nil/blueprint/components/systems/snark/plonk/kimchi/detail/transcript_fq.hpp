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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_TRANSCRIPT_FQ_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_TRANSCRIPT_FQ_HPP

#include <vector>
#include <array>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/limbs.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/sponge.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/compare.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/types.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                // Fiat-Shamir transfotmation (base field part)
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/oracle/src/sponge.rs#L98
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/oracle/src/sponge.rs#L128
                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class kimchi_transcript_fq;

                template<typename BlueprintFieldType, typename CurveType,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4,
                         std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9,
                         std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class kimchi_transcript_fq<snark::plonk_constraint_system<BlueprintFieldType>,
                                           CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    using group_value = typename zk::components::var_ec_point<BlueprintFieldType>;

                    constexpr static bool scalar_larger() {
                        using ScalarField = typename CurveType::scalar_field_type;
                        using BaseField = typename CurveType::base_field_type;

                        auto n1 = ScalarField::modulus;
                        auto n2 = BaseField::modulus;
                        return (n1 > n2);
                    }

                    static const std::size_t fr_value_size = scalar_larger() ? 2 : 1;

                    struct fr_value {
                        std::array<var, fr_value_size> value;
                    };

                    static const std::size_t CHALLENGE_LENGTH_IN_LIMBS = 2;
                    static const std::size_t HIGH_ENTROPY_LIMBS = 2;

                    using sponge_component = kimchi_sponge<ArithmetizationType,
                                                           CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11,
                                                           W12, W13, W14>;
                    sponge_component sponge;

                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;

                    using pack = from_limbs<ArithmetizationType, W0, W1, W2>;
                    using unpack =
                        to_limbs<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    using compare = compare_with_const<ArithmetizationType, CurveType, W0, W1, W2>;

                    std::vector<var> last_squeezed;

                    std::array<var, 2>
                        squeeze_limbs_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                 std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        if (last_squeezed.size() >= CHALLENGE_LENGTH_IN_LIMBS) {
                            std::array<var, 2> limbs = {last_squeezed[0], last_squeezed[1]};
                            std::vector<var> remaining = {last_squeezed.begin() + CHALLENGE_LENGTH_IN_LIMBS,
                                                          last_squeezed.end()};
                            last_squeezed = remaining;
                            return limbs;
                        }
                        var sq = sponge.squeeze_assignment(assignment, row);
                        row += sponge_component::squeeze_rows;
                        auto x = unpack::generate_assignments(assignment, {sq}, row).result;
                        row += unpack::rows_amount;
                        for (int i = 0; i < HIGH_ENTROPY_LIMBS; ++i) {
                            last_squeezed.push_back(x[i]);
                        }
                        return squeeze_limbs_assignment(assignment, row);
                    }

                    std::array<var, 2>
                        squeeze_limbs_circuit(blueprint<ArithmetizationType> &bp,
                                              blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                              std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        if (last_squeezed.size() >= CHALLENGE_LENGTH_IN_LIMBS) {
                            std::array<var, 2> limbs = {last_squeezed[0], last_squeezed[1]};
                            std::vector<var> remaining = {last_squeezed.begin() + CHALLENGE_LENGTH_IN_LIMBS,
                                                          last_squeezed.end()};
                            last_squeezed = remaining;
                            return limbs;
                        }
                        var sq = sponge.squeeze_circuit(bp, assignment, row);
                        row += sponge_component::squeeze_rows;
                        auto x = unpack::generate_circuit(bp, assignment, {sq}, row).result;
                        row += unpack::rows_amount;
                        for (int i = 0; i < HIGH_ENTROPY_LIMBS; ++i) {
                            last_squeezed.push_back(x[i]);
                        }
                        return squeeze_limbs_circuit(bp, assignment, row);
                    }

                public:
                    constexpr static const std::size_t rows_amount = 0;
                    constexpr static const std::size_t init_rows = sponge_component::init_rows;
                    constexpr static const std::size_t absorb_group_rows = 2 * sponge_component::absorb_rows;
                    constexpr static const std::size_t absorb_fr_rows = fr_value_size * sponge_component::absorb_rows;
                    constexpr static const std::size_t challenge_rows =
                        sponge_component::squeeze_rows + unpack::rows_amount + pack::rows_amount;
                    constexpr static const std::size_t challenge_fq_rows = sponge_component::squeeze_rows;
                    constexpr static const std::size_t digest_rows =
                        sponge_component::squeeze_rows + compare::rows_amount + mul_component::rows_amount;

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
                        // accepts {g.X, g.Y}
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
                        // accepts {g.X, g.Y}
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
                        for (std::size_t i = 0; i < fr_value_size; i++) {
                            sponge.absorb_assignment(assignment, absorbing_value.value[i], row);
                            row += sponge_component::absorb_rows;
                        }
                    }

                    void absorb_fr_circuit(blueprint<ArithmetizationType> &bp,
                                           blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                           fr_value absorbing_value,
                                           std::size_t &component_start_row) {
                        std::size_t row = component_start_row;
                        last_squeezed = {};
                        for (std::size_t i = 0; i < fr_value_size; i++) {
                            sponge.absorb_circuit(bp, assignment, absorbing_value.value[i], row);
                            row += sponge_component::absorb_rows;
                        }
                    }

                    var challenge_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
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

                    var challenge_fq_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                std::size_t component_start_row) {
                        last_squeezed = {};
                        return sponge.squeeze_assignment(assignment, component_start_row);
                    }

                    var challenge_fq_circuit(blueprint<ArithmetizationType> &bp,
                                             blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                             std::size_t component_start_row) {
                        last_squeezed = {};
                        return sponge.squeeze_circuit(bp, assignment, component_start_row);
                    }

                    var digest_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                          std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        last_squeezed = {};
                        var sq = sponge.squeeze_assignment(assignment, row);
                        row += sponge_component::squeeze_rows;
                        if (scalar_larger()) {
                            return sq;
                        }
                        var compare_result = compare::generate_assignments(assignment, sq, row).output;
                        row += compare::rows_amount;
                        return mul_component::generate_assignments(assignment, {compare_result, sq}, row).output;
                    }

                    var digest_circuit(blueprint<ArithmetizationType> &bp,
                                       blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                       std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        last_squeezed = {};
                        var sq = sponge.squeeze_circuit(bp, assignment, row);
                        row += sponge_component::squeeze_rows;
                        if (scalar_larger()) {
                            return sq;
                        }
                        var compare_result = compare::generate_circuit(bp, assignment, sq, row).output;
                        row += compare::rows_amount;
                        return zk::components::generate_circuit<mul_component>(
                                   bp, assignment, {compare_result, sq}, row)
                            .output;
                    }
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_TRANSCRIPT_FQ_HPP
