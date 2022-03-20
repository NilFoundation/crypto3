//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class curve_element_variable_base_endo_scalar_mul;

                template<typename BlueprintFieldType,
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
                class curve_element_variable_base_endo_scalar_mul<snark::plonk_constraint_system<BlueprintFieldType>,
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
                                                                  W14>
                    : public component<snark::plonk_constraint_system<BlueprintFieldType>> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType> arithmetization_type;
                    typedef blueprint<arithmetization_type> blueprint_type;

                    std::size_t j;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t required_rows_amount = 65;
                    constexpr static const std::size_t endo = 3;

                public:
                    struct init_params { };

                    struct assignment_params {
                        typename CurveType::template g1_type<>::value_type P;
                        typename CurveType::scalar_field_type::value_type b;
                    };

                    curve_element_variable_base_endo_scalar_mul(blueprint_type &bp,
                                                                const init_params &params = init_params()) :
                        component<arithmetization_type>(bp) {

                        // the last row is only for the n
                        j = this->bp.allocate_rows(required_rows_amount);
                    }

                    static std::size_t allocate_rows(blueprint<arithmetization_type> &in_bp) {
                        return in_bp.allocate_rows(required_rows_amount);
                    }

                    template<std::size_t SelectorColumns, std::size_t PublicInputColumns, std::size_t ConstantColumns>
                    void generate_gates(blueprint_public_assignment_table<arithmetization_type,
                                                                          SelectorColumns,
                                                                          PublicInputColumns,
                                                                          ConstantColumns> &public_assignment,
                                        std::size_t circuit_start_row = 0) {

                        std::size_t selector_index = public_assignment.add_selector(j, j + required_rows_amount - 2);

                        auto bit_check_1 = this->bp.add_bit_check(var(W11, 0));
                        auto bit_check_2 = this->bp.add_bit_check(var(W12, 0));
                        auto bit_check_3 = this->bp.add_bit_check(var(W13, 0));
                        auto bit_check_4 = this->bp.add_bit_check(var(W14, 0));

                        auto constraint_1 = this->bp.add_constraint(
                            ((1 + (endo - 1) * var(W12, 0)) * var(W0, 0) - var(W4, 0)) * var(W9, 0) -
                            ((2 * var(W11, 0) - 1) * var(W1, 0) - var(W5, 0)));
                        auto constraint_2 = this->bp.add_constraint(
                            (2 * var(W4, 0) - var(W9, 0) ^ 2 + (1 + (endo - 1) * var(W12, 0)) * var(W0, 0)) *
                                ((var(W4, 0) - var(W7, 0)) * var(W9, 0) + var(W8, 0) + var(W5, 0)) -
                            ((var(W4, 0) - var(W7, 0)) * 2 * var(W5, 0)));
                        auto constraint_3 = this->bp.add_constraint(
                            (var(W8, 0) + var(W5, 0)) ^
                            2 - ((var(W4, 0) - var(W7, 0)) ^
                                 2 * (var(W9, 0) ^ 2 - (1 + (endo - 1) * var(W12, 0)) * var(W0, 0) + var(W7, 0))));
                        auto constraint_4 = this->bp.add_constraint(
                            ((1 + (endo - 1) * var(W12, 0)) * var(W0, 0) - var(W7, 0)) * var(W10, 0) -
                            ((2 * var(W13, 0) - 1) * var(W1, 0) - var(W8, 0)));
                        auto constraint_5 = this->bp.add_constraint(
                            (2 * var(W7, 0) - var(W10, 0) ^ 2 + (1 + (endo - 1) * var(W14, 0)) * var(W0, 0)) *
                                ((var(W7, 0) - var(W4, +1)) * var(W10, 0) + var(W5, +1) + var(W8, 0)) -
                            ((var(W7, 0) - var(W4, +1)) * 2 * var(W8, 0)));
                        auto constraint_6 = this->bp.add_constraint(
                            (var(W4, +1) + var(W8, 0)) ^
                            2 - ((var(W7, 0) - var(W4, +1)) ^
                                 2 * (var(W10, 0) ^ 2 - (1 + (endo - 1) * var(W14, 0)) * var(W0, 0) + var(W4, +1))));
                        auto constraint_7 =
                            this->bp.add_constraint(var(W6, +1) - (16 * var(W6, 0) + 8 * var(W11, 0) + 4 * var(W12, 0) +
                                                                   2 * var(W13, 0) + var(W14, 0)));

                        this->bp.add_gate(selector_index,
                                          {bit_check_1, bit_check_2, bit_check_3, bit_check_4, constraint_1,
                                           constraint_2, constraint_3, constraint_4, constraint_5, constraint_6,
                                           constraint_7});
                    }

                    template<std::size_t SelectorColumns, std::size_t PublicInputColumns, std::size_t ConstantColumns>
                    void
                        generate_copy_constraints(blueprint_public_assignment_table<arithmetization_type,
                                                                                    SelectorColumns,
                                                                                    PublicInputColumns,
                                                                                    ConstantColumns> &public_assignment,
                                                  std::size_t circuit_start_row = 0) {

                        for (int z = 0; z < required_rows_amount - 2; z++) {
                            this->bp.add_copy_constraint({{W0, j + z, false}, {W0, j + z + 1, false}});
                            this->bp.add_copy_constraint({{W1, j + z, false}, {W1, j + z + 1, false}});
                        }

                        // TODO: (xP , yP ) in row i are copy constrained with values from the first doubling circuit
                    }

                    template<std::size_t WitnessColumns,
                             std::size_t SelectorColumns,
                             std::size_t PublicInputColumns,
                             std::size_t ConstantColumns>
                    void generate_assignments(
                        blueprint_private_assignment_table<arithmetization_type, WitnessColumns> &private_assignment,
                        blueprint_public_assignment_table<arithmetization_type,
                                                          SelectorColumns,
                                                          PublicInputColumns,
                                                          ConstantColumns> &public_assignment,
                        const assignment_params &params,
                        std::size_t circuit_start_row = 0) {
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
