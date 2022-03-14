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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_FIXED_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_FIXED_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class element_g1_fixed_base_scalar_mul;

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
                class element_g1_fixed_base_scalar_mul<snark::plonk_constraint_system<BlueprintFieldType>,
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

                    typename CurveType::template g1_type<>::value_type B;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t required_rows_amount = 43;

                public:
                    struct init_params {
                        typename CurveType::template g1_type<>::value_type B;
                    };

                    struct assignment_params {
                        typename CurveType::scalar_field_type::value_type a;
                        typename CurveType::scalar_field_type::value_type s;
                        typename CurveType::template g1_type<>::value_type P;
                    };

                    element_g1_fixed_base_scalar_mul(blueprint_type &bp, const init_params &params) :
                        component<arithmetization_type>(bp), B(params.B) {

                        j = this->bp.allocate_rows(required_rows_amount);
                    }

                    static std::size_t allocate_rows(blueprint<arithmetization_type> &in_bp) {
                        return in_bp.allocate_rows(required_rows_amount);
                    }

                private:
                    typename CurveType::template g1_type<>::value_type get_omega(std::size_t s, std::size_t i) {

                        std::size_t coef = i * math::detail::power_of_two(3 * s);

                        return coef * B;
                    }

                    snark::plonk_constraint<BlueprintFieldType>
                        generate_phi1_gate(typename blueprint_type::value_type x_1,
                                           typename blueprint_type::value_type x_2,
                                           typename blueprint_type::value_type x_3,
                                           typename blueprint_type::value_type x_4,
                                           std::array<typename CurveType::base_field_type::value_type, 8>
                                               u) {

                        return this->bp.add_constraint(
                            x_3 * (-u[0] * x_2 * x_1 + u[0] * x_1 + u[0] * x_2 - u[0] + u[2] * x_1 * x_2 - u[2] * x_2 +
                                   u[4] * x_1 * x_2 - u[4] * x_2 - u[6] * x_1 * x_2 + u[1] * x_2 * x_1 - u[1] * x_1 -
                                   u[1] * x_2 + u[1] - u[3] * x_1 * x_2 + u[3] * x_2 - u[5] * x_1 * x_2 + u[5] * x_2 +
                                   u[7] * x_1 * x_2) -
                            (x_4 - u[0] * x_2 * x_1 + u[0] * x_1 + u[0] * x_2 - u[0] + u[2] * x_1 * x_2 - u[2] * x_2 +
                             u[4] * x_1 * x_2 - u[4] * x_2 - u[6] * x_1 * x_2));
                    }

                    snark::plonk_constraint<BlueprintFieldType>
                        generate_phi2_gate(typename blueprint_type::value_type x_1,
                                           typename blueprint_type::value_type x_2,
                                           typename blueprint_type::value_type x_3,
                                           typename blueprint_type::value_type x_4,
                                           std::array<typename CurveType::base_field_type::value_type, 8>
                                               v) {
                        return this->bp.add_constraint(
                            x_3 * (-v[0] * x_2 * x_1 + v[0] * x_1 + v[0] * x_2 - v[0] + v[2] * x_1 * x_2 - v[2] * x_2 +
                                   v[4] * x_1 * x_2 - v[4] * x_2 - v[6] * x_1 * x_2 + v[1] * x_2 * x_1 - v[1] * x_1 -
                                   v[1] * x_2 + v[1] - v[3] * x_1 * x_2 + v[3] * x_2 - v[5] * x_1 * x_2 + v[5] * x_2 +
                                   v[7] * x_1 * x_2) -
                            (x_4 - v[0] * x_2 * x_1 + v[0] * x_1 + v[0] * x_2 - v[0] + v[2] * x_1 * x_2 - v[2] * x_2 +
                             v[4] * x_1 * x_2 - v[4] * x_2 - v[6] * x_1 * x_2));
                    }

                public:
                    template<std::size_t SelectorColumns, std::size_t PublicInputColumns, std::size_t ConstantColumns>
                    void generate_gates(blueprint_public_assignment_table<arithmetization_type,
                                                                          SelectorColumns,
                                                                          PublicInputColumns,
                                                                          ConstantColumns> &public_assignment,
                                        std::size_t circuit_start_row = 0) {

                        auto bit_check_0 = this->bp.add_bit_check(var(W0, 0));
                        auto bit_check_1 = this->bp.add_bit_check(var(W1, 0));
                        auto bit_check_2 = this->bp.add_bit_check(var(W2, 0));
                        auto bit_check_3 = this->bp.add_bit_check(var(W3, 0));
                        auto bit_check_4 = this->bp.add_bit_check(var(W4, 0));
                        auto bit_check_5 = this->bp.add_bit_check(var(W5, 0));

                        std::array<typename CurveType::base_field_type::value_type, 8> u;
                        std::array<typename CurveType::base_field_type::value_type, 8> v;

                        // For j + 0:
                        {
                            std::size_t selector_index_j_0 = public_assignment.add_selector(j);

                            for (std::size_t i = 0; i <= 7; i++) {
                                typename CurveType::template g1_type<>::value_type omega = get_omega(0, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }

                            auto constraint_1 = generate_phi1_gate(var(W0, 0), var(W1, 0), var(W2, 0), var(W6, 0), u);
                            auto constraint_2 = generate_phi2_gate(var(W0, 0), var(W1, 0), var(W2, 0), var(W8, 0), v);

                            for (std::size_t i = 0; i <= 7; i++) {
                                typename CurveType::template g1_type<>::value_type omega = get_omega(1, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }
                            auto constraint_3 = generate_phi1_gate(var(W3, 0), var(W4, 0), var(W5, 0), var(W7, 0), u);
                            auto constraint_4 = generate_phi2_gate(var(W3, 0), var(W4, 0), var(W5, 0), var(W9, 0), v);

                            auto acc_constraint = this->bp.add_constraint(
                                var(W14, 0) - (var(W0, 0) + var(W1, 0) * 2 + var(W2, 0) * 4 + var(W3, 0) * 8 +
                                               var(W4, 0) * 16 + var(W5, 0) * 32));

                            auto constraint_6 = this->bp.add_constraint(var(W10, 0) - var(W6, 0));
                            auto constraint_7 = this->bp.add_constraint(var(W11, 0) - var(W8, 0));

                            auto incomplete_addition_constraint_1;
                            auto incomplete_addition_constraint_2;
                            // TODO: add constraints for incomplete addition

                            this->bp.add_gate(selector_index_j_0,
                                              {bit_check_0, bit_check_1, bit_check_2, bit_check_3, bit_check_4,
                                               bit_check_5, constraint_1, constraint_2, constraint_3, constraint_4,
                                               acc_constraint, constraint_6, constraint_7,
                                               incomplete_addition_constraint_1, incomplete_addition_constraint_2});
                        }

                        // For j + z, z = 1..41:
                        for (std::size_t z = 1; z <= 41; z++) {

                            std::size_t selector_index_j_z = public_assignment.add_selector(j + z);

                            for (std::size_t i = 0; i <= 7; i++) {
                                typename CurveType::template g1_type<>::value_type omega = get_omega(z * 2, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }

                            auto constraint_1 = generate_phi1_gate(var(W0, 0), var(W1, 0), var(W2, 0), var(W6, 0), u);
                            auto constraint_2 = generate_phi2_gate(var(W0, 0), var(W1, 0), var(W2, 0), var(W8, 0), v);

                            for (std::size_t i = 0; i <= 7; i++) {
                                typename CurveType::template g1_type<>::value_type omega = get_omega(z * 2 + 1, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }
                            auto constraint_3 = generate_phi1_gate(var(W3, 0), var(W4, 0), var(W5, 0), var(W7, 0), u);
                            auto constraint_4 = generate_phi2_gate(var(W3, 0), var(W4, 0), var(W5, 0), var(W9, 0), v);

                            auto acc_constraint = this->bp.add_constraint(
                                var(W14, 0) - (var(W0, 0) + var(W1, 0) * 2 + var(W2, 0) * 4 + var(W3, 0) * 8 +
                                               var(W4, 0) * 16 + var(W5, 0) * 32 + var(W14, -1) * 64));

                            auto incomplete_addition_constraint_1;
                            auto incomplete_addition_constraint_2;
                            // TODO: add constraints for incomplete addition

                            this->bp.add_gate(selector_index_j_z,
                                              {bit_check_0, bit_check_1, bit_check_2, bit_check_3, bit_check_4,
                                               bit_check_5, constraint_1, constraint_2, constraint_3, constraint_4,
                                               acc_constraint, incomplete_addition_constraint_1,
                                               incomplete_addition_constraint_2});
                        }

                        // For j + 42:
                        {

                            std::size_t selector_index_j_42 = public_assignment.add_selector(j + 42);

                            for (std::size_t i = 0; i <= 7; i++) {
                                typename CurveType::template g1_type<>::value_type omega = get_omega(84, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }

                            auto constraint_1 = generate_phi1_gate(var(W0, 0), var(W1, 0), var(W2, 0), var(W6, 0), u);
                            auto constraint_2 = generate_phi2_gate(var(W0, 0), var(W1, 0), var(W2, 0), var(W8, 0), v);

                            auto acc_constraint = this->bp.add_constraint(
                                var(W14, 0) - (var(W0, 0) + var(W1, 0) * 2 + var(W2, 0) * 4 + var(W14, -1) * 8));

                            auto complete_addition_constraint_1;
                            auto complete_addition_constraint_2;
                            // TODO: add constraints for complete addition

                            this->bp.add_gate(selector_index_j_42,
                                              {bit_check_0, bit_check_1, bit_check_2, constraint_1, constraint_2,
                                               acc_constraint, complete_addition_constraint_1,
                                               complete_addition_constraint_2});
                        }
                    }

                    template<std::size_t SelectorColumns, std::size_t PublicInputColumns, std::size_t ConstantColumns>
                    void
                        generate_copy_constraints(blueprint_public_assignment_table<arithmetization_type,
                                                                                    SelectorColumns,
                                                                                    PublicInputColumns,
                                                                                    ConstantColumns> &public_assignment,
                                                  std::size_t circuit_start_row = 0) {
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

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_FIXED_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
