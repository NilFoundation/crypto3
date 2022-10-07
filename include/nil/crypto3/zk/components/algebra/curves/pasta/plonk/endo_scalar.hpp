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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_ENDO_SCALAR_COMPONENT_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_ENDO_SCALAR_COMPONENT_15_WIRES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                         std::size_t ScalarSize,
                         std::size_t... WireIndexes>
                class endo_scalar;

                template<typename CurveType>
                struct endo_scalar_params;

                template<>
                struct endo_scalar_params<algebra::curves::vesta> {
                    using curve_type = algebra::curves::vesta;
                    using scalar_field_type = typename curve_type::scalar_field_type;
                    using base_field_type = typename curve_type::base_field_type;
                    constexpr static const typename scalar_field_type::value_type endo_r =
                        0x12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9_cppui255;
                    constexpr static const typename base_field_type::value_type endo_q =
                        0x06819A58283E528E511DB4D81CF70F5A0FED467D47C033AF2AA9D2E050AA0E4F_cppui255;
                };

                template<>
                struct endo_scalar_params<algebra::curves::pallas> {
                    using curve_type = algebra::curves::pallas;
                    using scalar_field_type = typename curve_type::scalar_field_type;
                    using base_field_type = typename curve_type::base_field_type;
                    constexpr static const typename scalar_field_type::value_type endo_r =
                        0x397E65A7D7C1AD71AEE24B27E308F0A61259527EC1D4752E619D1840AF55F1B1_cppui255;
                    constexpr static const typename base_field_type::value_type endo_q =
                        0x2D33357CB532458ED3552A23A8554E5005270D29D19FC7D27B7FD22F0201B547_cppui255;
                };

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                         std::size_t ScalarSize, std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3,
                         std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9,
                         std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class endo_scalar<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                  CurveType, ScalarSize, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using endo_params = endo_scalar_params<CurveType>;

                public:
                    constexpr static const std::size_t selector_seed = 0x0f00;
                    constexpr static const std::size_t rows_amount = 8;
                    constexpr static const std::size_t gates_amount = 2;

                    constexpr static const typename BlueprintFieldType::value_type endo_r = endo_params::endo_r;
                    constexpr static const typename CurveType::base_field_type::value_type endo_q = endo_params::endo_q;

                    struct params_type {
                        var scalar;
                    };

                    struct result_type {
                        var output = var(0, 0, false);
                        result_type(const params_type &params, std::size_t start_row_index) {
                            output = var(W6, start_row_index + rows_amount - 1, false, var::column_type::witness);
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;

                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }

                        std::size_t j = start_row_index;
                        assignment.enable_selector(first_selector_index, j, j + rows_amount - 1);
                        assignment.enable_selector(first_selector_index + 1, j + rows_amount - 1);

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type(params, start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        const std::size_t crumbs_per_row = 8;
                        const std::size_t bits_per_crumb = 2;
                        const std::size_t bits_per_row =
                            bits_per_crumb * crumbs_per_row;    // we suppose that ScalarSize % bits_per_row = 0

                        typename BlueprintFieldType::value_type scalar = assignment.var_value(params.scalar);
                        typename BlueprintFieldType::integral_type integral_scalar =
                            typename BlueprintFieldType::integral_type(scalar.data);
                        std::array<bool, ScalarSize> bits_msb;
                        {
                            nil::marshalling::status_type status;
                            assert(ScalarSize <= 255);

                            std::array<bool, 255> bits_msb_all =
                                nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_scalar, status);
                            
                            assert(status == nil::marshalling::status_type::success);

                            std::copy(bits_msb_all.end() - ScalarSize, bits_msb_all.end(), bits_msb.begin());
                            
                            for(std::size_t i = 0; i < 255 - ScalarSize; ++i) {
                                assert(bits_msb_all[i] == false);
                            }
                        }
                        typename BlueprintFieldType::value_type a = 2;
                        typename BlueprintFieldType::value_type b = 2;
                        typename BlueprintFieldType::value_type n = 0;

                        assert (ScalarSize % bits_per_row == 0);
                        for (std::size_t chunk_start = 0; chunk_start < bits_msb.size(); chunk_start += bits_per_row) {
                            assignment.witness(W0)[row] = n;
                            assignment.witness(W2)[row] = a;
                            assignment.witness(W3)[row] = b;

                            for (std::size_t j = 0; j < crumbs_per_row; j++) {
                                std::size_t crumb = chunk_start + j * bits_per_crumb;
                                typename BlueprintFieldType::value_type b0 = static_cast<int>(bits_msb[crumb + 1]);
                                typename BlueprintFieldType::value_type b1 = static_cast<int>(bits_msb[crumb + 0]);

                                typename BlueprintFieldType::value_type crumb_value = b0 + b1.doubled();
                                assignment.witness(W7 + j)[row] = crumb_value;

                                a = a.doubled();
                                b = b.doubled();

                                typename BlueprintFieldType::value_type s =
                                    (b0 == BlueprintFieldType::value_type::one()) ? 1 : -1;

                                if (b1 == BlueprintFieldType::value_type::zero()) {
                                    b += s;
                                } else {
                                    a += s;
                                }

                                n = (n.doubled()).doubled();
                                n += crumb_value;
                            }

                            assignment.witness(W1)[row] = n;
                            assignment.witness(W4)[row] = a;
                            assignment.witness(W5)[row] = b;
                            row++;
                        }
                        auto res = a * endo_r + b;
                        assignment.witness(W6)[row - 1] = res;
                        return result_type(params, start_row_index);
                    }

                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {

                        using F = typename BlueprintFieldType::value_type;

                        std::size_t selector_index_1 = first_selector_index;
                        std::size_t selector_index_2 = first_selector_index + 1;

                        auto c_f = [](var x) {
                            return (F(11) * F(6).inversed()) * x + (-F(5) * F(2).inversed()) * x * x +
                                   (F(2) * F(3).inversed()) * x * x * x;
                        };

                        auto d_f = [](var x) {
                            return -F::one() + (F(29) * F(6).inversed()) * x + (-F(7) * F(2).inversed()) * x * x +
                                   (F(2) * F(3).inversed()) * x * x * x;
                        };

                        auto constraint_1 =
                            bp.add_constraint(var(W7, 0) * (var(W7, 0) - 1) * (var(W7, 0) - 2) * (var(W7, 0) - 3));
                        auto constraint_2 =
                            bp.add_constraint(var(W8, 0) * (var(W8, 0) - 1) * (var(W8, 0) - 2) * (var(W8, 0) - 3));
                        auto constraint_3 =
                            bp.add_constraint(var(W9, 0) * (var(W9, 0) - 1) * (var(W9, 0) - 2) * (var(W9, 0) - 3));
                        auto constraint_4 =
                            bp.add_constraint(var(W10, 0) * (var(W10, 0) - 1) * (var(W10, 0) - 2) * (var(W10, 0) - 3));
                        auto constraint_5 =
                            bp.add_constraint(var(W11, 0) * (var(W11, 0) - 1) * (var(W11, 0) - 2) * (var(W11, 0) - 3));
                        auto constraint_6 =
                            bp.add_constraint(var(W12, 0) * (var(W12, 0) - 1) * (var(W12, 0) - 2) * (var(W12, 0) - 3));
                        auto constraint_7 =
                            bp.add_constraint(var(W13, 0) * (var(W13, 0) - 1) * (var(W13, 0) - 2) * (var(W13, 0) - 3));
                        auto constraint_8 =
                            bp.add_constraint(var(W14, 0) * (var(W14, 0) - 1) * (var(W14, 0) - 2) * (var(W14, 0) - 3));
                        auto constraint_9 = bp.add_constraint(
                            var(W4, 0) - (256 * var(W2, 0) + 128 * c_f(var(W7, 0)) + 64 * c_f(var(W8, 0)) +
                                          32 * c_f(var(W9, 0)) + 16 * c_f(var(W10, 0)) + 8 * c_f(var(W11, 0)) +
                                          4 * c_f(var(W12, 0)) + 2 * c_f(var(W13, 0)) + c_f(var(W14, 0))));
                        auto constraint_10 = bp.add_constraint(
                            var(W5, 0) - (256 * var(W3, 0) + 128 * d_f(var(W7, 0)) + 64 * d_f(var(W8, 0)) +
                                          32 * d_f(var(W9, 0)) + 16 * d_f(var(W10, 0)) + 8 * d_f(var(W11, 0)) +
                                          4 * d_f(var(W12, 0)) + 2 * d_f(var(W13, 0)) + d_f(var(W14, 0))));
                        auto constraint_11 = bp.add_constraint(
                            var(W1, 0) - ((1 << 16) * var(W0, 0) + (1 << 14) * var(W7, 0) + (1 << 12) * var(W8, 0) +
                                          (1 << 10) * var(W9, 0) + (1 << 8) * var(W10, 0) + (1 << 6) * var(W11, 0) +
                                          (1 << 4) * var(W12, 0) + (1 << 2) * var(W13, 0) + var(W14, 0)));

                        auto constraint_12 = bp.add_constraint(var(W6, 0) - (endo_r * var(W4, 0) + var(W5, 0)));

                        bp.add_gate(selector_index_2, {constraint_12});

                        bp.add_gate(selector_index_1,
                                    {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6,
                                     constraint_7, constraint_8, constraint_9, constraint_10, constraint_11});
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {

                        std::size_t j = start_row_index;

                        for (std::size_t z = 1; z < rows_amount; z++) {
                            bp.add_copy_constraint(
                                {{W0, static_cast<int>(j + z), false}, {W1, static_cast<int>(j + z - 1), false}});
                            bp.add_copy_constraint(
                                {{W2, static_cast<int>(j + z), false}, {W4, static_cast<int>(j + z - 1), false}});
                            bp.add_copy_constraint(
                                {{W3, static_cast<int>(j + z), false}, {W5, static_cast<int>(j + z - 1), false}});
                        }

                        // check that the recalculated n is equal to the input challenge
                        bp.add_copy_constraint({{W1, static_cast<int>(j + rows_amount - 1), false}, params.scalar});
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_ENDO_SCALAR_COMPONENT_15_WIRES_HPP
