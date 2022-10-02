//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the DECOMPOSITION component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_DECOMPOSITION_EDWARD25519_HPP
#define CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_DECOMPOSITION_EDWARD25519_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>
namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class reduction;

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
                         std::size_t W8>
                class reduction<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                CurveType,
                                W0,
                                W1,
                                W2,
                                W3,
                                W4,
                                W5,
                                W6,
                                W7,
                                W8> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                public:
                    constexpr static const std::size_t rows_amount = 4;
                    constexpr static const std::size_t selector_seed = 0xff34;

                    constexpr static const std::size_t gates_amount = 2;
                    struct params_type {
                        std::array<var, 8> k;
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t component_start_row) {
                            output = var(W4, component_start_row + rows_amount - 3, false);
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         std::size_t start_row_index) {
                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;

                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }

                        assignment.enable_selector(first_selector_index, start_row_index + 1);
                        assignment.enable_selector(first_selector_index + 1, start_row_index + 2);

                        generate_copy_constraints(bp, assignment, params, start_row_index);

                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        std::array<typename ArithmetizationType::field_type::integral_type, 8> data = {
                            typename ArithmetizationType::field_type::integral_type(
                                assignment.var_value(params.k[0]).data),
                            typename ArithmetizationType::field_type::integral_type(
                                assignment.var_value(params.k[1]).data),
                            typename ArithmetizationType::field_type::integral_type(
                                assignment.var_value(params.k[2]).data),
                            typename ArithmetizationType::field_type::integral_type(
                                assignment.var_value(params.k[3]).data),
                            typename ArithmetizationType::field_type::integral_type(
                                assignment.var_value(params.k[4]).data),
                            typename ArithmetizationType::field_type::integral_type(
                                assignment.var_value(params.k[5]).data),
                            typename ArithmetizationType::field_type::integral_type(
                                assignment.var_value(params.k[6]).data),
                            typename ArithmetizationType::field_type::integral_type(
                                assignment.var_value(params.k[7]).data)};

                        auto L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed_cppui512;
                        auto k = 0x00_cppui512;
                        auto shft = 0x01_cppui512;

                        for (std::size_t i = 0; i < 8; i++) {
                            assignment.witness(i)[row + 3] = data[i];
                            k = k + data[i] * (shft % L);
                            shft = shft * 0x10000000000000000_cppui255;
                        }

                        auto r = k % L;
                        auto q = (k / L);

                        assignment.witness(3)[row + 2] = q & 127;
                        assignment.witness(2)[row + 2] = (q >> 7) & ((1 << (20)) - 1);
                        assignment.witness(1)[row + 2] = (q >> 27) & ((1 << (20)) - 1);
                        assignment.witness(0)[row + 2] = (q >> 47) & ((1 << (20)) - 1);
                        assignment.witness(4)[row + 1] = r;

                        assignment.witness(3)[row + 1] =
                            typename ArithmetizationType::field_type::value_type((r) & ((1 << (13)) - 1));
                        assignment.witness(2)[row + 1] =
                            typename ArithmetizationType::field_type::value_type((r >> 13) & ((1 << (20)) - 1));
                        assignment.witness(1)[row + 1] =
                            typename ArithmetizationType::field_type::value_type((r >> 33) & ((1 << (20)) - 1));
                        assignment.witness(0)[row + 1] =
                            typename ArithmetizationType::field_type::value_type((r >> 53) & ((1 << (20)) - 1));
                        assignment.witness(8)[row] =
                            typename ArithmetizationType::field_type::value_type((r >> 73) & ((1 << (20)) - 1));
                        assignment.witness(7)[row] =
                            typename ArithmetizationType::field_type::value_type((r >> 93) & ((1 << (20)) - 1));
                        assignment.witness(6)[row] =
                            typename ArithmetizationType::field_type::value_type((r >> 113) & ((1 << (20)) - 1));
                        assignment.witness(5)[row] =
                            typename ArithmetizationType::field_type::value_type((r >> 133) & ((1 << (20)) - 1));
                        assignment.witness(4)[row] =
                            typename ArithmetizationType::field_type::value_type((r >> 153) & ((1 << (20)) - 1));
                        assignment.witness(3)[row] =
                            typename ArithmetizationType::field_type::value_type((r >> 173) & ((1 << (20)) - 1));
                        assignment.witness(2)[row] =
                            typename ArithmetizationType::field_type::value_type((r >> 193) & ((1 << (20)) - 1));
                        assignment.witness(1)[row] =
                            typename ArithmetizationType::field_type::value_type((r >> 213) & ((1 << (20)) - 1));
                        assignment.witness(0)[row] = typename ArithmetizationType::field_type::value_type((r >> 233));

                        typename ArithmetizationType::field_type::value_type s_r = assignment.witness(0)[row];
                        for (size_t i = 1; i < 9; i++) {
                            s_r += assignment.witness(i)[row];
                        }
                        s_r += assignment.witness(0)[row + 1] + assignment.witness(1)[row + 1] +
                               assignment.witness(2)[row + 1];
                        s_r -= 12 * ((1 << (20)) - 1);
                        algebra::curves::ed25519::scalar_field_type::extended_integral_type one = 1;
                        assignment.witness(5)[row + 1] = s_r.inversed();

                        // if ((r) & ((1 << (13)) - 1) (L - (one << 252))) { \\TO-DO
                        assignment.witness(6)[row + 1] = 1;
                        //} else {
                        //}

                        auto c =
                            data[0] + data[1] * ((one << 64)) + data[3] * (((one << 192) % L) & ((one << 73) - 1)) +
                            data[4] * (((one << 256) % L) & ((one << 73) - 1)) +
                            data[5] * (((one << 320) % L) & ((one << 73) - 1)) +
                            data[6] * (((one << 384) % L) & ((one << 73) - 1)) +
                            data[7] * (((one << 448) % L) & ((one << 73) - 1)) + q * ((one << 73) - (L % (one << 73)));
                        auto d = (r) & ((1 << (13)) - 1) + ((r >> 13) & ((1 << (20)) - 1)) * (one << 13) +
                                           ((r >> 33) & ((1 << (20)) - 1)) * (one << 33) +
                                           ((r >> 53) & ((1 << (20)) - 1)) * (one << 53);
                        auto v = (c - d) >> 69;

                        assignment.witness(8)[row + 3] = v;
                        assignment.witness(4)[row + 2] = v >> 56;
                        assignment.witness(5)[row + 2] = (v >> 34) & ((1 << (22)) - 1);
                        assignment.witness(6)[row + 2] = (v >> 12) & ((1 << (22)) - 1);
                        assignment.witness(7)[row + 2] = v & 4095;

                        return result_type(start_row_index);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               std::size_t first_selector_index) {

                        std::size_t selector_index = first_selector_index;
                        auto L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed_cppui512;

                        auto constraint_1 = bp.add_constraint(
                            var(W0, +1) * 0x01_cppui512 + var(W1, +1) * 0x10000000000000000_cppui512 +
                            var(W2, +1) * 0x100000000000000000000000000000000_cppui512 +
                            var(W3, +1) * 0x1000000000000000000000000000000000000000000000000_cppui512 +
                            var(W4, +1) * 0xffffffffffffffffffffffffffffffec6ef5bf4737dcf70d6ec31748d98951d_cppui512 +
                            var(W5, +1) * 0xffffffffffffffeb2106215d086329a93b8c838d39a5e065812631a5cf5d3ed_cppui512 +
                            var(W6, +1) * 0x2106215d086329a7ed9ce5a30a2c131b64a7f435e4fdd9539822129a02a6271_cppui512 +
                            var(W7, +1) * 0xed9ce5a30a2c131b399411b7c309a3de24babbe38d1d7a979daf520a00acb65_cppui512 -
                            var(W4, -1) -
                            (var(W0, 0) * 0x800000000000_cppui512 + var(W1, 0) * 0x8000000_cppui512 +
                             var(W2, 0) * 0x80_cppui512 + var(W3, 0)) *
                                L);

                        auto s_r = var(W0, -1) + var(W1, -1) + var(W2, -1) + var(W3, -1) + var(W4, -1) + var(W5, -1) +
                                   var(W6, -1) + var(W7, -1) + var(W8, -1) + var(W0, 0) + var(W1, 0) + var(W2, 0) -
                                   12 * ((1 << (20)) - 1);

                        auto constraint_2 = bp.add_constraint(
                            var(W4, 0) -
                            (var(W3, 0) + var(W2, 0) * 0x2000_cppui255 + var(W1, 0) * 0x200000000_cppui255 +
                             var(W0, 0) * 0x20000000000000_cppui255 + var(W8, -1) * 0x2000000000000000000_cppui255 +
                             var(W7, -1) * 0x200000000000000000000000_cppui255 +
                             var(W6, -1) * 0x20000000000000000000000000000_cppui255 +
                             var(W5, -1) * 0x2000000000000000000000000000000000_cppui255 +
                             var(W4, -1) * 0x200000000000000000000000000000000000000_cppui255 +
                             var(W3, -1) * 0x20000000000000000000000000000000000000000000_cppui255 +
                             var(W2, -1) * 0x2000000000000000000000000000000000000000000000000_cppui255 +
                             var(W1, -1) * 0x200000000000000000000000000000000000000000000000000000_cppui255 +
                             var(W0, -1) * 0x20000000000000000000000000000000000000000000000000000000000_cppui255));

                        auto constraint_3 = bp.add_constraint((s_r) * ((s_r)*var(W5, 0) - 1));

                        auto constraint_4 =
                            bp.add_constraint((s_r)*var(W5, 0) + (1 - (s_r)*var(W5, 0)) * var(W6, 0) - 1);
                        algebra::curves::ed25519::scalar_field_type::extended_integral_type one = 1;
                        std::array<algebra::curves::ed25519::scalar_field_type::extended_integral_type, 5> m = {
                            ((one << 192) % L), ((one << 256) % L), ((one << 320) % L), ((one << 384) % L),
                            ((one << 448) % L)};
                        auto constraint_5 = bp.add_constraint(
                            var(W0, +1) + var(W1, +1) * (one << 64) + var(W3, +1) * (m[0] & ((one << 73) - 1)) +
                            var(W4, +1) * (m[1] & ((one << 73) - 1)) + var(W5, +1) * (m[2] & ((one << 73) - 1)) +
                            var(W6, +1) * (m[3] & ((one << 73) - 1)) + var(W7, +1) * (m[4] & ((one << 73) - 1)) +
                            (var(W0, 0) * 0x800000000000_cppui512 + var(W1, 0) * 0x8000000_cppui512 +
                             var(W2, 0) * 0x80_cppui512 + var(W3, 0)) *
                                ((one << 73) - (L % (one << 73))) -
                            (var(W3, -1) + var(W2, -1) * (one << 13) + var(W1, -1) * (one << 33) +
                             var(W0, -1) * (one << 53)) -
                            var(W8, +1) * (one << 69));

                        auto constraint_6 =
                            bp.add_constraint(var(W8, +1) - (var(W4, 0) * (one << 56) + var(W5, 0) * (one << 34) +
                                                             var(W6, 0) * (one << 12) + var(W7, 0)));

                        bp.add_gate(selector_index, {constraint_2, constraint_3, constraint_4});

                        bp.add_gate(selector_index + 1, {constraint_1, constraint_5, constraint_6});
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t component_start_row) {

                        std::size_t row = component_start_row;

                        bp.add_copy_constraint({var(W0, row + 3, false), params.k[0]});
                        bp.add_copy_constraint({var(W1, row + 3, false), params.k[1]});
                        bp.add_copy_constraint({var(W2, row + 3, false), params.k[2]});
                        bp.add_copy_constraint({var(W3, row + 3, false), params.k[3]});
                        bp.add_copy_constraint({var(W4, row + 3, false), params.k[4]});
                        bp.add_copy_constraint({var(W5, row + 3, false), params.k[5]});
                        bp.add_copy_constraint({var(W6, row + 3, false), params.k[6]});
                        bp.add_copy_constraint({var(W7, row + 3, false), params.k[7]});
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_REDUCTION_HPP