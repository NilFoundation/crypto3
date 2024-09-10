//---------------------------------------------------------------------------//
// Copyright (c) 2023 Polina Chernyshova <pockvokhbtra@nil.foundation>
//               2024 Valeh Farzaliyev   <estoniaa@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_ROUND_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_ROUND_HPP

#include <iostream>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/lookup_library.hpp>
#include <nil/blueprint/configuration.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>

#include <vector>
#include <array>
#include <map>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename ArithmetizationType>
            class keccak_round;

            template<typename BlueprintFieldType>
            class keccak_round<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {

                using component_type = plonk_component<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;

                // xor2 - base=3, xor3 - base=4, xor5 - base=6, chi - base=2, rotate - base=0
                int bases[5] = {3, 4, 6, 2, 0};

                static std::size_t calculate_chunk_size(std::size_t num_rows, std::size_t base = 0) {
                    if (base == 0)
                        return 8;
                    std::size_t chunk_size = 0;
                    std::size_t power = base;
                    while (power < num_rows) {
                        ++chunk_size;
                        power *= base;
                    }
                    return chunk_size * 3;
                }
                static std::size_t calculate_num_chunks(std::size_t num_rows, std::size_t base = 0) {
                    if (base == 0)
                        return 8;
                    std::size_t chunk_size = calculate_chunk_size(num_rows, base);
                    std::size_t res = 192 / chunk_size + bool(192 % chunk_size);
                    return res;
                }
                static std::size_t calculate_num_cells(std::size_t num_rows, std::size_t base = 0) {
                    if (base == 0)
                        return 24;
                    std::size_t res = base == 3 ? 2 + 2 : base == 4 ? 3 + 2 : base == 6 ? 5 + 2 : 5;
                    res += 2 * calculate_num_chunks(num_rows, base);
                    return res;
                }
                static std::size_t calculate_buff(std::size_t witness_amount, std::size_t num_rows,
                                                  std::size_t base = 0) {
                    std::size_t buff = 0;
                    std::size_t cells = calculate_num_cells(num_rows, base);
                    if (base == 0) {
                        return 3 * witness_amount - cells;
                    }
                    if (base == 6) {
                        return witness_amount * ((cells - 1) / witness_amount + 1) - cells;
                    }
                    if (witness_amount % 9 == 0) {
                        while (cells % 3 != 0) {
                            cells++;
                            buff++;
                        }
                    } else if (witness_amount % 15 == 0) {
                        while (cells % 5 != 0) {
                            cells++;
                            buff++;
                        }
                    }
                    // if (base == 0 && buff < 2 * WitnessesAmount) {
                    //     buff = 2 * WitnessesAmount - rotate_cells;
                    // }
                    return buff;
                }
                static std::size_t calculate_last_round_call_row(std::size_t witness_amount,
                                                                 bool xor_with_mes,
                                                                 bool last_round_call,
                                                                 std::size_t limit_permutation_column) {
                    if (!last_round_call) {
                        return 0;
                    }
                    std::size_t res = 0;
                    auto gates_configuration_map =
                        configure_map(witness_amount, xor_with_mes, last_round_call, limit_permutation_column);
                    for (auto g : gates_configuration_map) {
                        if (g.first.first == 3) {
                            res = g.second[0];
                        }
                    }
                    return res;
                }

            public:
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::size_t witness_amount;
                    bool xor_with_mes;
                    bool last_round_call;
                    std::size_t limit_permutation_column;

                    static constexpr const std::size_t clamp = 15;

                    gate_manifest_type(std::size_t witness_amount_,
                                       bool xor_with_mes_,
                                       bool last_round_call_,
                                       std::size_t limit_permutation_column_) :
                        witness_amount(std::min(witness_amount_, clamp)),
                        xor_with_mes(xor_with_mes_), last_round_call(last_round_call_),
                        limit_permutation_column(limit_permutation_column_) {
                    }

                    std::uint32_t gates_amount() const override {
                        return keccak_round::get_gates_amount(witness_amount, xor_with_mes, last_round_call,
                                                              limit_permutation_column);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       bool xor_with_mes,
                                                       bool last_round_call,
                                                       std::size_t limit_permutation_column) {
                    gate_manifest manifest = gate_manifest(
                        gate_manifest_type(witness_amount, xor_with_mes, last_round_call, limit_permutation_column));
                    return manifest;
                }

                static manifest_type get_manifest(
                    bool xor_with_mes,
                    bool last_round_call,
                    std::size_t limit_permutation_column,
                    std::size_t lpc_ = 7
                ) {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_range_param(9, 15)), false);
                    return manifest;
                }

                using var = typename component_type::var;

                static const std::size_t lookup_rows = 65536;
                // const std::size_t lookup_columns;

                // need to xor inner state with message only on the first round
                const bool xor_with_mes;
                // need to xor last message chunk with 0x80 or 1 only on the last round
                const bool last_round_call;
                // num columns for the permutation argument
                const std::size_t limit_permutation_column;

                const typename BlueprintFieldType::integral_type big_rot_const =
                    calculate_sparse((integral_type(1) << 64) - 1);
                const std::array<std::array<typename BlueprintFieldType::integral_type, 2>, 29> all_rot_consts =
                    calculate_rot_consts();

                const std::size_t normalize3_chunk_size = calculate_chunk_size(lookup_rows, 3);
                const std::size_t normalize4_chunk_size = calculate_chunk_size(lookup_rows, 4);
                const std::size_t normalize6_chunk_size = calculate_chunk_size(lookup_rows, 6);
                const std::size_t chi_chunk_size = calculate_chunk_size(lookup_rows, 5);
                const std::size_t rotate_chunk_size = 24;

                const std::size_t normalize3_num_chunks = calculate_num_chunks(lookup_rows, 3);
                const std::size_t normalize4_num_chunks = calculate_num_chunks(lookup_rows, 4);
                const std::size_t normalize6_num_chunks = calculate_num_chunks(lookup_rows, 6);
                const std::size_t chi_num_chunks = calculate_num_chunks(lookup_rows, 5);
                const std::size_t rotate_num_chunks = 8;

                const std::size_t xor2_cells = calculate_num_cells(lookup_rows, 3);
                const std::size_t xor3_cells = calculate_num_cells(lookup_rows, 4);
                const std::size_t xor5_cells = calculate_num_cells(lookup_rows, 6);
                const std::size_t chi_cells = calculate_num_cells(lookup_rows, 5);
                const std::size_t rotate_cells = 24;

                const std::size_t xor2_buff = calculate_buff(this->witness_amount(), lookup_rows, 3);
                const std::size_t xor3_buff = calculate_buff(this->witness_amount(), lookup_rows, 4);
                const std::size_t xor5_buff = calculate_buff(this->witness_amount(), lookup_rows, 6);
                const std::size_t chi_buff = calculate_buff(this->witness_amount(), lookup_rows, 5);
                const std::size_t rotate_buff = calculate_buff(this->witness_amount(), lookup_rows);

                const std::size_t rows_amount =
                    get_rows_amount(this->witness_amount(), xor_with_mes, last_round_call, limit_permutation_column);

                // full configuration is precalculated, then used in other functions
                const std::size_t full_configuration_size = 17 * xor_with_mes + 85 + 29;
                std::vector<configuration> full_configuration =
                    configure_all(this->witness_amount(), xor_with_mes, last_round_call, limit_permutation_column);
                // number represents relative selector index for each constraint
                std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> gates_configuration_map =
                    configure_map(this->witness_amount(), xor_with_mes, last_round_call, limit_permutation_column);
                std::vector<std::vector<configuration>> gates_configuration =
                    configure_gates(this->witness_amount(), xor_with_mes, last_round_call, limit_permutation_column);
                std::vector<std::vector<configuration>> lookup_gates_configuration = configure_lookup_gates(
                    this->witness_amount(), xor_with_mes, last_round_call, limit_permutation_column);

                const std::size_t last_round_call_row = calculate_last_round_call_row(
                    this->witness_amount(), xor_with_mes, last_round_call, limit_permutation_column);
                const std::size_t gates_amount =
                    get_gates_amount(this->witness_amount(), xor_with_mes, last_round_call, limit_permutation_column);

                const value_type sparse_3 = 0x6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB6DB_cppui_modular256;

                const integral_type sparse_x80 = calculate_sparse(integral_type(0x8000000000000000));
                const integral_type sparse_x7f = calculate_sparse(integral_type(0x8000000000000000 - 1));

                constexpr static const std::array<std::size_t, 25> rho_offsets = {
                    0, 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};

                struct input_type {
                    std::array<var, 25> inner_state;
                    std::array<var, 17> padded_message_chunk;
                    var round_constant;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.insert(result.end(), inner_state.begin(), inner_state.end());
                        result.insert(result.end(), padded_message_chunk.begin(), padded_message_chunk.end());
                        result.push_back(round_constant);
                        return result;
                    }
                };

                struct result_type {
                    std::array<var, 25> inner_state;

                    result_type() {
                    }

                    result_type(const keccak_round &component, std::size_t start_row_index) {
                        std::size_t num_config = component.full_configuration.size() - 30;
                        inner_state[0] =
                            var(component.W(component.full_configuration[num_config].copy_from.column),
                                component.full_configuration[num_config].copy_from.row + start_row_index, false);
                        for (int i = 1; i < 25; ++i) {
                            inner_state[25 - i] = var(
                                component.W(component.full_configuration[num_config - i].copy_from.column),
                                component.full_configuration[num_config - i].copy_from.row + start_row_index, false);
                        }
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.insert(result.end(), inner_state.begin(), inner_state.end());
                        return result;
                    }
                };

                typename BlueprintFieldType::integral_type
                    calculate_sparse(const typename BlueprintFieldType::integral_type &value) const {
                    typename BlueprintFieldType::integral_type result = 0;
                    typename BlueprintFieldType::integral_type power = 1;
                    typename BlueprintFieldType::integral_type val = value;
                    while (val > 0) {
                        result += (val & 1) * power;
                        power <<= 3;
                        val >>= 1;
                    }
                    return result;
                }
                std::array<std::array<typename BlueprintFieldType::integral_type, 2>, 29> calculate_rot_consts() const {
                    std::array<std::array<typename BlueprintFieldType::integral_type, 2>, 29> result;
                    for (int i = 0; i < 5; ++i) {
                        result[i][0] = calculate_sparse((integral_type(1) << 1) - 1);
                        result[i][1] = calculate_sparse((integral_type(1) << 63) - 1);
                    }
                    for (int i = 1; i < 25; ++i) {
                        result[i + 4][0] = calculate_sparse((integral_type(1) << rho_offsets[i]) - 1);
                        result[i + 4][1] = calculate_sparse((integral_type(1) << (64 - rho_offsets[i])) - 1);
                    }
                    return result;
                }

                integral_type normalize(const integral_type &integral_value) const {
                    integral_type result = 0;
                    integral_type value = integral_value;
                    integral_type power = 1;
                    while (value > 0) {
                        result += (value & 1) * power;
                        power <<= 3;
                        value >>= 3;
                    }
                    return result;
                }

                integral_type chi(const integral_type &integral_value) const {
                    integral_type result = 0;
                    integral_type value = integral_value;
                    integral_type power = 1;
                    integral_type mask = 7;
                    int table[5] = {0, 1, 1, 0, 0};
                    while (value > 0) {
                        int bit = table[int(value & mask)];
                        result += bit * power;
                        power <<= 3;
                        value >>= 3;
                    }
                    return result;
                }

                static configuration configure_inner(std::size_t witness_amount, std::size_t limit_permutation_column,
                                                     std::size_t row, std::size_t column, std::size_t num_args,
                                                     std::size_t num_chunks, std::size_t num_cells,
                                                     std::size_t buff = 0) {

                    std::pair<std::size_t, std::size_t> first_coordinate = {row, column};

                    std::size_t last_row = row, last_column = column;

                    std::vector<std::pair<std::size_t, std::size_t>> copy_to;

                    if (num_args + column > limit_permutation_column) {
                        for (int i = 0; i < num_args; ++i) {
                            copy_to.push_back({last_row + 1, i});
                        }
                    } else {
                        for (int i = 0; i < num_args; ++i) {
                            copy_to.push_back(
                                {last_row + (last_column / witness_amount), (last_column++) % witness_amount});
                        }
                    }

                    std::pair<std::size_t, std::size_t> cell_copy_from;
                    std::size_t final_row = (column + num_cells - 1) / witness_amount + row;
                    if (final_row == copy_to[0].first) {
                        cell_copy_from = {final_row, copy_to.back().second + 1};
                    } else {
                        cell_copy_from = {final_row, 0};
                    }

                    std::vector<std::pair<std::size_t, std::size_t>> cells;
                    if (num_args + column > limit_permutation_column) {
                        for (int i = column; i < witness_amount; ++i) {
                            cells.push_back({row, i});
                        }
                        std::size_t cells_left = num_cells - witness_amount + column;
                        std::size_t cur_row = row + 1, cur_column = num_args;
                        while (cur_column < cells_left) {
                            if (cur_column % witness_amount == cell_copy_from.second &&
                                (cur_row + (cur_column / witness_amount) == cell_copy_from.first)) {
                                cur_column++;
                                continue;
                            }
                            cells.push_back({cur_row + (cur_column / witness_amount), (cur_column++) % witness_amount});
                        }
                    } else {
                        std::size_t cur_row = row, cur_column = column + num_args;
                        while (cur_column - column < num_cells) {
                            if (cur_column % witness_amount == cell_copy_from.second &&
                                (cur_row + (cur_column / witness_amount) == cell_copy_from.first)) {
                                cur_column++;
                                continue;
                            }
                            cells.push_back({cur_row + (cur_column / witness_amount), (cur_column++) % witness_amount});
                        }
                    }
                    std::size_t cell_index = 0;

                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints;
                    constraints.push_back({cells[cell_index++]});
                    for (int i = 0; i < num_args; ++i) {
                        constraints[0].push_back(copy_to[i]);
                    }

                    constraints.push_back({constraints[0][0]});
                    constraints.push_back({cell_copy_from});
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups(num_chunks);
                    for (std::size_t i = 1; i < 3; ++i) {
                        for (std::size_t j = 0; j < num_chunks; ++j) {
                            constraints[i].push_back(cells[cell_index++]);
                            lookups[j].push_back(constraints[i].back());
                        }
                    }

                    if (cell_copy_from.first > cells.back().first) {
                        cells.back() = cell_copy_from;
                    }

                    last_column = cells.back().second + 1 + buff;
                    last_row = cells.back().first + (last_column >= witness_amount);
                    last_column %= witness_amount;

                    return configuration(first_coordinate, {last_row, last_column}, copy_to, constraints, lookups,
                                         cell_copy_from);
                }

                static configuration configure_xor(std::size_t witness_amount, std::size_t limit_permutation_column,
                                                   std::size_t row, std::size_t column, int num_args) {
                    // regular constraints:
                    // sum = arg1 + arg2 + ... + argn
                    // sum = sum_chunk0 + sum_chunk1 * 2^chunk_size + ... + sum_chunkk * 2^(k*chunk_size)
                    // norm_sum = norm_sum_chunk0 + norm_sum_chunk1 * 2^chunk_size + ... + norm_sum_chunkk *
                    // 2^(k*chunk_size)

                    std::size_t num_chunks = calculate_num_chunks(lookup_rows, num_args + 1);
                    std::size_t num_cells = calculate_num_cells(lookup_rows, num_args + 1);
                    std::size_t buff = calculate_buff(witness_amount, lookup_rows, num_args + 1);

                    return configure_inner(witness_amount, limit_permutation_column, row, column, num_args, num_chunks,
                                           num_cells, buff);
                }

                static configuration configure_chi(std::size_t witness_amount, std::size_t limit_permutation_column,
                                                   std::size_t row, std::size_t column) {
                    // regular constraints:
                    // sum = sparse_3 - 2 * a + b - c;
                    // sum = sum_chunk0 + sum_chunk1 * 2^chunk_size + ... + sum_chunkk * 2^(k*chunk_size)
                    // chi_sum = chi_sum_chunk0 + chi_sum_chunk1 * 2^chunk_size + ... + chi_sum_chunkk *
                    // 2^(k*chunk_size)

                    std::size_t num_args = 3;
                    std::size_t num_chunks = calculate_num_chunks(lookup_rows, 5);
                    std::size_t num_cells = calculate_num_cells(lookup_rows, 5);
                    std::size_t buff = calculate_buff(witness_amount, lookup_rows, 5);

                    return configure_inner(witness_amount, limit_permutation_column, row, column, num_args, num_chunks,
                                           num_cells, buff);
                }

                static configuration configure_rot(std::size_t witness_amount, std::size_t limit_permutation_column,
                                                   std::size_t row, std::size_t column) {
                    // regular constraints:
                    // a = small_part * (1 << (192 - 3 * r)) + big_part;
                    // a_rot = big_part * (1 << (3 * r)) + small_part;
                    // bound_small = small_part - sparse((1 << r) - 1) + sparse((1 << 64) - 1);
                    // bound_small = small_chunk0 + small_chunk1 * 2^chunk_size + ... + small_chunkk * 2^(k*chunk_size)
                    // bound_big = big_part - sparse((1 << (64 - r)) - 1) + sparse((1 << 64) - 1);
                    // bound_big = big_chunk0 + big_chunk1 * 2^chunk_size + ... + big_chunkk * 2^(k*chunk_size)
                    // 1 << 192 = (1 << (192 - 3 * r)) * (1 << (3 * r))

                    std::pair<std::size_t, std::size_t> first_coordinate = {row, column};

                    std::size_t last_row = row, last_column = column;
                    std::size_t num_chunks = 8;
                    std::size_t num_cells = 24;

                    std::vector<std::pair<std::size_t, std::size_t>> copy_to;
                    std::pair<std::size_t, std::size_t> cell_copy_from;
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints;

                    if (2 + column > limit_permutation_column) {
                        copy_to.push_back({last_row + 1, 0});
                        cell_copy_from = {last_row + 1, 1};
                    } else {
                        copy_to.push_back(
                            {last_row + (last_column / witness_amount), (last_column++) % witness_amount});
                        cell_copy_from = {last_row + (last_column / witness_amount), (last_column++) % witness_amount};
                    }

                    std::vector<std::pair<std::size_t, std::size_t>> cells;
                    if (2 + column > limit_permutation_column) {
                        for (int i = column; i < witness_amount; ++i) {
                            cells.push_back({row, i});
                        }
                        std::size_t cells_left = num_cells - witness_amount + column;
                        std::size_t cur_row = row + 1, cur_column = 2;
                        while (cur_column < cells_left) {
                            cells.push_back({cur_row + (cur_column / witness_amount), (cur_column++) % witness_amount});
                        }
                    } else {
                        std::size_t cur_row = row, cur_column = column + 2;
                        while (cur_column - column < num_cells) {
                            cells.push_back({cur_row + (cur_column / witness_amount), (cur_column++) % witness_amount});
                        }
                    }
                    std::size_t cell_index = 0;
                    auto rot_const = cells[cell_index++];
                    auto minus_rot_const = cells[cell_index++];

                    constraints.push_back({copy_to[0]});
                    constraints[0].push_back(cells[cell_index++]);
                    constraints[0].push_back(cells[cell_index++]);

                    constraints.push_back({cell_copy_from});
                    constraints[1].push_back(constraints[0][2]);
                    constraints[1].push_back(constraints[0][1]);

                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups(
                        2, std::vector<std::pair<std::size_t, std::size_t>>());

                    constraints.push_back({cells[cell_index++]});
                    constraints[2].push_back(constraints[0][1]);
                    constraints.push_back({constraints[2][0]});
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        constraints[3].push_back(cells[cell_index++]);
                        lookups[0].push_back(constraints[3].back());
                        lookups[1].push_back(constraints[3].back());
                    }

                    constraints.push_back({cells[cell_index++]});
                    constraints[4].push_back(constraints[0][2]);
                    constraints.push_back({constraints[4][0]});
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        constraints[5].push_back(cells[cell_index++]);
                        lookups[0].push_back(constraints[5].back());
                        lookups[1].push_back(constraints[5].back());
                    }
                    constraints.push_back({rot_const, minus_rot_const});

                    constraints[0].push_back(constraints[6][1]);
                    constraints[1].push_back(constraints[6][0]);
                    constraints[2].push_back(constraints[6][0]);
                    constraints[4].push_back(constraints[6][1]);

                    last_column = cells.back().second + 1 + calculate_buff(witness_amount, num_chunks);
                    last_row = cells.back().first + (last_column / witness_amount);
                    last_column %= witness_amount;

                    return configuration(first_coordinate, {last_row, last_column}, copy_to, constraints, lookups,
                                         cell_copy_from);
                }


                static configuration configure_additional_rot(std::size_t witness_amount, std::size_t limit_permutation_column,
                                                   std::size_t row, std::size_t column) {
                    // regular constraints:
                    // small_part = small_part_chunk0 + small_part_chunk1 * 2^chunk_size + ... + small_part_chunkk * 2^(k*chunk_size)
                    // big_part = big_part_chunk0 + big_part_chunk1 * 2^chunk_size + ... + big_part_chunkk * 2^(k*chunk_size)

                    std::pair<std::size_t, std::size_t> first_coordinate = {row, column};

                    std::size_t last_row = row, last_column = column;
                    std::size_t num_chunks = calculate_num_chunks(lookup_rows);
                    std::size_t num_cells = 2 * (1 + 8);
                    std::size_t buff = (10 * witness_amount - num_cells) % witness_amount;

                    std::vector<std::pair<std::size_t, std::size_t>> copy_to;
                    std::pair<std::size_t, std::size_t> cell_copy_from;
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints;

                    if (2 + column > limit_permutation_column) {
                        copy_to.push_back({last_row + 1, 0});
                        cell_copy_from = {last_row + 1, 1};
                    } else {
                        copy_to.push_back(
                            {last_row + (last_column / witness_amount), (last_column++) % witness_amount});
                        cell_copy_from = {last_row + (last_column / witness_amount), (last_column++) % witness_amount};
                    }

                    std::vector<std::pair<std::size_t, std::size_t>> cells;
                    std::size_t cur_row = row, cur_column = 0;
                    while (cur_column < num_cells) {
                        cells.push_back({cur_row + (cur_column / witness_amount), (cur_column++) % witness_amount});
                    }
                    std::size_t cell_index = 0;

                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups(
                        2, std::vector<std::pair<std::size_t, std::size_t>>());

                    constraints.push_back({cells[cell_index++]});
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        constraints[0].push_back(cells[cell_index++]);
                        lookups[0].push_back(constraints[0].back());
                        lookups[1].push_back(constraints[0].back());
                    }
                    constraints.push_back({cells[cell_index++]});
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        constraints[1].push_back(cells[cell_index++]);
                        lookups[0].push_back(constraints[1].back());
                        lookups[1].push_back(constraints[1].back());
                    }
                    for (int i = 0; i < 2; ++i) {
                        copy_to.push_back(constraints[i][0]);
                    }

                    last_column = cells.back().second + 1 + buff;
                    last_row = cells.back().first + (last_column / witness_amount);
                    last_column %= witness_amount;

                    return configuration(first_coordinate, {last_row, last_column}, copy_to, constraints, lookups,
                                         cell_copy_from);
                }

                static std::vector<configuration> configure_all(std::size_t witness_amount,
                                                                bool xor_with_mes,
                                                                bool last_round_call,
                                                                std::size_t limit_permutation_column) {
                    std::size_t full_configuration_size = 17 * xor_with_mes + 85 + 29;
                    auto result = std::vector<configuration>(full_configuration_size);
                    std::size_t row = 0, column = 0;
                    std::size_t cur_config = 0;

                    // inner_state ^ chunk
                    if (xor_with_mes) {
                        for (int i = 0; i < 17 - last_round_call; ++i) {
                            result[i] = configure_xor(witness_amount, limit_permutation_column, row, column, 2);
                            row = result[i].last_coordinate.row;
                            column = result[i].last_coordinate.column;
                            cur_config++;
                        }
                        // xor with last message chunk
                        if (last_round_call) {
                            result[cur_config] =
                                configure_xor(witness_amount, limit_permutation_column, row, column, 3);
                            row = result[cur_config].last_coordinate.row;
                            column = result[cur_config].last_coordinate.column;
                            cur_config++;
                        }
                    }
                    // theta
                    for (int i = 0; i < 5; ++i) {
                        result[cur_config] = configure_xor(witness_amount, limit_permutation_column, row, column, 5);
                        row = result[cur_config].last_coordinate.row;
                        column = result[cur_config].last_coordinate.column;
                        cur_config++;
                    }
                    for (int i = 0; i < 5; ++i) {
                        result[cur_config] = configure_rot(witness_amount, limit_permutation_column, row, column);
                        row = result[cur_config].last_coordinate.row;
                        column = result[cur_config].last_coordinate.column;
                        cur_config++;
                    }
                    for (int i = 0; i < 25; ++i) {
                        result[cur_config] = configure_xor(witness_amount, limit_permutation_column, row, column, 3);
                        row = result[cur_config].last_coordinate.row;
                        column = result[cur_config].last_coordinate.column;
                        cur_config++;
                    }
                    // rho/phi
                    for (int i = 0; i < 24; ++i) {
                        result[cur_config] = configure_rot(witness_amount, limit_permutation_column, row, column);
                        row = result[cur_config].last_coordinate.row;
                        column = result[cur_config].last_coordinate.column;
                        cur_config++;
                    }
                    // chi
                    for (int i = 0; i < 25; ++i) {
                        result[cur_config] = configure_chi(witness_amount, limit_permutation_column, row, column);
                        row = result[cur_config].last_coordinate.row;
                        column = result[cur_config].last_coordinate.column;
                        cur_config++;
                    }
                    // iota
                    result[cur_config] = configure_xor(witness_amount, limit_permutation_column, row, column, 2);
                    row = result[cur_config].last_coordinate.row;
                    column = result[cur_config++].last_coordinate.column;
                    if (column != 0) {
                        row++;
                        column = 0;
                    }

                    // rot range checks 24+5
                    for (int i = 0; i < 29; ++i) {
                        result[cur_config] = configure_additional_rot(witness_amount, limit_permutation_column, row, column);
                        row = result[cur_config].last_coordinate.row;
                        column = result[cur_config].last_coordinate.column;
                        cur_config++;
                    }

                    // for (int i = 0; i < result.size(); ++i) {
                    //     std::cout << "\n config: " << result[i].name << std::endl;
                    //     std::cout << result[i].first_coordinate.row << " " << result[i].first_coordinate.column << "
                    //     " << result[i].last_coordinate.row << " " << result[i].last_coordinate.column << std::endl;
                    //     std::cout << result[i].copy_from.row << " " << result[i].copy_from.column << std::endl;
                    //     for (int j = 0; j < result[i].copy_to.size(); ++j) {
                    //         std::cout << result[i].copy_to[j].row << " " << result[i].copy_to[j].column << std::endl;
                    //     }
                    //     for (int j = 0; j < result[i].constraints.size(); ++j) {
                    //         for (int k = 0; k < result[i].constraints[j].size(); ++k) {
                    //             std::cout << result[i].constraints[j][k].row << " " <<
                    //             result[i].constraints[j][k].column << ", ";
                    //         }
                    //         std::cout << std::endl;
                    //     }
                    //     std::cout << "lookups: " << result[i].lookups.size() << std::endl;
                    //     for (int j = 0; j < result[i].lookups.size(); ++j) {
                    //         for (int k = 0; k < result[i].lookups[j].size(); ++k) {
                    //             std::cout << result[i].lookups[j][k].row << " " << result[i].lookups[j][k].column <<
                    //             ", ";
                    //         }
                    //         std::cout << std::endl;
                    //     }
                    // }

                    return result;
                }

                static std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>>
                    configure_map(std::size_t witness_amount,
                                  bool xor_with_mes,
                                  bool last_round_call,
                                  std::size_t limit_permutation_column) {
                    auto config =
                        configure_all(witness_amount, xor_with_mes, last_round_call, limit_permutation_column);
                    std::size_t row = 0, column = 0;
                    std::size_t cur_config = 0;

                    std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> config_map;

                    // inner_state ^ chunk
                    if (xor_with_mes) {
                        for (int i = 0; i < 17 - last_round_call; ++i) {
                            row = config[cur_config].first_coordinate.row;
                            column = config[cur_config].first_coordinate.column;
                            std::pair<std::size_t, std::size_t> zero_config = {2, column};
                            if (config_map.find(zero_config) != config_map.end()) {
                                config_map[zero_config].push_back(row);
                            } else {
                                config_map[zero_config] = {row};
                            }
                            cur_config++;
                        }
                        // xor with last message chunk
                        if (last_round_call) {
                            row = config[cur_config].first_coordinate.row;
                            column = config[cur_config].first_coordinate.column;
                            std::pair<std::size_t, std::size_t> zero_config = {3, column};
                            if (config_map.find(zero_config) != config_map.end()) {
                                config_map[zero_config].push_back(row);
                            } else {
                                config_map[zero_config] = {row};
                            }
                            cur_config++;
                        }
                    }
                    // theta
                    for (int i = 0; i < 5; ++i) {
                        row = config[cur_config].first_coordinate.row;
                        column = config[cur_config].first_coordinate.column;
                        std::pair<std::size_t, std::size_t> zero_config = {5, column};
                        if (config_map.find(zero_config) != config_map.end()) {
                            config_map[zero_config].push_back(row);
                        } else {
                            config_map[zero_config] = {row};
                        }
                        cur_config++;
                    }
                    for (int i = 0; i < 5; ++i) {
                        row = config[cur_config].first_coordinate.row;
                        column = config[cur_config].first_coordinate.column;
                        std::pair<std::size_t, std::size_t> zero_config = {7, column};
                        if (config_map.find(zero_config) != config_map.end()) {
                            config_map[zero_config].push_back(row);
                        } else {
                            config_map[zero_config] = {row};
                        }
                        cur_config++;
                    }
                    for (int i = 0; i < 25; ++i) {
                        row = config[cur_config].first_coordinate.row;
                        column = config[cur_config].first_coordinate.column;
                        std::pair<std::size_t, std::size_t> zero_config = {3, column};
                        if (config_map.find(zero_config) != config_map.end()) {
                            config_map[zero_config].push_back(row);
                        } else {
                            config_map[zero_config] = {row};
                        }
                        cur_config++;
                    }
                    // rho/phi
                    for (int i = 0; i < 24; ++i) {
                        row = config[cur_config].first_coordinate.row;
                        column = config[cur_config].first_coordinate.column;
                        std::pair<std::size_t, std::size_t> zero_config = {7, column};
                        if (config_map.find(zero_config) != config_map.end()) {
                            config_map[zero_config].push_back(row);
                        } else {
                            config_map[zero_config] = {row};
                        }
                        cur_config++;
                    }
                    // chi
                    for (int i = 0; i < 25; ++i) {
                        row = config[cur_config].first_coordinate.row;
                        column = config[cur_config].first_coordinate.column;
                        std::pair<std::size_t, std::size_t> zero_config = {0, column};
                        if (config_map.find(zero_config) != config_map.end()) {
                            config_map[zero_config].push_back(row);
                        } else {
                            config_map[zero_config] = {row};
                        }
                        cur_config++;
                    }
                    // iota
                    row = config[cur_config].first_coordinate.row;
                    column = config[cur_config++].first_coordinate.column;
                    std::pair<std::size_t, std::size_t> zero_config = {2, column};
                    if (config_map.find(zero_config) != config_map.end()) {
                        config_map[zero_config].push_back(row);
                    } else {
                        config_map[zero_config] = {row};
                    }
                    // additional rot range checks
                    for (int i = 0; i < 29; ++i) {
                        row = config[cur_config].first_coordinate.row;
                        column = config[cur_config].first_coordinate.column;
                        std::pair<std::size_t, std::size_t> zero_config = {10, column};
                        if (config_map.find(zero_config) != config_map.end()) {
                            config_map[zero_config].push_back(row);
                        } else {
                            config_map[zero_config] = {row};
                        }
                        cur_config++;
                    }

                    return config_map;
                }

                static std::vector<std::vector<configuration>> configure_gates(std::size_t witness_amount,
                                                                               bool xor_with_mes,
                                                                               bool last_round_call,
                                                                               std::size_t limit_permutation_column) {

                    std::vector<std::vector<configuration>> result;
                    auto gates_configuration_map =
                        configure_map(witness_amount, xor_with_mes, last_round_call, limit_permutation_column);

                    for (auto config : gates_configuration_map) {
                        configuration cur_config;
                        switch (config.first.first) {
                            case 2:
                                cur_config =
                                    configure_xor(witness_amount, limit_permutation_column, 0, config.first.second, 2);
                                break;
                            case 3:
                                cur_config =
                                    configure_xor(witness_amount, limit_permutation_column, 0, config.first.second, 3);
                                break;
                            case 5:
                                cur_config =
                                    configure_xor(witness_amount, limit_permutation_column, 0, config.first.second, 5);
                                break;
                            case 7:
                                cur_config =
                                    configure_rot(witness_amount, limit_permutation_column, 0, config.first.second);
                                break;
                            case 0:
                                cur_config =
                                    configure_chi(witness_amount, limit_permutation_column, 0, config.first.second);
                                break;
                            case 10:
                                cur_config =
                                    configure_additional_rot(witness_amount, limit_permutation_column, 0, config.first.second);
                                break;
                        }

                        // std::cout << "\nconfig:\n";
                        // std::cout << config.first.first << "\n";
                        // std::cout << cur_config.first_coordinate.row << " " << cur_config.first_coordinate.column <<
                        // " " << cur_config.last_coordinate.row << " " << cur_config.last_coordinate.column <<
                        // std::endl; std::cout << cur_config.copy_from.row << " " << cur_config.copy_from.column <<
                        // std::endl; for (int j = 0; j < cur_config.copy_to.size(); ++j) {
                        //     std::cout << cur_config.copy_to[j].row << " " << cur_config.copy_to[j].column <<
                        //     std::endl;
                        // }
                        // for (int j = 0; j < cur_config.constraints.size(); ++j) {
                        //     for (int k = 0; k < cur_config.constraints[j].size(); ++k) {
                        //         std::cout << cur_config.constraints[j][k].row << " " <<
                        //         cur_config.constraints[j][k].column << ", ";
                        //     }
                        //     std::cout << std::endl;
                        // }

                        std::vector<std::pair<std::size_t, std::size_t>> pairs;
                        for (auto constr : cur_config.constraints) {
                            std::size_t min = constr[0].row;
                            std::size_t max = constr.back().row;
                            for (std::size_t j = 0; j < constr.size(); ++j) {
                                min = std::min(min, constr[j].row);
                                max = std::max(max, constr[j].row);
                            }
                            BOOST_ASSERT(max <= 2 + min);
                            pairs.push_back({min, max});
                        }
                        std::vector<configuration> cur_result;
                        std::size_t cur_row = 0;
                        std::size_t cur_constr = 0;
                        while (cur_constr < pairs.size()) {
                            configuration c;
                            while (cur_constr < pairs.size() && pairs[cur_constr].second <= cur_row + 2 &&
                                    pairs[cur_constr].first >= cur_row) {
                                c.constraints.push_back(cur_config.constraints[cur_constr]);
                                c.first_coordinate = {cur_row, 0};
                                ++cur_constr;
                            }
                            if (cur_constr < pairs.size()) {
                                cur_row = pairs[cur_constr].first;
                            }
                            cur_result.push_back(c);
                        }
                        result.push_back(cur_result);
                    }

                    return result;
                }

                static std::vector<std::vector<configuration>>
                    configure_lookup_gates(std::size_t witness_amount,
                                           bool xor_with_mes,
                                           bool last_round_call,
                                           std::size_t limit_permutation_column) {
                    auto full_configuration =
                        configure_all(witness_amount, xor_with_mes, last_round_call, limit_permutation_column);
                    std::vector<std::vector<configuration>> result;
                    auto gates_configuration_map =
                        configure_map(witness_amount, xor_with_mes, last_round_call, limit_permutation_column);

                    for (auto config : gates_configuration_map) {
                        configuration cur_config;
                        switch (config.first.first) {
                            case 2:
                                cur_config =
                                    configure_xor(witness_amount, limit_permutation_column, 0, config.first.second, 2);
                                break;
                            case 3:
                                cur_config =
                                    configure_xor(witness_amount, limit_permutation_column, 0, config.first.second, 3);
                                break;
                            case 5:
                                cur_config =
                                    configure_xor(witness_amount, limit_permutation_column, 0, config.first.second, 5);
                                break;
                            case 7:
                                cur_config =
                                    configure_rot(witness_amount, limit_permutation_column, 0, config.first.second);
                                break;
                            case 0:
                                cur_config =
                                    configure_chi(witness_amount, limit_permutation_column, 0, config.first.second);
                                break;
                            case 10:
                                cur_config =
                                    configure_additional_rot(witness_amount, limit_permutation_column, 0, config.first.second);
                                break;
                        }

                        std::vector<std::pair<std::size_t, std::size_t>> pairs;
                        for (auto constr : cur_config.lookups) {
                            std::size_t min = constr[0].row;
                            std::size_t max = constr.back().row;
                            for (std::size_t j = 0; j < constr.size(); ++j) {
                                min = std::min(min, constr[j].row);
                                max = std::max(max, constr[j].row);
                            }
                            BOOST_ASSERT(max <= 2 + min);
                            pairs.push_back({min, max});
                        }

                        std::vector<configuration> cur_result;
                        std::size_t cur_row = 0;
                        std::size_t cur_constr = 0;
                        bool found;
                        while (cur_constr < pairs.size()) {
                            configuration c;
                            found = false;
                            while (cur_constr < pairs.size() && pairs[cur_constr].second <= cur_row + 2 &&
                                   pairs[cur_constr].first >= cur_row) {
                                c.lookups.push_back(cur_config.lookups[cur_constr]);
                                c.first_coordinate = {cur_row, 0};
                                ++cur_constr;
                                found = true;
                            }
                            if (cur_constr < pairs.size()) {
                                cur_row = pairs[cur_constr].first;
                            }
                            if (found) {
                                cur_result.push_back(c);
                            }
                        }
                        result.push_back(cur_result);
                    }
                    // std::size_t cur_row = 0;
                    // std::size_t cur_constr = 0;
                    // while (cur_row < rows_amount) {
                    //     while (cur_constr < pairs.size() && pairs[cur_constr].second <= cur_row + 2 &&
                    //     pairs[cur_constr].first >= cur_row) {
                    //         result.push_back(cur_row + 1);
                    //         ++cur_constr;
                    //     }
                    //     if (cur_constr == pairs.size()) {
                    //         break;
                    //     }
                    //     cur_row = pairs[cur_constr].first;
                    // }
                    return result;
                }
                static std::size_t get_gates_amount(std::size_t witness_amount,
                                                    bool xor_with_mes,
                                                    bool last_round_call,
                                                    std::size_t limit_permutation_column) {
                    std::size_t res = 0;
                    auto gates_configuration =
                        configure_gates(witness_amount, xor_with_mes, last_round_call, limit_permutation_column);
                    for (std::size_t i = 0; i < gates_configuration.size(); ++i) {
                        res += gates_configuration[i].size();
                    }
                    auto lookup_gates_configuration =
                        configure_lookup_gates(witness_amount, xor_with_mes, last_round_call, limit_permutation_column);
                    for (std::size_t i = 0; i < lookup_gates_configuration.size(); ++i) {
                        res += lookup_gates_configuration[i].size();
                    }
                    std::cout << "Keccak round gates amount = " << res << std::endl;
                    return res;
                }

                static std::size_t get_rows_amount(std::size_t witness_amount,
                                                   bool xor_with_mes,
                                                   bool last_round_call,
                                                   std::size_t limit_permutation_column) {
                    std::size_t xor2_cells = calculate_num_cells(lookup_rows, 3);
                    std::size_t xor3_cells = calculate_num_cells(lookup_rows, 4);
                    std::size_t xor5_cells = calculate_num_cells(lookup_rows, 6);
                    std::size_t chi_cells = calculate_num_cells(lookup_rows, 5);
                    std::size_t rotate_cells = calculate_num_cells(lookup_rows);
                    std::size_t additional_rotate_cells = 2 * (1 + 8);
                    std::size_t xor2_buff = calculate_buff(witness_amount, lookup_rows, 3);
                    std::size_t xor3_buff = calculate_buff(witness_amount, lookup_rows, 4);
                    std::size_t xor5_buff = calculate_buff(witness_amount, lookup_rows, 6);
                    std::size_t chi_buff = calculate_buff(witness_amount, lookup_rows, 5);
                    std::size_t rotate_buff = calculate_buff(witness_amount, lookup_rows);
                    std::size_t additional_rotate_buff = (10 * witness_amount - additional_rotate_cells) % witness_amount;

                    std::size_t num_cells =
                        (xor3_cells + xor3_buff) * last_round_call * xor_with_mes +    // xor with last message chunk
                        ((17 - last_round_call) * (xor2_cells + xor2_buff)) * xor_with_mes +    // inner_state ^ chunk
                        5 * (xor5_cells + xor5_buff) +                                          // theta
                        5 * (rotate_cells + rotate_buff) +                                      // theta
                        25 * (xor3_cells + xor3_buff) +                                         // theta
                        24 * (rotate_cells + rotate_buff) +                                     // rho/phi
                        25 * (chi_cells + chi_buff) +                                           // chi
                        xor2_cells + xor2_buff +                                                            // iota
                        29 * (additional_rotate_cells + additional_rotate_buff);                // additional rotate
                    // return num_cells / witness_amount + bool(num_cells % witness_amount);
                    auto config = configure_all(witness_amount, xor_with_mes, last_round_call, limit_permutation_column);
                    return config.back().last_coordinate.row + (config.back().last_coordinate.column > 0);
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["keccak_normalize3_table/full"] = 0;            // REQUIRED_TABLE
                    lookup_tables["keccak_normalize4_table/full"] = 0;            // REQUIRED_TABLE
                    lookup_tables["keccak_normalize6_table/full"] = 0;            // REQUIRED_TABLE
                    lookup_tables["keccak_chi_table/full"] = 0;                   // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/range_check_sparse"] = 0;    // REQUIRED_TABLE
                    return lookup_tables;
                }

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak_round(WitnessContainerType witness, ConstantContainerType constant,
                             PublicInputContainerType public_input, bool xor_with_mes_ = false,
                             bool last_round_call_ = false, std::size_t lpc_ = 7) :
                    component_type(witness, constant, public_input,
                                   get_manifest(xor_with_mes_, last_round_call_, lpc_)),
                    xor_with_mes(xor_with_mes_), last_round_call(last_round_call_), limit_permutation_column(lpc_) {
                                                                                        // check_params();
                                                                                    };

                keccak_round(std::initializer_list<typename component_type::witness_container_type::value_type>
                                 witnesses,
                             std::initializer_list<typename component_type::constant_container_type::value_type>
                                 constants,
                             std::initializer_list<typename component_type::public_input_container_type::value_type>
                                 public_inputs,
                             bool xor_with_mes_ = false,
                             bool last_round_call_ = false,
                             std::size_t lpc_ = 7) :
                    component_type(witnesses, constants, public_inputs,
                                   get_manifest(xor_with_mes_, last_round_call_, lpc_)),
                    xor_with_mes(xor_with_mes_), last_round_call(last_round_call_), limit_permutation_column(lpc_) {
                                                                                        // check_params();
                                                                                    };
            };

            template<typename BlueprintFieldType>
            using keccak_round_component =
                keccak_round<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            std::vector<std::size_t> generate_gates(
                const keccak_round_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename keccak_round_component<BlueprintFieldType>::input_type &instance_input,
                const typename lookup_library<BlueprintFieldType>::left_reserved_type lookup_tables_indices) {
                using component_type = keccak_round_component<BlueprintFieldType>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using lookup_constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using integral_type = typename BlueprintFieldType::integral_type;

                auto gate_map = component.gates_configuration_map;
                auto gate_config = component.gates_configuration;
                auto lookup_gate_config = component.lookup_gates_configuration;

                std::vector<std::size_t> selector_indexes;
                std::vector<constraint_type> constraints;
                std::vector<lookup_constraint_type> lookup_constraints;

                // general gates
                std::size_t index = 0;
                for (auto gm : gate_map) {
                    std::vector<configuration> cur_config_vec = gate_config[index];
                    std::size_t i = 0, j = 0, cur_len = 0;
                    std::vector<constraint_type> cur_constraints;
                    std::vector<configuration> cur_lookup_config_vec = lookup_gate_config[index];
                    std::vector<lookup_constraint_type> cur_lookup_constraints;
                    std::string cur_lookup_table_name;
                    switch (gm.first.first) {
                        case 2: {
                            cur_constraints.push_back(
                                constraint_type(var(cur_config_vec[i].constraints[j][1].column,
                                                    cur_config_vec[i].constraints[j][1].row -
                                                        cur_config_vec[i].first_coordinate.row - 1) +
                                                var(cur_config_vec[i].constraints[j][2].column,
                                                    cur_config_vec[i].constraints[j][2].row -
                                                        cur_config_vec[i].first_coordinate.row - 1) -
                                                var(cur_config_vec[i].constraints[j][0].column,
                                                    cur_config_vec[i].constraints[j][0].row -
                                                        cur_config_vec[i].first_coordinate.row - 1)));

                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                selector_indexes.push_back(bp.add_gate(cur_constraints));
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_1 = var(cur_config_vec[i].constraints[j][0].column,
                                                               cur_config_vec[i].constraints[j][0].row -
                                                                   cur_config_vec[i].first_coordinate.row - 1);
                            for (std::size_t k = 0; k < component.normalize3_num_chunks; ++k) {
                                constraint_1 -= var(cur_config_vec[i].constraints[j][k + 1].column,
                                                    cur_config_vec[i].constraints[j][k + 1].row -
                                                        cur_config_vec[i].first_coordinate.row - 1) *
                                                (integral_type(1) << (k * component.normalize3_chunk_size));
                            }
                            cur_constraints.push_back(constraint_1);

                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                selector_indexes.push_back(bp.add_gate(cur_constraints));
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_2 = var(cur_config_vec[i].constraints[j][0].column,
                                                               cur_config_vec[i].constraints[j][0].row -
                                                                   cur_config_vec[i].first_coordinate.row - 1);
                            for (std::size_t k = 0; k < component.normalize3_num_chunks; ++k) {
                                constraint_2 -= var(cur_config_vec[i].constraints[j][k + 1].column,
                                                    cur_config_vec[i].constraints[j][k + 1].row -
                                                        cur_config_vec[i].first_coordinate.row - 1) *
                                                (integral_type(1) << (k * component.normalize3_chunk_size));
                            }
                            cur_constraints.push_back(constraint_2);
                            selector_indexes.push_back(bp.add_gate(cur_constraints));

                            cur_lookup_table_name = "keccak_normalize3_table/full";
                            break;
                        }
                        case 3: {
                            cur_constraints.push_back(var(cur_config_vec[i].constraints[j][1].column,
                                                          cur_config_vec[i].constraints[j][1].row -
                                                              cur_config_vec[i].first_coordinate.row - 1) +
                                                      var(cur_config_vec[i].constraints[j][2].column,
                                                          cur_config_vec[i].constraints[j][2].row -
                                                              cur_config_vec[i].first_coordinate.row - 1) +
                                                      var(cur_config_vec[i].constraints[j][3].column,
                                                          cur_config_vec[i].constraints[j][3].row -
                                                              cur_config_vec[i].first_coordinate.row - 1) -
                                                      var(cur_config_vec[i].constraints[j][0].column,
                                                          cur_config_vec[i].constraints[j][0].row -
                                                              cur_config_vec[i].first_coordinate.row - 1));

                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                selector_indexes.push_back(bp.add_gate(cur_constraints));
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_1 = var(cur_config_vec[i].constraints[j][0].column,
                                                               cur_config_vec[i].constraints[j][0].row -
                                                                   cur_config_vec[i].first_coordinate.row - 1);
                            for (std::size_t k = 0; k < component.normalize4_num_chunks; ++k) {
                                constraint_1 -= var(cur_config_vec[i].constraints[j][k + 1].column,
                                                    cur_config_vec[i].constraints[j][k + 1].row -
                                                        cur_config_vec[i].first_coordinate.row - 1) *
                                                (integral_type(1) << (k * component.normalize4_chunk_size));
                            }
                            cur_constraints.push_back(constraint_1);

                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                selector_indexes.push_back(bp.add_gate(cur_constraints));
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_2 = var(cur_config_vec[i].constraints[j][0].column,
                                                               cur_config_vec[i].constraints[j][0].row -
                                                                   cur_config_vec[i].first_coordinate.row - 1);
                            for (std::size_t k = 0; k < component.normalize4_num_chunks; ++k) {
                                constraint_2 -= var(cur_config_vec[i].constraints[j][k + 1].column,
                                                    cur_config_vec[i].constraints[j][k + 1].row -
                                                        cur_config_vec[i].first_coordinate.row - 1) *
                                                (integral_type(1) << (k * component.normalize4_chunk_size));
                            }
                            cur_constraints.push_back(constraint_2);
                            selector_indexes.push_back(bp.add_gate(cur_constraints));

                            cur_lookup_table_name = "keccak_normalize4_table/full";
                            break;
                        }
                        case 5: {
                            cur_constraints.push_back(var(cur_config_vec[i].constraints[j][1].column,
                                                          cur_config_vec[i].constraints[j][1].row -
                                                              cur_config_vec[i].first_coordinate.row - 1) +
                                                      var(cur_config_vec[i].constraints[j][2].column,
                                                          cur_config_vec[i].constraints[j][2].row -
                                                              cur_config_vec[i].first_coordinate.row - 1) +
                                                      var(cur_config_vec[i].constraints[j][3].column,
                                                          cur_config_vec[i].constraints[j][3].row -
                                                              cur_config_vec[i].first_coordinate.row - 1) +
                                                      var(cur_config_vec[i].constraints[j][4].column,
                                                          cur_config_vec[i].constraints[j][4].row -
                                                              cur_config_vec[i].first_coordinate.row - 1) +
                                                      var(cur_config_vec[i].constraints[j][5].column,
                                                          cur_config_vec[i].constraints[j][5].row -
                                                              cur_config_vec[i].first_coordinate.row - 1) -
                                                      var(cur_config_vec[i].constraints[j][0].column,
                                                          cur_config_vec[i].constraints[j][0].row -
                                                              cur_config_vec[i].first_coordinate.row - 1));

                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                selector_indexes.push_back(bp.add_gate(cur_constraints));
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_1 = var(cur_config_vec[i].constraints[j][0].column,
                                                               cur_config_vec[i].constraints[j][0].row -
                                                                   cur_config_vec[i].first_coordinate.row - 1);
                            for (std::size_t k = 0; k < component.normalize6_num_chunks; ++k) {
                                constraint_1 -= var(cur_config_vec[i].constraints[j][k + 1].column,
                                                    cur_config_vec[i].constraints[j][k + 1].row -
                                                        cur_config_vec[i].first_coordinate.row - 1) *
                                                (integral_type(1) << (k * component.normalize6_chunk_size));
                            }
                            cur_constraints.push_back(constraint_1);

                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                selector_indexes.push_back(bp.add_gate(cur_constraints));
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_2 = var(cur_config_vec[i].constraints[j][0].column,
                                                               cur_config_vec[i].constraints[j][0].row -
                                                                   cur_config_vec[i].first_coordinate.row - 1);
                            for (std::size_t k = 0; k < component.normalize6_num_chunks; ++k) {
                                constraint_2 -= var(cur_config_vec[i].constraints[j][k + 1].column,
                                                    cur_config_vec[i].constraints[j][k + 1].row -
                                                        cur_config_vec[i].first_coordinate.row - 1) *
                                                (integral_type(1) << (k * component.normalize6_chunk_size));
                            }
                            cur_constraints.push_back(constraint_2);
                            selector_indexes.push_back(bp.add_gate(cur_constraints));

                            cur_lookup_table_name = "keccak_normalize6_table/full";
                            break;
                        }
                        case 7: {
                            std::size_t true_first_row = cur_config_vec[i].first_coordinate.row;

                            cur_constraints.push_back(var(cur_config_vec[i].constraints[j][1].column,
                                                          cur_config_vec[i].constraints[j][1].row -
                                                              cur_config_vec[i].first_coordinate.row - 1) *
                                                          var(cur_config_vec[i].constraints[j][3].column,
                                                              cur_config_vec[i].constraints[j][3].row -
                                                                  cur_config_vec[i].first_coordinate.row - 1) +
                                                      var(cur_config_vec[i].constraints[j][2].column,
                                                          cur_config_vec[i].constraints[j][2].row -
                                                              cur_config_vec[i].first_coordinate.row - 1) -
                                                      var(cur_config_vec[i].constraints[j][0].column,
                                                          cur_config_vec[i].constraints[j][0].row -
                                                              cur_config_vec[i].first_coordinate.row - 1));

                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                selector_indexes.push_back(bp.add_gate(cur_constraints));
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            cur_constraints.push_back(var(cur_config_vec[i].constraints[1][1].column,
                                                          cur_config_vec[i].constraints[1][1].row -
                                                              cur_config_vec[i].first_coordinate.row - 1) *
                                                          var(cur_config_vec[i].constraints[j][3].column,
                                                              cur_config_vec[i].constraints[j][3].row -
                                                                  cur_config_vec[i].first_coordinate.row - 1) +
                                                      var(cur_config_vec[i].constraints[1][2].column,
                                                          cur_config_vec[i].constraints[1][2].row -
                                                              cur_config_vec[i].first_coordinate.row - 1) -
                                                      var(cur_config_vec[i].constraints[1][0].column,
                                                          cur_config_vec[i].constraints[1][0].row -
                                                              cur_config_vec[i].first_coordinate.row - 1));

                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                selector_indexes.push_back(bp.add_gate(cur_constraints));
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            cur_constraints.push_back(
                                var(cur_config_vec[i].constraints[j][0].column,
                                    cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row -
                                        1) -
                                var(cur_config_vec[i].constraints[j][1].column,
                                    cur_config_vec[i].constraints[j][1].row - cur_config_vec[i].first_coordinate.row -
                                        1) +
                                var(component.C(0), true_first_row + 1 - cur_config_vec[i].first_coordinate.row - 1,
                                    true, var::column_type::constant) -
                                component.big_rot_const);

                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                selector_indexes.push_back(bp.add_gate(cur_constraints));
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_1 = var(cur_config_vec[i].constraints[j][0].column,
                                                               cur_config_vec[i].constraints[j][0].row -
                                                                   cur_config_vec[i].first_coordinate.row - 1);
                            for (std::size_t k = 0; k < component.rotate_num_chunks; ++k) {
                                constraint_1 -= var(cur_config_vec[i].constraints[j][k + 1].column,
                                                    cur_config_vec[i].constraints[j][k + 1].row -
                                                        cur_config_vec[i].first_coordinate.row - 1) *
                                                (integral_type(1) << (k * component.rotate_chunk_size));
                            }
                            cur_constraints.push_back(constraint_1);

                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                selector_indexes.push_back(bp.add_gate(cur_constraints));
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            cur_constraints.push_back(
                                var(cur_config_vec[i].constraints[j][0].column,
                                    cur_config_vec[i].constraints[j][0].row - cur_config_vec[i].first_coordinate.row -
                                        1) -
                                var(cur_config_vec[i].constraints[j][1].column,
                                    cur_config_vec[i].constraints[j][1].row - cur_config_vec[i].first_coordinate.row -
                                        1) +
                                var(component.C(0), true_first_row + 2 - cur_config_vec[i].first_coordinate.row - 1,
                                    true, var::column_type::constant) -
                                component.big_rot_const);

                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                selector_indexes.push_back(bp.add_gate(cur_constraints));
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_2 = var(cur_config_vec[i].constraints[j][0].column,
                                                               cur_config_vec[i].constraints[j][0].row -
                                                                   cur_config_vec[i].first_coordinate.row - 1);
                            for (std::size_t k = 0; k < component.rotate_num_chunks; ++k) {
                                constraint_2 -= var(cur_config_vec[i].constraints[j][k + 1].column,
                                                    cur_config_vec[i].constraints[j][k + 1].row -
                                                        cur_config_vec[i].first_coordinate.row - 1) *
                                                (integral_type(1) << (k * component.rotate_chunk_size));
                            }
                            cur_constraints.push_back(constraint_2);

                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                selector_indexes.push_back(bp.add_gate(cur_constraints));
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            cur_constraints.push_back(var(cur_config_vec[i].constraints[j][0].column,
                                                          cur_config_vec[i].constraints[j][0].row -
                                                              cur_config_vec[i].first_coordinate.row - 1) *
                                                          var(cur_config_vec[i].constraints[j][1].column,
                                                              cur_config_vec[i].constraints[j][1].row -
                                                                  cur_config_vec[i].first_coordinate.row - 1) -
                                                      (integral_type(1) << 192));

                            selector_indexes.push_back(bp.add_gate(cur_constraints));

                            cur_lookup_table_name = "keccak_pack_table/range_check_sparse";
                            break;
                        }
                        case 10: {
                            std::size_t true_first_row = cur_config_vec[i].first_coordinate.row;

                            constraint_type constraint_1 = var(cur_config_vec[i].constraints[j][0].column,
                                                               cur_config_vec[i].constraints[j][0].row -
                                                                   cur_config_vec[i].first_coordinate.row - 1);
                            for (std::size_t k = 0; k < component.rotate_num_chunks; ++k) {
                                constraint_1 -= var(cur_config_vec[i].constraints[j][k + 1].column,
                                                    cur_config_vec[i].constraints[j][k + 1].row -
                                                        cur_config_vec[i].first_coordinate.row - 1) *
                                                (integral_type(1) << (k * component.rotate_chunk_size));
                            }
                            cur_constraints.push_back(constraint_1);

                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                selector_indexes.push_back(bp.add_gate(cur_constraints));
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_2 = var(cur_config_vec[i].constraints[j][0].column,
                                                               cur_config_vec[i].constraints[j][0].row -
                                                                   cur_config_vec[i].first_coordinate.row - 1);
                            for (std::size_t k = 0; k < component.rotate_num_chunks; ++k) {
                                constraint_2 -= var(cur_config_vec[i].constraints[j][k + 1].column,
                                                    cur_config_vec[i].constraints[j][k + 1].row -
                                                        cur_config_vec[i].first_coordinate.row - 1) *
                                                (integral_type(1) << (k * component.rotate_chunk_size));
                            }
                            cur_constraints.push_back(constraint_2);

                            selector_indexes.push_back(bp.add_gate(cur_constraints));
                            //std::cout << selector_indexes.back() << std::endl;

                            cur_lookup_table_name = "keccak_pack_table/range_check_sparse";
                            break;
                        }
                        case 0: {
                            cur_constraints.push_back(component.sparse_3 -
                                                      var(cur_config_vec[i].constraints[j][1].column,
                                                          cur_config_vec[i].constraints[j][1].row -
                                                              cur_config_vec[i].first_coordinate.row - 1) *
                                                          2 +
                                                      var(cur_config_vec[i].constraints[j][2].column,
                                                          cur_config_vec[i].constraints[j][2].row -
                                                              cur_config_vec[i].first_coordinate.row - 1) -
                                                      var(cur_config_vec[i].constraints[j][3].column,
                                                          cur_config_vec[i].constraints[j][3].row -
                                                              cur_config_vec[i].first_coordinate.row - 1) -
                                                      var(cur_config_vec[i].constraints[j][0].column,
                                                          cur_config_vec[i].constraints[j][0].row -
                                                              cur_config_vec[i].first_coordinate.row - 1));

                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                selector_indexes.push_back(bp.add_gate(cur_constraints));
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_1 = var(cur_config_vec[i].constraints[j][0].column,
                                                               cur_config_vec[i].constraints[j][0].row -
                                                                   cur_config_vec[i].first_coordinate.row - 1);
                            for (std::size_t k = 0; k < component.chi_num_chunks; ++k) {
                                constraint_1 -= var(cur_config_vec[i].constraints[j][k + 1].column,
                                                    cur_config_vec[i].constraints[j][k + 1].row -
                                                        cur_config_vec[i].first_coordinate.row - 1) *
                                                (integral_type(1) << (k * component.chi_chunk_size));
                            }
                            cur_constraints.push_back(constraint_1);

                            j++;
                            cur_len = cur_config_vec[i].constraints.size();
                            if (j >= cur_len) {
                                selector_indexes.push_back(bp.add_gate(cur_constraints));
                                cur_constraints.clear();
                            }
                            i += j / cur_len;
                            j %= cur_len;

                            constraint_type constraint_2 = var(cur_config_vec[i].constraints[j][0].column,
                                                               cur_config_vec[i].constraints[j][0].row -
                                                                   cur_config_vec[i].first_coordinate.row - 1);
                            for (std::size_t k = 0; k < component.chi_num_chunks; ++k) {
                                constraint_2 -= var(cur_config_vec[i].constraints[j][k + 1].column,
                                                    cur_config_vec[i].constraints[j][k + 1].row -
                                                        cur_config_vec[i].first_coordinate.row - 1) *
                                                (integral_type(1) << (k * component.chi_chunk_size));
                            }
                            cur_constraints.push_back(constraint_2);
                            selector_indexes.push_back(bp.add_gate(cur_constraints));

                            cur_lookup_table_name = "keccak_chi_table/full";
                            break;
                        }
                    }
                    if (gm.first.first >= 7) {
                        for (std::size_t i = 0; i < cur_lookup_config_vec.size(); ++i) {
                            for (std::size_t j = 0; j < cur_lookup_config_vec[i].lookups.size(); ++j) {
                                lookup_constraint_type lookup_constraint = {
                                    lookup_tables_indices.at(cur_lookup_table_name),
                                    {var(component.W(cur_lookup_config_vec[i].lookups[j][0].column),
                                         static_cast<int32_t>(cur_lookup_config_vec[i].lookups[j][0].row) -
                                             static_cast<int32_t>(cur_lookup_config_vec[i].first_coordinate.row) - 1)}};
                                cur_lookup_constraints.push_back(lookup_constraint);
                            }
                            selector_indexes.push_back(bp.add_lookup_gate(cur_lookup_constraints));
                            cur_lookup_constraints.clear();
                        }
                        ++index;
                        continue;
                    }

                    for (std::size_t i = 0; i < cur_lookup_config_vec.size(); ++i) {
                        for (std::size_t j = 0; j < cur_lookup_config_vec[i].lookups.size(); ++j) {
                            lookup_constraint_type lookup_constraint = {
                                lookup_tables_indices.at(cur_lookup_table_name),
                                {var(component.W(cur_lookup_config_vec[i].lookups[j][0].column),
                                     static_cast<int32_t>(cur_lookup_config_vec[i].lookups[j][0].row) -
                                         static_cast<int32_t>(cur_lookup_config_vec[i].first_coordinate.row) - 1),
                                 var(component.W(cur_lookup_config_vec[i].lookups[j][1].column),
                                     static_cast<int32_t>(cur_lookup_config_vec[i].lookups[j][1].row) -
                                         static_cast<int32_t>(cur_lookup_config_vec[i].first_coordinate.row) - 1)}};
                            cur_lookup_constraints.push_back(lookup_constraint);
                        }
                        selector_indexes.push_back(bp.add_lookup_gate(cur_lookup_constraints));
                        cur_lookup_constraints.clear();
                    }
                    index++;
                }
                return selector_indexes;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const keccak_round_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename keccak_round_component<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = keccak_round_component<BlueprintFieldType>;
                using var = typename component_type::var;

                std::size_t config_index = 0;
                std::size_t prev_index = 0;
                auto config = component.full_configuration;
                std::vector<var> additional_rot_vars;

                if (component.xor_with_mes) {
                    // inner_state ^ chunk
                    for (int i = 0; i < 17 - component.last_round_call; ++i) {
                        bp.add_copy_constraint(
                            {instance_input.inner_state[i],
                             var(component.W(config[i].copy_to[0].column),
                                 static_cast<int>(config[i].copy_to[0].row + start_row_index), false)});
                        bp.add_copy_constraint(
                            {instance_input.padded_message_chunk[i],
                             var(component.W(config[i].copy_to[1].column),
                                 static_cast<int>(config[i].copy_to[1].row + start_row_index), false)});
                    }
                    config_index += 16;
                    if (component.last_round_call) {
                        bp.add_copy_constraint(
                            {instance_input.inner_state[config_index],
                             var(component.W(config[config_index].copy_to[0].column),
                                 static_cast<int>(config[config_index].copy_to[0].row + start_row_index), false)});
                        bp.add_copy_constraint(
                            {instance_input.padded_message_chunk[config_index],
                             var(component.W(config[config_index].copy_to[1].column),
                                 static_cast<int>(config[config_index].copy_to[1].row + start_row_index), false)});
                        bp.add_copy_constraint(
                            {var(component.C(0), component.last_round_call_row + start_row_index, false,
                                 var::column_type::constant),
                             var(component.W(config[config_index].copy_to[2].column),
                                 static_cast<int>(config[config_index].copy_to[2].row + start_row_index), false)});
                    }
                    config_index += 1;

                    // theta
                    for (int i = 0; i < 17; ++i) {
                        bp.add_copy_constraint(
                            {{component.W(config[prev_index + i].copy_from.column),
                              static_cast<int>(config[prev_index + i].copy_from.row + start_row_index), false},
                             {component.W(config[config_index + i % 5].copy_to[i / 5].column),
                              static_cast<int>(config[config_index + i % 5].copy_to[i / 5].row + start_row_index),
                              false}});
                    }
                    for (int i = 17; i < 25; ++i) {
                        bp.add_copy_constraint(
                            {instance_input.inner_state[i],
                             {component.W(config[config_index + i % 5].copy_to[i / 5].column),
                              static_cast<int>(config[config_index + i % 5].copy_to[i / 5].row + start_row_index),
                              false}});
                    }
                    config_index += 5;
                    prev_index += 17;
                } else {
                    for (int i = 0; i < 25; ++i) {
                        bp.add_copy_constraint(
                            {instance_input.inner_state[i],
                             {component.W(config[config_index + i % 5].copy_to[i / 5].column),
                              static_cast<int>(config[config_index + i % 5].copy_to[i / 5].row + start_row_index),
                              false}});
                    }
                    config_index += 5;
                }
                for (int i = 0; i < 5; ++i) {
                    bp.add_copy_constraint(
                        {{component.W(config[prev_index + i].copy_from.column),
                          static_cast<int>(config[prev_index + i].copy_from.row + start_row_index), false},
                         {component.W(config[config_index + i].copy_to[0].column),
                          static_cast<int>(config[config_index + i].copy_to[0].row + start_row_index), false}});
                    bp.add_copy_constraint(
                        {{component.W(config[config_index + i].constraints[6][0].column),
                          static_cast<int>(config[config_index + i].constraints[6][0].row + start_row_index), false},
                         var(component.C(0),
                             static_cast<int>(config[config_index + i].first_coordinate.row + start_row_index), false,
                             var::column_type::constant)});
                    additional_rot_vars.push_back(
                        var(component.W(config[config_index + i].constraints[0][1].column),
                            static_cast<int>(config[config_index + i].constraints[0][1].row + start_row_index), false));
                    additional_rot_vars.push_back(
                        var(component.W(config[config_index + i].constraints[0][2].column),
                            static_cast<int>(config[config_index + i].constraints[0][2].row + start_row_index), false));
                }
                config_index += 5;
                prev_index += 5;

                for (int i = 0; i < 25; ++i) {
                    std::size_t x = i % 5;
                    bp.add_copy_constraint(
                        {{component.W(config[prev_index - 5 + i % 5].copy_to[i / 5].column),
                          static_cast<int>(config[prev_index - 5 + i % 5].copy_to[i / 5].row + start_row_index), false},
                         {component.W(config[config_index + i].copy_to[0].column),
                          static_cast<int>(config[config_index + i].copy_to[0].row + start_row_index), false}});
                    bp.add_copy_constraint(
                        {{component.W(config[prev_index + (x + 1) % 5].copy_from.column),
                          static_cast<int>(config[prev_index + (x + 1) % 5].copy_from.row + start_row_index), false},
                         {component.W(config[config_index + i].copy_to[1].column),
                          static_cast<int>(config[config_index + i].copy_to[1].row + start_row_index), false}});
                    bp.add_copy_constraint(
                        {{component.W(config[prev_index + (x + 4) % 5].copy_to[0].column),
                          static_cast<int>(config[prev_index + (x + 4) % 5].copy_to[0].row + start_row_index), false},
                         {component.W(config[config_index + i].copy_to[2].column),
                          static_cast<int>(config[config_index + i].copy_to[2].row + start_row_index), false}});
                }
                config_index += 25;
                prev_index += 5;

                // rho/phi
                std::size_t perm_rho[24] = {1, 10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24,
                                            4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6};
                for (int i = 0; i < 24; ++i) {
                    bp.add_copy_constraint(
                        {{component.W(config[prev_index + perm_rho[i]].copy_from.column),
                          static_cast<int>(config[prev_index + perm_rho[i]].copy_from.row + start_row_index), false},
                         {component.W(config[config_index + i].copy_to[0].column),
                          static_cast<int>(config[config_index + i].copy_to[0].row + start_row_index), false}});
                    bp.add_copy_constraint(
                        {{component.W(config[config_index + i].constraints[6][0].column),
                          static_cast<int>(config[config_index + i].constraints[6][0].row + start_row_index), false},
                         var(component.C(0),
                             static_cast<int>(config[config_index + i].first_coordinate.row + start_row_index), false,
                             var::column_type::constant)});
                    additional_rot_vars.push_back(
                        var(component.W(config[config_index + i].constraints[0][1].column),
                            static_cast<int>(config[config_index + i].constraints[0][1].row + start_row_index), false));
                    additional_rot_vars.push_back(
                        var(component.W(config[config_index + i].constraints[0][2].column),
                            static_cast<int>(config[config_index + i].constraints[0][2].row + start_row_index), false));
                }

                // chi
                std::size_t perm_chi[24] = {23, 17, 5,  11, 6, 22, 1,  8,  21, 0,  2,  16,
                                            15, 19, 12, 7,  3, 4,  14, 18, 9,  20, 13, 10};
                std::vector<var> B = {{component.W(config[prev_index].copy_from.column),
                                       static_cast<int>(config[prev_index].copy_from.row + start_row_index), false}};
                for (auto i : perm_chi) {
                    B.push_back({component.W(config[config_index + i].copy_from.column),
                                 static_cast<int>(config[config_index + i].copy_from.row + start_row_index), false});
                }
                config_index += 24;
                prev_index += 25;
                for (int i = 0; i < 25; ++i) {
                    int x = i % 5;
                    int y = i / 5;
                    bp.add_copy_constraint(
                        {B[x + 5 * y],
                         {component.W(config[config_index + i].copy_to[0].column),
                          static_cast<int>(config[config_index + i].copy_to[0].row + start_row_index), false}});
                    bp.add_copy_constraint(
                        {B[(x + 1) % 5 + 5 * y],
                         {component.W(config[config_index + i].copy_to[1].column),
                          static_cast<int>(config[config_index + i].copy_to[1].row + start_row_index), false}});
                    bp.add_copy_constraint(
                        {B[(x + 2) % 5 + 5 * y],
                         {component.W(config[config_index + i].copy_to[2].column),
                          static_cast<int>(config[config_index + i].copy_to[2].row + start_row_index), false}});
                }
                config_index += 25;
                prev_index += 24;

                // iota
                bp.add_copy_constraint(
                    {{component.W(config[prev_index].copy_from.column),
                      static_cast<int>(config[prev_index].copy_from.row + start_row_index), false},
                     {component.W(config[config_index].copy_to[0].column),
                      static_cast<int>(config[config_index].copy_to[0].row + start_row_index), false}});
                bp.add_copy_constraint(
                    {instance_input.round_constant,
                     {component.W(config[config_index].copy_to[1].column),
                      static_cast<int>(config[config_index].copy_to[1].row + start_row_index), false}});
                config_index += 1;

                // additional rot constraints
                for (std::size_t i = 0; i < 29; ++i) {
                    bp.add_copy_constraint(
                        {additional_rot_vars[2 * i],
                         {component.W(config[config_index + i].constraints[0][0].column),
                          static_cast<int>(config[config_index + i].constraints[0][0].row + start_row_index), false}});
                    bp.add_copy_constraint(
                        {additional_rot_vars[2 * i + 1],
                         {component.W(config[config_index + i].constraints[1][0].column),
                          static_cast<int>(config[config_index + i].constraints[1][0].row + start_row_index), false}});
                }
            }

            template<typename BlueprintFieldType>
            void generate_assignments_constant(
                const keccak_round_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename keccak_round_component<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = keccak_round_component<BlueprintFieldType>;
                using integral_type = typename BlueprintFieldType::integral_type;

                std::size_t row = start_row_index;
                if (component.last_round_call) {
                    assignment.constant(component.C(0), row + component.last_round_call_row) =
                        component.sparse_x80;    // sparse 0x80
                }

                auto gate_map = component.gates_configuration_map;
                std::vector<std::size_t> rotate_rows;
                for (auto g : gate_map) {
                    if (g.first.first == 7) {
                        rotate_rows.insert(rotate_rows.end(), g.second.begin(), g.second.end());
                    }
                }
                std::sort(rotate_rows.begin(), rotate_rows.end());
                for (std::size_t i = 0; i < 5; i++) {
                    assignment.constant(component.C(0), row + rotate_rows[i]) = integral_type(1) << 3;
                    assignment.constant(component.C(0), row + rotate_rows[i] + 1) = component.all_rot_consts[i][0];
                    assignment.constant(component.C(0), row + rotate_rows[i] + 2) = component.all_rot_consts[i][1];
                }
                for (std::size_t i = 5; i < 29; i++) {
                    assignment.constant(component.C(0), row + rotate_rows[i]) =
                        integral_type(1) << (3 * component_type::rho_offsets[i - 4]);
                    assignment.constant(component.C(0), row + rotate_rows[i] + 1) = component.all_rot_consts[i][0];
                    assignment.constant(component.C(0), row + rotate_rows[i] + 2) = component.all_rot_consts[i][1];
                }
            }

            template<typename BlueprintFieldType>
            typename keccak_round_component<BlueprintFieldType>::result_type generate_circuit(
                const keccak_round_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename keccak_round_component<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = keccak_round_component<BlueprintFieldType>;
                generate_assignments_constant(component, bp, assignment, instance_input, start_row_index);
                auto selector_indexes =
                    generate_gates(component, bp, assignment, instance_input, bp.get_reserved_indices());
                std::size_t ind = 0;
                std::size_t index = 0;

                for (auto g : component.gates_configuration_map) {
                    for (std::size_t i = 0; i < component.gates_configuration[ind].size(); ++i) {
                        for (auto j : g.second) {
                            assignment.enable_selector(
                                selector_indexes[index],
                                start_row_index + j + component.gates_configuration[ind][i].first_coordinate.row + 1);
                        }
                        index++;
                    }
                    for (std::size_t i = 0; i < component.lookup_gates_configuration[ind].size(); ++i) {
                        for (auto j : g.second) {
                            assignment.enable_selector(
                                selector_indexes[index],
                                start_row_index + j +
                                    component.lookup_gates_configuration[ind][i].first_coordinate.row + 1);
                        }
                        index++;
                    }
                    ind++;
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            typename keccak_round_component<BlueprintFieldType>::result_type generate_assignments(
                const keccak_round_component<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename keccak_round_component<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = keccak_round_component<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                const std::size_t strow = start_row_index;

                int config_index = 0;

                // inner_state ^ chunk
                std::array<value_type, 25> A_1;
                if (component.xor_with_mes) {
                    std::cout << "Last round call = " << component.last_round_call << std::endl;
                    for (int index = 0; index < 17 - component.last_round_call; ++index) {
                        value_type state = var_value(assignment, instance_input.inner_state[index]);
                        value_type message = var_value(assignment, instance_input.padded_message_chunk[index]);
                        value_type sum = state + message;
                        integral_type integral_sum = integral_type(sum.data);
                        auto chunk_size = component.normalize3_chunk_size;
                        auto num_chunks = component.normalize3_num_chunks;
                        std::vector<integral_type> integral_chunks;
                        std::vector<integral_type> integral_normalized_chunks;
                        integral_type mask = (integral_type(1) << chunk_size) - 1;
                        integral_type power = 1;
                        integral_type integral_normalized_sum = 0;
                        for (std::size_t j = 0; j < num_chunks; ++j) {
                            integral_chunks.push_back(integral_sum & mask);
                            integral_sum >>= chunk_size;
                            integral_normalized_chunks.push_back(component.normalize(integral_chunks.back()));
                            integral_normalized_sum += integral_normalized_chunks.back() * power;
                            power <<= chunk_size;
                        }
                        A_1[index] = value_type(integral_normalized_sum);

                        auto cur_config = component.full_configuration[index];
                        assignment.witness(component.W(cur_config.copy_to[0].column),
                                           cur_config.copy_to[0].row + strow) = state;
                        assignment.witness(component.W(cur_config.copy_to[1].column),
                                           cur_config.copy_to[1].row + strow) = message;
                        assignment.witness(component.W(cur_config.constraints[1][0].column),
                                           cur_config.constraints[1][0].row + strow) = sum;
                        assignment.witness(component.W(cur_config.constraints[2][0].column),
                                           cur_config.constraints[2][0].row + strow) =
                            value_type(integral_normalized_sum);
                        for (std::size_t j = 1; j < num_chunks + 1; ++j) {
                            assignment.witness(component.W(cur_config.constraints[1][j].column),
                                               cur_config.constraints[1][j].row + strow) =
                                value_type(integral_chunks[j - 1]);
                            assignment.witness(component.W(cur_config.constraints[2][j].column),
                                               cur_config.constraints[2][j].row + strow) =
                                value_type(integral_normalized_chunks[j - 1]);
                        }
                    }
                    // last round call
                    if (component.last_round_call) {
                        value_type state = var_value(assignment, instance_input.inner_state[16]);
                        std::cout << "Last round state = " << std::hex << state << " " << component.sparse_x80 << std::dec << std::endl;
                        value_type message = var_value(assignment, instance_input.padded_message_chunk[16]);
                        value_type sum = state + message + value_type(component.sparse_x80);
                        integral_type integral_sum = integral_type(sum.data);
                        auto chunk_size = component.normalize4_chunk_size;
                        auto num_chunks = component.normalize4_num_chunks;
                        std::vector<integral_type> integral_chunks;
                        std::vector<integral_type> integral_normalized_chunks;
                        integral_type mask = (integral_type(1) << chunk_size) - 1;
                        integral_type power = 1;
                        integral_type integral_normalized_sum = 0;
                        for (std::size_t j = 0; j < num_chunks; ++j) {
                            integral_chunks.push_back(integral_sum & mask);
                            integral_sum >>= chunk_size;
                            integral_normalized_chunks.push_back(component.normalize(integral_chunks.back()));
                            integral_normalized_sum += integral_normalized_chunks.back() * power;
                            power <<= chunk_size;
                        }
                        A_1[16] = value_type(integral_normalized_sum);

                        auto cur_config = component.full_configuration[16];
                        assignment.witness(component.W(cur_config.copy_to[0].column),
                                           cur_config.copy_to[0].row + strow) = state;
                        assignment.witness(component.W(cur_config.copy_to[1].column),
                                           cur_config.copy_to[1].row + strow) = message;
                        assignment.witness(component.W(cur_config.copy_to[2].column),
                                           cur_config.copy_to[2].row + strow) = value_type(component.sparse_x80);
                        assignment.witness(component.W(cur_config.constraints[1][0].column),
                                           cur_config.constraints[1][0].row + strow) = sum;
                        assignment.witness(component.W(cur_config.constraints[2][0].column),
                                           cur_config.constraints[2][0].row + strow) =
                            value_type(integral_normalized_sum);
                        for (std::size_t j = 1; j < num_chunks + 1; ++j) {
                            assignment.witness(component.W(cur_config.constraints[1][j].column),
                                               cur_config.constraints[1][j].row + strow) =
                                value_type(integral_chunks[j - 1]);
                            assignment.witness(component.W(cur_config.constraints[2][j].column),
                                               cur_config.constraints[2][j].row + strow) =
                                value_type(integral_normalized_chunks[j - 1]);
                        }
                    }
                    for (int i = 17; i < 25; ++i) {
                        A_1[i] = var_value(assignment, instance_input.inner_state[i]);
                        std::cout << "Round state " << i << " = "<< A_1[i] << std::endl;
                    }
                    config_index += 17;
                } else {
                    for (int i = 0; i < 25; ++i) {
                        A_1[i] = var_value(assignment, instance_input.inner_state[i]);
                    }
                }
                // std::cout << "A_1:\n";
                // for (int i = 0; i < 25; ++i) {
                //     std::cout << A_1[i].data << " ";
                // }
                // std::cout << "\n";

                // theta
                std::array<value_type, 5> C;
                for (int index = 0; index < 5; ++index) {
                    value_type sum = 0;
                    for (int j = 0; j < 5; ++j) {
                        sum += A_1[index + 5 * j];
                    }
                    integral_type integral_sum = integral_type(sum.data);
                    auto chunk_size = component.normalize6_chunk_size;
                    auto num_chunks = component.normalize6_num_chunks;
                    std::vector<integral_type> integral_chunks;
                    std::vector<integral_type> integral_normalized_chunks;
                    integral_type mask = (integral_type(1) << chunk_size) - 1;
                    integral_type power = 1;
                    integral_type integral_normalized_sum = 0;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_chunks.push_back(integral_sum & mask);
                        integral_sum >>= chunk_size;
                        integral_normalized_chunks.push_back(component.normalize(integral_chunks.back()));
                        integral_normalized_sum += integral_normalized_chunks.back() * power;
                        power <<= chunk_size;
                    }
                    C[index] = value_type(integral_normalized_sum);

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_to[0].column), cur_config.copy_to[0].row + strow) =
                        A_1[index];
                    assignment.witness(component.W(cur_config.copy_to[1].column), cur_config.copy_to[1].row + strow) =
                        A_1[index + 5];
                    assignment.witness(component.W(cur_config.copy_to[2].column), cur_config.copy_to[2].row + strow) =
                        A_1[index + 10];
                    assignment.witness(component.W(cur_config.copy_to[3].column), cur_config.copy_to[3].row + strow) =
                        A_1[index + 15];
                    assignment.witness(component.W(cur_config.copy_to[4].column), cur_config.copy_to[4].row + strow) =
                        A_1[index + 20];
                    assignment.witness(component.W(cur_config.constraints[1][0].column),
                                       cur_config.constraints[1][0].row + strow) = sum;
                    assignment.witness(component.W(cur_config.constraints[2][0].column),
                                       cur_config.constraints[2][0].row + strow) = value_type(integral_normalized_sum);
                    for (std::size_t j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[1][j].column),
                                           cur_config.constraints[1][j].row + strow) =
                            value_type(integral_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[2][j].column),
                                           cur_config.constraints[2][j].row + strow) =
                            value_type(integral_normalized_chunks[j - 1]);
                    }
                }
                config_index += 5;
                // std::cout << "C:\n";
                // for (int i = 0; i < 5; ++i) {
                //     std::cout << C[i].data << " ";
                // }
                // std::cout << "\n";

                std::vector<integral_type> additional_rot_chunks;

                // ROT
                std::array<value_type, 5> C_rot;
                integral_type for_bound_smaller = component.calculate_sparse((integral_type(1) << 64) - 1) -
                                                  component.calculate_sparse((integral_type(1) << 1) - 1);
                integral_type for_bound_bigger = component.calculate_sparse((integral_type(1) << 64) - 1) -
                                                 component.calculate_sparse((integral_type(1) << 63) - 1);
                // std::cout << "for_bound_smaller: " << for_bound_smaller << ", for_bound_bigger: " << for_bound_bigger
                // << '\n'; std::cout << component.calculate_sparse((integral_type(1) << 64) - 1) << "\n" <<
                // component.calculate_sparse((integral_type(1) << 63) - 1) << "\n" <<
                // component.calculate_sparse((integral_type(1) << 1) - 1) << "\n";
                for (int index = 0; index < 5; ++index) {
                    integral_type integral_C = integral_type(C[index].data);
                    integral_type smaller_part = integral_C >> 189;
                    integral_type bigger_part = integral_C & ((integral_type(1) << 189) - 1);
                    integral_type integral_C_rot = (bigger_part << 3) + smaller_part;
                    C_rot[index] = value_type(integral_C_rot);
                    additional_rot_chunks.push_back(smaller_part);
                    additional_rot_chunks.push_back(bigger_part);
                    // integral_type bound_smaller = smaller_part - (integral_type(1) << 3) + (integral_type(1) << 192);
                    // integral_type bound_bigger = bigger_part - (integral_type(1) << 189) + (integral_type(1) << 192);
                    integral_type bound_smaller = smaller_part + for_bound_smaller;
                    integral_type bound_bigger = bigger_part + for_bound_bigger;
                    auto copy_bound_smaller = bound_smaller;
                    auto copy_bound_bigger = bound_bigger;
                    auto chunk_size = component.rotate_chunk_size;
                    auto num_chunks = component.rotate_num_chunks;
                    std::vector<integral_type> integral_small_chunks;
                    std::vector<integral_type> integral_big_chunks;
                    integral_type mask = (integral_type(1) << chunk_size) - 1;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_small_chunks.push_back(bound_smaller & mask);
                        bound_smaller >>= chunk_size;
                        integral_big_chunks.push_back(bound_bigger & mask);
                        bound_bigger >>= chunk_size;
                    }
                    // auto check = integral_big_chunks[0];
                    // auto power = integral_type(1);
                    // for (std::size_t j = 1; j < num_chunks; ++j) {
                    //     power <<= chunk_size;
                    //     check += integral_big_chunks[j] * power;
                    // }
                    // std::cout << "check: " << check << ' ' << copy_bound_bigger << '\n';

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_to[0].column), cur_config.copy_to[0].row + strow) =
                        C[index];
                    assignment.witness(component.W(cur_config.copy_from.column), cur_config.copy_from.row + strow) =
                        C_rot[index];
                    assignment.witness(component.W(cur_config.constraints[0][1].column),
                                       cur_config.constraints[0][1].row + strow) = value_type(smaller_part);
                    assignment.witness(component.W(cur_config.constraints[0][2].column),
                                       cur_config.constraints[0][2].row + strow) = value_type(bigger_part);
                    assignment.witness(component.W(cur_config.constraints[3][0].column),
                                       cur_config.constraints[3][0].row + strow) = value_type(copy_bound_smaller);
                    assignment.witness(component.W(cur_config.constraints[5][0].column),
                                       cur_config.constraints[5][0].row + strow) = value_type(copy_bound_bigger);
                    for (std::size_t j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[3][j].column),
                                           cur_config.constraints[3][j].row + strow) =
                            value_type(integral_small_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[5][j].column),
                                           cur_config.constraints[5][j].row + strow) =
                            value_type(integral_big_chunks[j - 1]);
                    }
                    assignment.witness(component.W(cur_config.constraints[6][0].column),
                                       cur_config.constraints[6][0].row + strow) = value_type(integral_type(1) << 3);
                    assignment.witness(component.W(cur_config.constraints[6][1].column),
                                       cur_config.constraints[6][1].row + strow) = value_type(integral_type(1) << 189);
                }
                config_index += 5;
                // std::cout << "C_rot:\n";
                // for (int i = 0; i < 5; ++i) {
                //     std::cout << C_rot[i].data << " ";
                // }
                // std::cout << "\n";

                std::array<value_type, 25> A_2;
                for (int index = 0; index < 25; ++index) {
                    int x = index % 5;
                    value_type sum = A_1[index] + C_rot[(x + 1) % 5] + C[(x + 4) % 5];
                    integral_type integral_sum = integral_type(sum.data);
                    auto chunk_size = component.normalize4_chunk_size;
                    auto num_chunks = component.normalize4_num_chunks;
                    std::vector<integral_type> integral_chunks;
                    std::vector<integral_type> integral_normalized_chunks;
                    integral_type mask = (integral_type(1) << chunk_size) - 1;
                    integral_type power = 1;
                    integral_type integral_normalized_sum = 0;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_chunks.push_back(integral_sum & mask);
                        integral_sum >>= chunk_size;
                        integral_normalized_chunks.push_back(component.normalize(integral_chunks.back()));
                        integral_normalized_sum += integral_normalized_chunks.back() * power;
                        power <<= chunk_size;
                    }
                    A_2[index] = value_type(integral_normalized_sum);

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_to[0].column), cur_config.copy_to[0].row + strow) =
                        A_1[index];
                    assignment.witness(component.W(cur_config.copy_to[1].column), cur_config.copy_to[1].row + strow) =
                        C_rot[(x + 1) % 5];
                    assignment.witness(component.W(cur_config.copy_to[2].column), cur_config.copy_to[2].row + strow) =
                        C[(x + 4) % 5];
                    assignment.witness(component.W(cur_config.constraints[1][0].column),
                                       cur_config.constraints[1][0].row + strow) = sum;
                    assignment.witness(component.W(cur_config.constraints[2][0].column),
                                       cur_config.constraints[2][0].row + strow) = A_2[index];
                    for (std::size_t j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[1][j].column),
                                           cur_config.constraints[1][j].row + strow) =
                            value_type(integral_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[2][j].column),
                                           cur_config.constraints[2][j].row + strow) =
                            value_type(integral_normalized_chunks[j - 1]);
                    }
                }
                config_index += 25;
                // std::cout << "A_2:\n";
                // for (int i = 0; i < 25; ++i) {
                //     std::cout << A_2[i].data << " ";
                // }
                // std::cout << "\n";

                // rho/phi
                value_type B[25];
                std::size_t perm[25] = {1,  10, 7,  11, 17, 18, 3,  5,  16, 8, 21, 24, 4,
                                        15, 23, 19, 13, 12, 2,  20, 14, 22, 9, 6,  1};
                B[0] = A_2[0];
                for (int index = 1; index < 25; ++index) {
                    int r = 3 * component.rho_offsets[index];
                    int minus_r = 192 - r;
                    integral_type integral_A = integral_type(A_2[perm[index - 1]].data);
                    integral_type smaller_part = integral_A >> minus_r;
                    integral_type bigger_part = integral_A & ((integral_type(1) << minus_r) - 1);
                    integral_type integral_A_rot = (bigger_part << r) + smaller_part;
                    B[perm[index]] = value_type(integral_A_rot);
                    additional_rot_chunks.push_back(smaller_part);
                    additional_rot_chunks.push_back(bigger_part);
                    // integral_type bound_smaller = smaller_part - (integral_type(1) << r) + (integral_type(1) << 192);
                    // integral_type bound_bigger = bigger_part - (integral_type(1) << minus_r) + (integral_type(1) <<
                    // 192);
                    integral_type bound_smaller =
                        smaller_part + component.calculate_sparse((integral_type(1) << 64) - 1) -
                        component.calculate_sparse((integral_type(1) << component.rho_offsets[index]) - 1);
                    integral_type bound_bigger =
                        bigger_part + component.calculate_sparse((integral_type(1) << 64) - 1) -
                        component.calculate_sparse((integral_type(1) << (64 - component.rho_offsets[index])) - 1);
                    auto copy_bound_smaller = bound_smaller;
                    auto copy_bound_bigger = bound_bigger;
                    auto chunk_size = component.rotate_chunk_size;
                    auto num_chunks = component.rotate_num_chunks;
                    std::vector<integral_type> integral_small_chunks;
                    std::vector<integral_type> integral_big_chunks;
                    integral_type mask = (integral_type(1) << chunk_size) - 1;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_small_chunks.push_back(bound_smaller & mask);
                        bound_smaller >>= chunk_size;
                        integral_big_chunks.push_back(bound_bigger & mask);
                        bound_bigger >>= chunk_size;
                    }

                    auto cur_config = component.full_configuration[index - 1 + config_index];
                    assignment.witness(component.W(cur_config.copy_to[0].column), cur_config.copy_to[0].row + strow) =
                        A_2[perm[index - 1]];
                    assignment.witness(component.W(cur_config.copy_from.column), cur_config.copy_from.row + strow) =
                        value_type(integral_A_rot);
                    assignment.witness(component.W(cur_config.constraints[0][1].column),
                                       cur_config.constraints[0][1].row + strow) = value_type(smaller_part);
                    assignment.witness(component.W(cur_config.constraints[0][2].column),
                                       cur_config.constraints[0][2].row + strow) = value_type(bigger_part);
                    assignment.witness(component.W(cur_config.constraints[3][0].column),
                                       cur_config.constraints[3][0].row + strow) = value_type(copy_bound_smaller);
                    assignment.witness(component.W(cur_config.constraints[5][0].column),
                                       cur_config.constraints[5][0].row + strow) = value_type(copy_bound_bigger);
                    for (std::size_t j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[3][j].column),
                                           cur_config.constraints[3][j].row + strow) =
                            value_type(integral_small_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[5][j].column),
                                           cur_config.constraints[5][j].row + strow) =
                            value_type(integral_big_chunks[j - 1]);
                    }
                    assignment.witness(component.W(cur_config.constraints[6][0].column),
                                       cur_config.constraints[6][0].row + strow) = value_type(integral_type(1) << r);
                    assignment.witness(component.W(cur_config.constraints[6][1].column),
                                       cur_config.constraints[6][1].row + strow) =
                        value_type(integral_type(1) << minus_r);
                }
                config_index += 24;

                // chi
                std::array<value_type, 25> A_3;
                for (int index = 0; index < 25; ++index) {
                    int x = index % 5;
                    int y = index / 5;
                    value_type sum =
                        component.sparse_3 - 2 * B[x + 5 * y] + B[(x + 1) % 5 + 5 * y] - B[(x + 2) % 5 + 5 * y];
                    integral_type integral_sum = integral_type(sum.data);
                    auto chunk_size = component.chi_chunk_size;
                    auto num_chunks = component.chi_num_chunks;
                    std::vector<integral_type> integral_chunks;
                    std::vector<integral_type> integral_chi_chunks;
                    integral_type mask = (integral_type(1) << chunk_size) - 1;
                    integral_type power = 1;
                    integral_type integral_chi_sum = 0;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_chunks.push_back(integral_sum & mask);
                        integral_sum >>= chunk_size;
                        integral_chi_chunks.push_back(component.chi(integral_chunks.back()));
                        integral_chi_sum += integral_chi_chunks.back() * power;
                        power <<= chunk_size;
                    }
                    A_3[index] = value_type(integral_chi_sum);

                    auto cur_config = component.full_configuration[index + config_index];
                    assignment.witness(component.W(cur_config.copy_to[0].column), cur_config.copy_to[0].row + strow) =
                        B[x + 5 * y];
                    assignment.witness(component.W(cur_config.copy_to[1].column), cur_config.copy_to[1].row + strow) =
                        B[(x + 1) % 5 + 5 * y];
                    assignment.witness(component.W(cur_config.copy_to[2].column), cur_config.copy_to[2].row + strow) =
                        B[(x + 2) % 5 + 5 * y];
                    assignment.witness(component.W(cur_config.constraints[1][0].column),
                                       cur_config.constraints[1][0].row + strow) = sum;
                    assignment.witness(component.W(cur_config.constraints[2][0].column),
                                       cur_config.constraints[2][0].row + strow) = value_type(integral_chi_sum);
                    for (std::size_t j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[1][j].column),
                                           cur_config.constraints[1][j].row + strow) =
                            value_type(integral_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[2][j].column),
                                           cur_config.constraints[2][j].row + strow) =
                            value_type(integral_chi_chunks[j - 1]);
                    }
                }
                config_index += 25;

                // iota
                value_type A_4;
                {
                    value_type round_constant = var_value(assignment, instance_input.round_constant);
                    value_type sum = A_3[0] + round_constant;
                    integral_type integral_sum = integral_type(sum.data);
                    auto chunk_size = component.normalize3_chunk_size;
                    auto num_chunks = component.normalize3_num_chunks;
                    std::vector<integral_type> integral_chunks;
                    std::vector<integral_type> integral_normalized_chunks;
                    integral_type mask = (integral_type(1) << chunk_size) - 1;
                    integral_type power = 1;
                    integral_type integral_normalized_sum = 0;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_chunks.push_back(integral_sum & mask);
                        integral_sum >>= chunk_size;
                        integral_normalized_chunks.push_back(component.normalize(integral_chunks.back()));
                        integral_normalized_sum += integral_normalized_chunks.back() * power;
                        power <<= chunk_size;
                    }
                    A_4 = value_type(integral_normalized_sum);

                    auto cur_config = component.full_configuration[config_index++];
                    assignment.witness(component.W(cur_config.copy_to[0].column), cur_config.copy_to[0].row + strow) =
                        A_3[0];
                    assignment.witness(component.W(cur_config.copy_to[1].column), cur_config.copy_to[1].row + strow) =
                        round_constant;
                    assignment.witness(component.W(cur_config.constraints[1][0].column),
                                       cur_config.constraints[1][0].row + strow) = sum;
                    assignment.witness(component.W(cur_config.constraints[2][0].column),
                                       cur_config.constraints[2][0].row + strow) = value_type(integral_normalized_sum);
                    for (std::size_t j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[1][j].column),
                                           cur_config.constraints[1][j].row + strow) =
                            value_type(integral_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[2][j].column),
                                           cur_config.constraints[2][j].row + strow) =
                            value_type(integral_normalized_chunks[j - 1]);
                    }

                }
                // std::cout << "result:\n" << A_4.data << " ";
                // for (int i = 1; i < 25; ++i) {
                //     std::cout << A_3[i].data << " ";
                // }
                // std::cout << "\n";

                for (std::size_t i = 0; i < 29; ++i) {
                    auto chunk_size = component.rotate_chunk_size;
                    auto num_chunks = component.rotate_num_chunks;
                    auto copy_bound_smaller = additional_rot_chunks[2 * i];
                    auto copy_bound_bigger = additional_rot_chunks[2 * i + 1];
                    std::vector<integral_type> integral_small_chunks;
                    std::vector<integral_type> integral_big_chunks;
                    integral_type mask = (integral_type(1) << chunk_size) - 1;
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        integral_small_chunks.push_back(copy_bound_smaller & mask);
                        copy_bound_smaller >>= chunk_size;
                        integral_big_chunks.push_back(copy_bound_bigger & mask);
                        copy_bound_bigger >>= chunk_size;
                    }

                    auto cur_config = component.full_configuration[config_index++];
                    assignment.witness(component.W(cur_config.constraints[0][0].column),
                                       cur_config.constraints[0][0].row + strow) = value_type(additional_rot_chunks[2 * i]);
                    assignment.witness(component.W(cur_config.constraints[1][0].column),
                                       cur_config.constraints[1][0].row + strow) = value_type(additional_rot_chunks[2 * i + 1]);
                    for (std::size_t j = 1; j < num_chunks + 1; ++j) {
                        assignment.witness(component.W(cur_config.constraints[0][j].column),
                                           cur_config.constraints[0][j].row + strow) =
                            value_type(integral_small_chunks[j - 1]);
                        assignment.witness(component.W(cur_config.constraints[1][j].column),
                                           cur_config.constraints[1][j].row + strow) =
                            value_type(integral_big_chunks[j - 1]);
                    }
                    // std::cout << "last conf: " << cur_config.constraints[0][num_chunks].column << ' ' << cur_config.constraints[0][num_chunks].row << '\n';
                }

                return typename component_type::result_type(component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_ROUND_HPP
