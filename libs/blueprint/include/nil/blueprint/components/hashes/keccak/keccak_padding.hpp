//---------------------------------------------------------------------------//
// Copyright (c) 2023 Polina Chernyshova <pockvokhbtra@nil.foundation>
//               2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_PADDING_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_PADDING_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/lookup_library.hpp>
#include <nil/blueprint/configuration.hpp>

#include <iostream>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename ArithmetizationType>
            class keccak_padding;

            template<typename BlueprintFieldType>
            class keccak_padding<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {

                using component_type = plonk_component<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;

            public:
                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::size_t witness_amount;
                    std::size_t num_blocks;
                    std::size_t num_bits;
                    bool range_check_input;
                    std::size_t limit_permutation_column;
                    static constexpr const std::size_t clamp = 15;

                    gate_manifest_type(std::size_t witness_amount_, std::size_t num_blocks_, std::size_t num_bits_,
                                       bool range_check_input_, std::size_t limit_permutation_column_ = 7) :
                        witness_amount(std::min(witness_amount_, clamp)),
                        num_blocks(num_blocks_), num_bits(num_bits_), range_check_input(range_check_input_),
                        limit_permutation_column(limit_permutation_column_) {};

                    std::uint32_t gates_amount() const override {
                        return keccak_padding::get_gates_amount(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t num_blocks,
                                                       std::size_t num_bits,
                                                       bool range_check_input,
                                                       std::size_t limit_permutation_column = 7) {
                    gate_manifest manifest =
                        gate_manifest(gate_manifest_type(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column));
                    return manifest;
                }

                static manifest_type get_manifest(
                    std::size_t num_blocks,
                    std::size_t num_bits,
                    bool range_check_input,
                    std::size_t limit_permutation_column = 7
                ) {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<nil::blueprint::manifest_param>(
                                          new nil::blueprint::manifest_single_value_param(9)),
                                      true);
                    return manifest;
                }

                static const std::size_t lookup_rows = 65536;
                static const std::size_t num_chunks = 8;

                const std::size_t num_blocks;
                const std::size_t num_bits;
                const bool range_check_input;
                const std::size_t limit_permutation_column = 7;

                const std::size_t shift = calculate_shift(num_blocks, num_bits);
                const std::size_t num_padding_zeros = calculate_num_padding_zeros(num_blocks, shift);

                const integral_type padding_delimiter = integral_type(1) << 56;

                const std::size_t num_cells = calculate_num_cells(num_blocks, num_bits, range_check_input);
                const std::size_t buff = calculate_buff(this->witness_amount(), range_check_input);

                const std::vector<configuration> full_configuration =
                    configure_all(this->witness_amount(), num_blocks, num_bits, range_check_input, limit_permutation_column);
                const std::map<std::size_t, std::vector<std::size_t>> gates_configuration_map =
                    configure_map(this->witness_amount(), num_blocks, num_bits, range_check_input, limit_permutation_column);
                const std::vector<std::vector<configuration>> gates_configuration =
                    configure_gates(this->witness_amount(), num_blocks, num_bits, range_check_input, limit_permutation_column);

                const std::vector<std::vector<configuration>> output_gates_configuration =
                    configure_output_gates(this->witness_amount(), num_blocks, num_bits, range_check_input, limit_permutation_column);
                const std::vector<std::vector<configuration>> inner_range_check_gates_configuration =
                    configure_inner_range_check_gates(this->witness_amount(), num_blocks, num_bits, range_check_input, limit_permutation_column);

                std::vector<std::size_t> gates_rows = calculate_gates_rows(this->witness_amount());

                const std::size_t rows_amount =
                    get_rows_amount(this->witness_amount(), num_blocks, num_bits, range_check_input, limit_permutation_column);
                const std::size_t gates_amount = get_gates_amount(this->witness_amount(), num_blocks, num_bits, range_check_input);

                struct input_type {
                    // initial message = message[0] * 2^(64 * (num_blocks - 1)) + ... + message[num_blocks - 2] * 2^64 +
                    // message[num_blocks - 1] all message[i] are 64-bit for i > 0 message[0] is <= 64-bit
                    std::vector<var> message;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res;
                        res.reserve(message.size());
                        res.insert(res.end(), message.begin(), message.end());
                        return res;
                    }
                };

                struct result_type {
                    std::vector<var> padded_message;

                    result_type(const keccak_padding &component, std::size_t start_row_index) {
                        auto size = component.full_configuration.size() - 1 - component.num_blocks * (component.shift != 0);
                        padded_message.resize(size + component.num_padding_zeros);
                        std::cout << "Padding component result size = " << padded_message.size() <<  " : ";
                        for (std::size_t i = 0; i < padded_message.size() - 17; ++i) {
                            auto config = component.full_configuration[i];
                            padded_message[i] = var(component.W(config.copy_to.back().column),
                                                    config.copy_to.back().row + start_row_index, false);
                            std::cout << padded_message[i] << " ";
                        }
                        auto output_config = component.full_configuration[component.num_blocks];
                        for (std::size_t i = 0; i < 17; ++i) {
                            padded_message[padded_message.size() - 17 + i] = var(component.W(output_config.copy_to[i].column),
                                                                            output_config.copy_to[i].row + start_row_index, false);
                            std::cout << padded_message[padded_message.size() - 17 + i] << " ";
                        }
                        std::cout << std::endl;
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res;
                        res.reserve(padded_message.size());
                        res.insert(res.end(), padded_message.begin(), padded_message.end());
                        return res;
                    }
                };

                static std::size_t calculate_shift(std::size_t num_blocks, std::size_t num_bits) {
                    // assert(num_blocks * 64 >= num_bits);
                    return num_blocks * 64 - num_bits;
                }
                static std::size_t calculate_num_padding_zeros(std::size_t num_blocks, std::size_t shift) {
                    if (num_blocks % 17 == 0){
                        if(shift == 0 ){
                            return 17;
                        }
                        return 0;
                    }
                    return 17 - num_blocks % 17;
                }
                static std::size_t calculate_num_cells(std::size_t num_blocks, std::size_t num_bits, bool range_check_input) {
                    if (calculate_shift(num_blocks, num_bits) == 0 && range_check_input) {
                        return 1 + 8;       // chunk, chunk range_check
                    }
                    std::size_t res = 1     // relay
                                    + 1     // chunk = first * 2^k + second
                                    + 2     // first, second
                                    + 1     // sum = relay * 2^(64-k) + first
                                    + 8;    // sum range_check
                    if (range_check_input) {
                        res += 8;           // chunk range_check
                    }
                    return res;
                }
                static std::size_t calculate_buff(std::size_t witness_amount, bool range_check_input) {
                    if (!range_check_input) {
                        return 2;
                    }
                    if (witness_amount == 15) {
                        return 4;
                    }
                    return 0;
                }

                static configuration configure_inner_no_padding(std::size_t witness_amount, std::size_t num_blocks, std::size_t num_bits,
                                                    bool range_check_input, std::size_t limit_permutation_column, std::size_t row, std::size_t column,
                                                    std::size_t num_cells, std::size_t buff) {

                    if (column > 0) {
                        row += 1;
                        column = 0;
                    }

                    std::pair<std::size_t, std::size_t> first_coordinate = {row, column};

                    std::size_t last_row = row,
                                last_column = column;

                    // chunk
                    std::vector<std::pair<std::size_t, std::size_t>> copy_to;
                    if (column > limit_permutation_column) {
                        copy_to.push_back({last_row + 1, 0});
                    } else {
                        copy_to.push_back({last_row + (last_column / witness_amount),
                                                        (last_column++) % witness_amount});
                    }
                    if (!range_check_input) {
                        return configuration(first_coordinate, {last_row, last_column}, copy_to, {}, {}, copy_to[0]);
                    }

                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints;
                    // chunk range_check
                    constraints.push_back({copy_to[0]});
                    for (int i = 0; i < 8; ++i) {
                        constraints[0].push_back({last_row + (last_column / witness_amount),
                                                    (last_column++) % witness_amount});
                    }

                    last_row += last_column / witness_amount;
                    last_column %= witness_amount;

                    auto cur_config = configuration(first_coordinate, {last_row, last_column}, copy_to, constraints, {}, copy_to[0]);

                    return configuration(first_coordinate, {last_row, last_column}, copy_to, constraints, {}, copy_to[0]);
                }
                static configuration configure_inner_with_padding(std::size_t witness_amount, std::size_t num_blocks, std::size_t num_bits,
                                                    bool range_check_input, std::size_t row, std::size_t column,
                                                    std::size_t num_cells, std::size_t buff) {

                    std::pair<std::size_t, std::size_t> first_coordinate = {row, column};

                    std::size_t last_row = row,
                                last_column = column;

                    // relay, chunk, sum; second
                    std::vector<std::pair<std::size_t, std::size_t>> copy_to;
                    std::pair<std::size_t, std::size_t> cell_copy_from;
                    if (column > 3) {
                        for (int i = 0; i < 3; ++i) {
                            copy_to.push_back({last_row + 1, i});
                        }
                        cell_copy_from = {last_row + 1, 3};
                    } else {
                        for (int i = 0; i < 3; ++i) {
                            copy_to.push_back({last_row + (last_column / witness_amount),
                                                            (last_column++) % witness_amount});
                        }
                        cell_copy_from = {last_row + (last_column / witness_amount),
                                            (last_column++) % witness_amount};
                    }


                    std::vector<std::pair<std::size_t, std::size_t>> cells;
                    if (column > 3) {
                        for (int i = column; i < witness_amount; ++i) {
                            cells.push_back({row, i});
                        }
                        std::size_t cells_left = num_cells - witness_amount + column;
                        std::size_t cur_row = row + 1,
                                    cur_column = 4;
                        while (cur_column < cells_left) {
                            cells.push_back({cur_row + (cur_column / witness_amount), (cur_column++) % witness_amount});
                        }
                    } else {
                        std::size_t cur_row = row,
                                    cur_column = column + 4;
                        while (cur_column - column < num_cells) {
                            cells.push_back({cur_row + (cur_column / witness_amount), (cur_column++) % witness_amount});
                        }
                    }
                    std::size_t cell_index = 0;

                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints;
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups(1 + range_check_input);
                    // chunk, first, second
                    constraints.push_back({copy_to[1]});
                    constraints[0].push_back(cells[cell_index++]);
                    constraints[0].push_back(cell_copy_from);
                    // sum, relay, first
                    constraints.push_back({copy_to[2]});
                    constraints[1].push_back(copy_to[0]);
                    constraints[1].push_back(constraints[0][1]);
                    // sum range_check
                    constraints.push_back({constraints[1][0]});
                    for (int i = 0; i < 8; ++i) {
                        constraints[2].push_back(cells[cell_index++]);
                        lookups[0].push_back(constraints.back().back());
                    }
                    // chunk range_check
                    if (range_check_input) {
                        constraints.push_back({constraints[0][0]});
                        for (int i = 0; i < 8; ++i) {
                            constraints[3].push_back(cells[cell_index++]);
                            lookups[1].push_back(constraints.back().back());
                        }
                    }

                    if (cell_copy_from.first > cells.back().first) {
                        cells.back() = cell_copy_from;
                    }

                    last_column = cells.back().second + 1 + buff;
                    last_row = cells.back().first + (last_column >= witness_amount);
                    last_column %= witness_amount;

                    auto cur_config = configuration(first_coordinate, {last_row, last_column}, copy_to, constraints, lookups, cell_copy_from);

                    return configuration(first_coordinate, {last_row, last_column}, copy_to, constraints, lookups, cell_copy_from);
                }
                static configuration configure_inner(std::size_t witness_amount, std::size_t num_blocks, std::size_t num_bits,
                                                    bool range_check_input, std::size_t limit_permutation_column,
                                                    std::size_t row, std::size_t column,
                                                    std::size_t num_cells, std::size_t buff) {
                    if (calculate_shift(num_blocks, num_bits) == 0) {
                        return configure_inner_no_padding(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column, row, column, num_cells, buff);
                    }
                    return configure_inner_with_padding(witness_amount, num_blocks, num_bits, range_check_input, row, column, num_cells, buff);
                }

                static configuration configure_output(std::size_t witness_amount, std::size_t num_blocks, std::size_t num_bits,
                                                    bool range_check_input, std::size_t limit_permutation_column,
                                                    std::size_t row, std::size_t column) {

                    if (column > 0) {
                        row += 1;
                        column = 0;
                    }
                    std::pair<std::size_t, std::size_t> first_coordinate = {row, column};

                    std::size_t last_row = row,
                                last_column = column;
                    std::size_t shift = calculate_shift(num_blocks, num_bits);

                    // relay, chunk, sum; second
                    std::vector<std::pair<std::size_t, std::size_t>> copy_to;
                    std::pair<std::size_t, std::size_t> cell_copy_from;

                    std::vector<std::pair<std::size_t, std::size_t>> selectors;
                    std::pair<std::size_t, std::size_t> almost_sum; //((34-sum)*sum-1)
                    std::pair<std::size_t, std::size_t> delta;
                    std::vector<std::pair<std::size_t, std::size_t>> values;

                    for (std::size_t i = 0; i < 17; i++) {
                        values.push_back({last_row + (last_column / witness_amount),
                                                        (last_column++) % witness_amount});
                        copy_to.push_back(values.back());

                    }
                    delta = {last_row + (last_column / witness_amount), (last_column++) % witness_amount};
                    for (std::size_t i = 0; i < 17; i++) {
                        selectors.push_back({last_row + (last_column / witness_amount),
                                                        (last_column++) % witness_amount});

                    }
                    almost_sum = {last_row + (last_column / witness_amount), (last_column++) % witness_amount};

                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints;
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups(1);

                    //s_i(s_i - 2)(w_i*delta - 1)=0  &&  (s_i - 1)(s_i - 2)w_i=0
                    for (std::size_t i = 0; i < 17; i++) {
                        constraints.push_back({selectors[i], values[i], delta});
                    }

                    lookups[0].push_back(almost_sum);

                    last_row = almost_sum.first;
                    last_column = almost_sum.second;
                    if (last_column != 0) {
                        last_row += 1;
                        last_column = 0;
                    }

                    return configuration(first_coordinate, {last_row, last_column}, copy_to, constraints, lookups, cell_copy_from);
                }

                static configuration configure_inner_range_checks(std::size_t witness_amount, std::size_t limit_permutation_column,
                                                   std::size_t row, std::size_t column) {
                    // regular constraints:
                    // copy_first * 2^k - first = 0
                    // first = first_chunk0 + first_chunk1 * 2^chunk_size + ... + first_chunkk * 2^(k*chunk_size)
                    // copy_second * 2^(64-k) - second = 0
                    // second = second_chunk0 + second_chunk1 * 2^chunk_size + ... + second_chunkk * 2^(k*chunk_size)

                    std::pair<std::size_t, std::size_t> first_coordinate = {row, column};

                    std::size_t last_row = row, last_column = column;
                    std::size_t num_chunks = 8;
                    std::size_t num_cells = 2 * (2 + 8);
                    std::size_t buff = (10 * witness_amount - num_cells) % witness_amount;

                    std::vector<std::pair<std::size_t, std::size_t>> copy_to;
                    std::pair<std::size_t, std::size_t> cell_copy_from;
                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> constraints;

                    std::vector<std::pair<std::size_t, std::size_t>> cells;
                    std::size_t cur_row = row, cur_column = 0;
                    while (cur_column < num_cells) {
                        cells.push_back({cur_row + (cur_column / witness_amount), (cur_column++) % witness_amount});
                    }
                    std::size_t cell_index = 0;

                    std::vector<std::vector<std::pair<std::size_t, std::size_t>>> lookups(1);

                    constraints.push_back({cells[cell_index++]});
                    constraints[0].push_back(cells[cell_index++]);

                    constraints.push_back({constraints[0].back()});
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        constraints[1].push_back(cells[cell_index++]);
                        lookups[0].push_back(constraints[1].back());
                    }

                    constraints.push_back({cells[cell_index++]});
                    constraints[2].push_back(cells[cell_index++]);

                    constraints.push_back({constraints[2].back()});
                    for (std::size_t j = 0; j < num_chunks; ++j) {
                        constraints[3].push_back(cells[cell_index++]);
                        lookups[0].push_back(constraints[3].back());
                    }
                    for (int i = 0; i < 2; ++i) {
                        copy_to.push_back(constraints[2 * i][0]);
                    }

                    last_column = cells.back().second + 1 + buff;
                    last_row = cells.back().first + (last_column / witness_amount);
                    last_column %= witness_amount;

                    return configuration(first_coordinate, {last_row, last_column}, copy_to, constraints, lookups,
                                         cell_copy_from);
                }

                static std::vector<configuration> configure_all(std::size_t witness_amount, std::size_t num_blocks, std::size_t num_bits,
                                                                bool range_check_input, std::size_t limit_permutation_column) {

                    std::vector<configuration> result;
                    // result.push_back(configure_shift(witness_amount, 0, 0));
                    std::size_t row = 0,
                                column = 0;

                    if (calculate_shift(num_blocks, num_bits) == 0 && !range_check_input) {
                        for (std::size_t i = 0; i < num_blocks; ++i) {
                            configuration conf;
                            conf.copy_from = {row, column};
                            conf.copy_to.push_back({row, column});
                            column += 1;
                            if (column == limit_permutation_column) {
                                column = 0;
                                row += 1;
                            }
                            conf.last_coordinate = {row, column};
                            result.push_back(conf);
                        }
                        result.push_back(configure_output(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column, row, column));
                        return result;
                    }

                    std::size_t num_cells = calculate_num_cells(num_blocks, num_bits, range_check_input);
                    std::size_t buff = calculate_buff(witness_amount, range_check_input);
                    for (std::size_t i = 0; i < num_blocks; ++i) {
                        auto conf = configure_inner(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column, row, column, num_cells, buff);
                        result.push_back(conf);
                        row = conf.last_coordinate.row;
                        column = conf.last_coordinate.column;
                    }
                    result.push_back(configure_output(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column, row, column));

                    if (calculate_shift(num_blocks, num_bits) == 0) {
                        return result;
                    }

                    row = result.back().last_coordinate.row;
                    column = result.back().last_coordinate.column;
                    for (std::size_t i = 0; i < num_blocks; ++i) {
                        auto conf = configure_inner_range_checks(witness_amount, limit_permutation_column, row, column);
                        result.push_back(conf);
                        row = conf.last_coordinate.row;
                        column = conf.last_coordinate.column;
                    }

                    return result;
                }
                static std::map<std::size_t, std::vector<std::size_t>> configure_map(std::size_t witness_amount,
                                                                                    std::size_t num_blocks,
                                                                                    std::size_t num_bits,
                                                                                    bool range_check_input,
                                                                                    std::size_t limit_permutation_column) {

                    auto shift = calculate_shift(num_blocks, num_bits);
                    if (shift == 0 && !range_check_input) {
                        return {};
                    }

                    auto config = configure_all(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column);
                    std::size_t row = 0,
                                column = 0;

                    std::map<std::size_t, std::vector<std::size_t>> config_map;

                    for (std::size_t i = 0; i < num_blocks; ++i) {
                        row = config[i].first_coordinate.row;
                        column = config[i].first_coordinate.column;
                        if (config_map.find(column) != config_map.end()) {
                            config_map[column].push_back(row );
                        } else {
                            config_map[column] = {row };
                        }
                    }

                    return config_map;
                }

                static std::vector<std::vector<configuration>> configure_output_gates(std::size_t witness_amount,
                                                                            std::size_t num_blocks,
                                                                            std::size_t num_bits,
                                                                            bool range_check_input,
                                                                            std::size_t limit_permutation_column) {
                    std::vector<std::vector<configuration>> result;

                    configuration cur_config = configure_output(witness_amount, num_blocks, num_bits,
                                                                range_check_input, limit_permutation_column,
                                                                0, 0);
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
                    cur_result.back().lookups = cur_config.lookups;
                    result.push_back(cur_result);

                    return result;
                }

                static std::vector<std::vector<configuration>> configure_inner_range_check_gates(std::size_t witness_amount,
                                                                            std::size_t num_blocks,
                                                                            std::size_t num_bits,
                                                                            bool range_check_input,
                                                                            std::size_t limit_permutation_column) {
                    std::vector<std::vector<configuration>> result;

                    configuration cur_config = configure_inner_range_checks(witness_amount, limit_permutation_column, 0, 0);
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
                    cur_result.back().lookups = cur_config.lookups;
                    result.push_back(cur_result);

                    return result;
                }

                static std::vector<std::vector<configuration>> configure_gates(std::size_t witness_amount,
                                                                            std::size_t num_blocks,
                                                                            std::size_t num_bits,
                                                                            bool range_check_input,
                                                                            std::size_t limit_permutation_column) {

                    if (calculate_shift(num_blocks, num_bits) == 0 && !range_check_input) {
                        return {};
                    }

                    std::vector<std::vector<configuration>> result;
                    auto gates_configuration_map = configure_map(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column);
                    std::size_t num_cells = calculate_num_cells(num_blocks, num_bits, range_check_input);
                    std::size_t buff = calculate_buff(witness_amount, range_check_input);

                    for (auto config: gates_configuration_map) {
                        configuration cur_config = configure_inner(witness_amount, num_blocks, num_bits,
                                                                    range_check_input, limit_permutation_column,
                                                                    0, config.first, num_cells, buff);
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

                std::vector<std::size_t> calculate_gates_rows(std::size_t witness_amount) {
                    std::vector<std::size_t> res;
                    std::size_t incr = 3;
                    std::size_t block_per_gate = 5;
                    std::size_t first_block = 0;
                    if (witness_amount == 15) {
                        res.push_back(0);
                        incr = 2;
                        block_per_gate = 6;
                        first_block = 2;
                    }
                    std::size_t cur_row = 1;
                    for (std::size_t i = first_block; i < num_blocks; i += block_per_gate) {
                        res.push_back(cur_row);
                        cur_row += incr;
                    }

                    auto config = configure_all(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column);
                    auto output = configure_output_gates(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column);
                    auto row = config.back().last_coordinate.row;
                    if (config.back().last_coordinate.column == 0) row--;
                    if (output.size() == 2) {
                        res.push_back(row - 2);
                    }
                    res.push_back(row - 1);
                    return res;
                }

                static std::size_t get_gates_amount(std::size_t witness_amount,
                                                    std::size_t num_blocks,
                                                    std::size_t num_bits,
                                                    bool range_check_input,
                                                    std::size_t limit_permutation_column = 7) {
                    auto map = configure_map(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column);
                    auto res = map.size() * 2 + range_check_input;
                    auto output = configure_output_gates(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column);
                    res += output[0].size() + 1;
                    auto shift = calculate_shift(num_blocks, num_bits);
                    if (shift != 0) res += 2;
                    return res;
                }

                static std::size_t get_rows_amount(std::size_t witness_amount,
                                                   std::size_t num_blocks,
                                                   std::size_t num_bits,
                                                   bool range_check_input,
                                                   std::size_t limit_permutation_column) {
                    auto confs = configure_all(witness_amount, num_blocks, num_bits, range_check_input, limit_permutation_column);
                    auto res = confs.back().last_coordinate.row + 1 * (confs.back().last_coordinate.column != 0);
                    if (res < 2) res = 2;
                    return res;
                }

                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["keccak_pack_table/range_check"] = 0; // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/64bit"] = 0; // REQUIRED_TABLE
                    lookup_tables["keccak_sign_bit_table/full"] = 0; // REQUIRED_TABLE
                    return lookup_tables;
                }

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak_padding(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input, std::size_t num_blocks_, std::size_t num_bits_,
                               bool range_check_input_ = true, std::size_t limit_permutation_column_ = 7) :
                    component_type(witness, constant, public_input,
                                   get_manifest(num_blocks_, num_bits_, range_check_input_, limit_permutation_column_)),
                    num_blocks(num_blocks_), num_bits(num_bits_), range_check_input(range_check_input_),
                    limit_permutation_column(limit_permutation_column_) {};

                keccak_padding(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t num_blocks_, std::size_t num_bits_, bool range_check_input_ = true, std::size_t limit_permutation_column_ = 7) :
                    component_type(witnesses, constants, public_inputs,
                                   get_manifest(num_blocks_, num_bits_, range_check_input_, limit_permutation_column_)),
                    num_blocks(num_blocks_), num_bits(num_bits_), range_check_input(range_check_input_),
                    limit_permutation_column(limit_permutation_column_) {};

                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
            };

            template<typename BlueprintFieldType>
            using padding_component =
                keccak_padding<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            std::vector<std::size_t> generate_gates(
                const padding_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename padding_component<BlueprintFieldType>::input_type
                    &instance_input,
                const typename lookup_library<BlueprintFieldType>::left_reserved_type lookup_tables_indices) {

                using component_type = padding_component<BlueprintFieldType>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using lookup_constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using integral_type = typename BlueprintFieldType::integral_type;

                std::vector<std::size_t> selector_indexes;
                auto gates_configuration = component.gates_configuration;
                std::size_t gate_index = 0;
                std::size_t lookup_gate_index = 0;

                std::vector<constraint_type> cur_constraints;
                std::vector<lookup_constraint_type> cur_lookup_constraints;

                cur_constraints.clear();
                cur_lookup_constraints.clear();

                if (component.shift == 0) {
                    if (component.range_check_input) {
                        auto conf = gates_configuration[0][0];
                        for (std::size_t i = 1; i < 8; ++i) {
                            cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),
                                                            {var(component.W(conf.constraints[0][i].column), static_cast<int>(conf.constraints[0][i].row))}});
                        }
                        cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_sign_bit_table/full"),
                                                        {var(component.W(conf.constraints[0][8].column), static_cast<int>(conf.constraints[0][8].row))}});
                        selector_indexes.push_back(bp.add_lookup_gate(cur_lookup_constraints));
                        lookup_gate_index++;
                        cur_lookup_constraints.clear();
                        for (auto confs : gates_configuration) {
                            auto conf = confs[0];
                            constraint_type constraint = var(conf.constraints[0][0].column, static_cast<int>(conf.constraints[0][0].row));
                            for (std::size_t i = 1; i < 9; ++i) {
                                constraint -= var(component.W(conf.constraints[0][i].column), static_cast<int>(conf.constraints[0][i].row))
                                            * (integral_type(1) << ((i-1) * 8));
                                cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),
                                                                {var(component.W(conf.constraints[0][i].column), static_cast<int>(conf.constraints[0][i].row))}});
                            }
                            selector_indexes.push_back(bp.add_gate(constraint));
                            gate_index++;
                            selector_indexes.push_back(bp.add_lookup_gate(cur_lookup_constraints));
                            lookup_gate_index++;
                            cur_lookup_constraints.clear();
                        }
                    }
                } else {
                    if (component.range_check_input) {
                        auto conf = gates_configuration[0][0];
                        for (std::size_t i = 1; i < 8; ++i) {
                            cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),
                                                            {var(component.W(conf.constraints[2][i].column), static_cast<int>(conf.constraints[2][i].row))}});
                        }
                        cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_sign_bit_table/full"),
                                                        {var(component.W(conf.constraints[2][8].column), static_cast<int>(conf.constraints[2][8].row))}});
                        // chunk, range_check
                        for (std::size_t i = 1; i < 9; ++i) {
                            cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),
                                                            {var(component.W(conf.constraints[3][i].column), static_cast<int>(conf.constraints[3][i].row))}});
                        }
                        selector_indexes.push_back(bp.add_lookup_gate(cur_lookup_constraints));
                        lookup_gate_index++;
                        cur_lookup_constraints.clear();
                    }
                    for (auto confs : gates_configuration) {
                        auto conf = confs[0];
                        // chunk, first, second
                        cur_constraints.push_back(constraint_type(
                            var(component.W(conf.constraints[0][0].column), static_cast<int>(conf.constraints[0][0].row)) -
                            var(component.W(conf.constraints[0][1].column), static_cast<int>(conf.constraints[0][1].row)) *
                                (integral_type(1) << (64 - component.shift)) -
                            var(component.W(conf.constraints[0][2].column), static_cast<int>(conf.constraints[0][2].row))));
                        // sum, relay, first
                        cur_constraints.push_back(
                            var(component.W(conf.constraints[1][0].column), static_cast<int>(conf.constraints[1][0].row)) -
                            var(component.W(conf.constraints[1][1].column), static_cast<int>(conf.constraints[1][1].row)) *
                                (integral_type(1) << component.shift) -
                            var(component.W(conf.constraints[1][2].column), static_cast<int>(conf.constraints[1][2].row)));
                        // sum, range_check
                        constraint_type constraint = var(conf.constraints[2][0].column, static_cast<int>(conf.constraints[2][0].row));
                        for (std::size_t i = 1; i < 9; ++i) {
                            constraint -= var(component.W(conf.constraints[2][i].column), static_cast<int>(conf.constraints[2][i].row))
                                        * (integral_type(1) << ((i-1) * 8));
                            cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),
                                                            {var(component.W(conf.constraints[2][i].column), static_cast<int>(conf.constraints[2][i].row))}});
                        }
                        cur_constraints.push_back(constraint);
                        if (component.range_check_input) {
                            // chunk, range_check
                            constraint = var(component.W(conf.constraints[3][0].column), static_cast<int>(conf.constraints[3][0].row));
                            for (std::size_t i = 1; i < 9; ++i) {
                                constraint -= var(component.W(conf.constraints[3][i].column), static_cast<int>(conf.constraints[3][i].row))
                                            * (integral_type(1) << ((i-1) * 8));
                                cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),
                                                                {var(component.W(conf.constraints[3][i].column), static_cast<int>(conf.constraints[3][i].row))}});
                            }
                            cur_constraints.push_back(constraint);
                        }

                        selector_indexes.push_back(bp.add_gate(cur_constraints));
                        gate_index++;
                        cur_constraints.clear();
                        selector_indexes.push_back(bp.add_lookup_gate(cur_lookup_constraints));
                        lookup_gate_index++;
                        cur_lookup_constraints.clear();
                    }
                }

                auto output_gates = component.output_gates_configuration[0];
                std::size_t idx[2] = {0, 0};
                std::size_t shifts[2] = {1, 1};
                if (output_gates.size() > 1) {
                    idx[1] = 1;
                    shifts[1] = 2;
                }
                // (s_i - 1)(s_i - 2)w_i=0  &&  s_i(s_i - 2)(w_i*delta - 1)=0
                for (auto constr : output_gates[idx[0]].constraints) {
                    cur_constraints.push_back((var(constr[0].column, static_cast<int>(constr[0].row) - shifts[0]) - 1) *
                                              (var(constr[0].column, static_cast<int>(constr[0].row) - shifts[0]) - 2) *
                                              var(constr[1].column, static_cast<int>(constr[1].row) - shifts[0]));
                    cur_constraints.push_back(var(constr[0].column, static_cast<int>(constr[0].row) - shifts[0]) *
                                              (var(constr[0].column, static_cast<int>(constr[0].row) - shifts[0]) - 2) *
                                              (var(constr[1].column, static_cast<int>(constr[1].row) - shifts[0]) * var(constr[2].column, static_cast<int>(constr[2].row) - shifts[0]) - 1));
                }
                if (output_gates.size() > 1) {
                    selector_indexes.push_back(bp.add_gate(cur_constraints));
                    gate_index++;
                    cur_constraints.clear();
                }
                for (auto constr : output_gates[idx[1]].constraints) {
                    cur_constraints.push_back((var(constr[0].column, static_cast<int>(constr[0].row) - shifts[1]) - 1) *
                                              (var(constr[0].column, static_cast<int>(constr[0].row) - shifts[1]) - 2) *
                                              var(constr[1].column, static_cast<int>(constr[1].row) - shifts[1]));
                    cur_constraints.push_back(var(constr[0].column, static_cast<int>(constr[0].row) - shifts[1]) *
                                              (var(constr[0].column, static_cast<int>(constr[0].row) - shifts[1]) - 2) *
                                              (var(constr[1].column, static_cast<int>(constr[1].row) - shifts[1]) * var(constr[2].column, static_cast<int>(constr[2].row) - shifts[1]) - 1));
                }
                std::vector<constraint_type> s_i;
                for (std::size_t i = 0; i < 2; ++i) {
                    for (auto constr : output_gates[idx[i]].constraints) {
                        s_i.push_back(var(constr[0].column, static_cast<int>(constr[0].row) - shifts[1]));
                    }
                }
                // s_i(s_i - 1)(s_i - 2)=0
                for (std::size_t i = 0; i < 17; ++i) {
                    cur_constraints.push_back(s_i[i] * (s_i[i] - 1) * (s_i[i] - 2));
                }
                // s_i(s_i - 2)s_i+1=0  &&  (s_i+1 - s_i + 1)(s_i+1 - s_i)=0
                for (std::size_t i = 0; i < 16; ++i) {
                    cur_constraints.push_back(s_i[i] * (s_i[i] - 2) * s_i[i+1]);
                    cur_constraints.push_back((s_i[i+1] - s_i[i] + 1) * (s_i[i+1] - s_i[i]));
                }
                // sum
                constraint_type sum = s_i[0];
                for (std::size_t i = 1; i < 17; ++i) {
                    sum += s_i[i];
                }
                cur_constraints.push_back((34 - sum) * sum - 1 - var(output_gates[idx[1]].lookups[0][0].column, static_cast<int>(output_gates[idx[1]].lookups[0][0].row) - shifts[1]));

                selector_indexes.push_back(bp.add_gate(cur_constraints));
                gate_index++;
                cur_constraints.clear();

                cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),
                                                 {var(output_gates[idx[1]].lookups[0][0].column, static_cast<int>(output_gates[idx[1]].lookups[0][0].row) - shifts[1])}});

                selector_indexes.push_back(bp.add_lookup_gate(cur_lookup_constraints));
                lookup_gate_index++;
                cur_lookup_constraints.clear();

                if (component.shift != 0) {
                    auto conf = component.inner_range_check_gates_configuration[0][0];
                    int row_shift = 0;
                    if (conf.last_coordinate.row - conf.first_coordinate.row == 2) row_shift = 1;

                    cur_constraints.push_back(var(conf.constraints[0][0].column, static_cast<int>(conf.constraints[0][0].row) - row_shift) *
                                                (integral_type(1) << (64 - component.shift)) -
                                            var(conf.constraints[0][1].column, static_cast<int>(conf.constraints[0][1].row) - row_shift));
                    cur_constraints.push_back(var(conf.constraints[2][0].column, static_cast<int>(conf.constraints[2][0].row) - row_shift) *
                                                (integral_type(1) << component.shift) -
                                            var(conf.constraints[2][1].column, static_cast<int>(conf.constraints[2][1].row) - row_shift));
                    for (std::size_t j = 0; j < 2; ++j) {
                        constraint_type constraint = var(conf.constraints[2 * j + 1][0].column, static_cast<int>(conf.constraints[2 * j + 1][0].row) - row_shift);
                        for (std::size_t i = 1; i < 9; ++i) {
                            constraint -= var(conf.constraints[2 * j + 1][i].column, static_cast<int>(conf.constraints[2 * j + 1][i].row) - row_shift)
                                        * (integral_type(1) << ((i-1) * 8));
                            cur_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),
                                                            {var(conf.constraints[2 * j + 1][i].column, static_cast<int>(conf.constraints[2 * j + 1][i].row) - row_shift)}});
                        }
                        cur_constraints.push_back(constraint);
                    }

                    selector_indexes.push_back(bp.add_gate(cur_constraints));
                    gate_index++;
                    selector_indexes.push_back(bp.add_lookup_gate(cur_lookup_constraints));
                    lookup_gate_index++;
                }

                BOOST_ASSERT(gate_index + lookup_gate_index == component.gates_amount);
                return selector_indexes;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const padding_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename padding_component<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = padding_component<BlueprintFieldType>;
                using var = typename component_type::var;

                const std::size_t strow = start_row_index;
                std::size_t config_index = 0;
                std::size_t input_index = 0;
                std::vector<std::array<var, 2>> first_second_chunks;
                std::array<var, 2> fs_chunk;

                std::size_t conf_index_for_input = 0;
                if (component.shift != 0) {
                    bp.add_copy_constraint({instance_input.message[input_index++], var(component.W(0), strow, false)});
                    conf_index_for_input = 1;
                }

                while (config_index < component.num_blocks - 1) {
                    auto config = component.full_configuration[config_index];
                    bp.add_copy_constraint({instance_input.message[input_index++],
                                            var(component.W(config.copy_to[conf_index_for_input].column),
                                                config.copy_to[conf_index_for_input].row + strow, false)});
                    if (component.shift != 0) {
                        auto next_config = component.full_configuration[config_index + 1];
                        bp.add_copy_constraint({var(component.W(config.copy_from.column),
                                                    config.copy_from.row + strow, false),
                                                var(component.W(next_config.copy_to[0].column),
                                                    next_config.copy_to[0].row + strow, false)});
                        first_second_chunks.push_back({var(component.W(config.constraints[0][1].column),
                                                        config.constraints[0][1].row + strow, false),
                                                       var(component.W(config.constraints[0][2].column),
                                                        config.constraints[0][2].row + strow, false)});
                    }
                    config_index++;
                }
                if (component.shift != 0) {
                    auto config = component.full_configuration[config_index++];
                    bp.add_copy_constraint({var(component.C(0), start_row_index + 1, false, var::column_type::constant),
                                            var(component.W(config.copy_to[conf_index_for_input].column),
                                                config.copy_to[conf_index_for_input].row + strow, false)});
                    first_second_chunks.push_back({var(component.W(config.constraints[0][1].column),
                                                    config.constraints[0][1].row + strow, false),
                                                   var(component.W(config.constraints[0][2].column),
                                                    config.constraints[0][2].row + strow, false)});
                } else {
                    auto config = component.full_configuration[config_index++];
                    bp.add_copy_constraint({instance_input.message[input_index++],
                                            var(component.W(config.copy_to[conf_index_for_input].column),
                                                config.copy_to[conf_index_for_input].row + strow, false)});
                }

                auto config = component.full_configuration[config_index];
                std::size_t idx = 0;
                std::size_t prev_offset = (component.shift != 0) * 2;
                for (int i = 17 - component.num_padding_zeros; i > 0; --i) {
                    auto prev_config = component.full_configuration[config_index - i];
                    bp.add_copy_constraint({var(component.W(config.copy_to[idx].column), config.copy_to[idx++].row + strow, false),
                                            var(component.W(prev_config.copy_to[prev_offset].column), prev_config.copy_to[prev_offset].row + strow, false)});
                }
                config_index++;

                if (component.shift == 0) {
                    bp.add_copy_constraint({var(component.C(0), start_row_index + 1, false, var::column_type::constant),
                                            var(component.W(config.copy_to[idx].column), config.copy_to[idx++].row + strow, false)});
                }
                for (int i = 0; i < component.num_padding_zeros - (component.shift == 0); ++i) {
                    bp.add_copy_constraint({var(component.W(config.copy_to[idx].column), config.copy_to[idx++].row + strow, false),
                                            var(component.C(0), start_row_index, false, var::column_type::constant)});
                }

                if (component.shift != 0) {
                    for (int i = 0; i < component.num_blocks; ++i) {
                        config = component.full_configuration[config_index++];
                        bp.add_copy_constraint({first_second_chunks[i][0], var(component.W(config.constraints[0][0].column), config.constraints[0][0].row + strow, false)});
                        bp.add_copy_constraint({first_second_chunks[i][1], var(component.W(config.constraints[2][0].column), config.constraints[2][0].row + strow, false)});
                    }
                }
            }

            template<typename BlueprintFieldType>
            typename padding_component<BlueprintFieldType>::result_type generate_circuit(
                const padding_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename padding_component<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {
                std::cout << "Keccak padding generate_circuit rows_amount = " << component.rows_amount << " gates_amount = " << component.gates_amount << std::endl;

                using component_type = padding_component<BlueprintFieldType>;

                auto selector_indexes = generate_gates(component, bp, assignment, instance_input, bp.get_reserved_indices());

                auto gc_map = component.gates_configuration_map;
                std::size_t sel_ind = 0;
                auto gc_iter = gc_map.begin();

                if (gc_iter != gc_map.end()) {
                    if (component.range_check_input) {
                        assignment.enable_selector(selector_indexes[sel_ind], gc_iter->second[0] + start_row_index);
                        sel_ind++;
                        assignment.enable_selector(selector_indexes[sel_ind], gc_iter->second[0] + start_row_index);
                    } else {
                        assignment.enable_selector(selector_indexes[sel_ind], gc_iter->second[0] + start_row_index);
                        assignment.enable_selector(selector_indexes[sel_ind + 1], gc_iter->second[0] + start_row_index);
                    }
                    for (std::size_t i = 1; i < gc_iter->second.size(); ++i) {
                        assignment.enable_selector(selector_indexes[sel_ind], gc_iter->second[i] + start_row_index);
                        assignment.enable_selector(selector_indexes[sel_ind + 1], gc_iter->second[i] + start_row_index);
                    }
                    sel_ind += 2;
                    gc_iter++;

                    for (; gc_iter != gc_map.end(); ++gc_iter) {
                        for (auto gate_row : gc_iter->second) {
                            assignment.enable_selector(selector_indexes[sel_ind], gate_row + start_row_index);
                            assignment.enable_selector(selector_indexes[sel_ind + 1], gate_row + start_row_index);
                        }
                        sel_ind += 2;
                    }
                }
                auto output = component.full_configuration[component.num_blocks];
                auto output_gates = component.output_gates_configuration[0];
                assignment.enable_selector(selector_indexes[sel_ind++], output.first_coordinate.row + 1 + start_row_index);
                if (output_gates.size() > 1) {
                    assignment.enable_selector(selector_indexes[sel_ind++], output.first_coordinate.row + 2 + start_row_index);
                }

                if (component.shift != 0) {
                    int row_shift = 0;
                    auto conf = component.full_configuration[component.num_blocks + 1];
                    if (conf.last_coordinate.row - conf.first_coordinate.row == 2) row_shift = 1;
                    for (std::size_t i = 1; i < component.num_blocks + 1; ++i) {
                        conf = component.full_configuration[component.num_blocks + i];
                        assignment.enable_selector(selector_indexes[sel_ind], conf.first_coordinate.row + start_row_index + row_shift);
                    }
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                generate_assignments_constant(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            typename padding_component<BlueprintFieldType>::result_type generate_assignments(
                const padding_component<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename padding_component<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {
                std::cout << "Keccak padding component generate assignments" << std::endl;

                const std::size_t strow = start_row_index;

                using component_type = padding_component<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using var = typename component_type::var;

                BOOST_ASSERT(component.num_blocks == instance_input.message.size());

                std::size_t config_index = 0;
                // range_check shift
                integral_type mask_range_check = (integral_type(1) << 8) - 1;
                std::vector<value_type> output_values;
                std::vector<std::array<integral_type, 2>> non_shifted_chunk_parts;
                std::vector<std::array<integral_type, 2>> shifted_chunk_parts;

                if (component.shift != 0) {
                    integral_type relay_chunk = integral_type(var_value(assignment, instance_input.message[0]).data);
                    for (std::size_t index = 1; index < component.num_blocks + 1; ++index) {
                        value_type chunk = value_type(component.padding_delimiter);
                        if (index < component.num_blocks) {
                            chunk = var_value(assignment, instance_input.message[index]);
                        }
                        integral_type integral_chunk = integral_type(chunk.data);
                        integral_type mask = (integral_type(1) << (64 - component.shift)) - 1;
                        std::array<integral_type, 2> chunk_parts = {integral_chunk >> (64 - component.shift),
                                                                    integral_chunk & mask};
                        non_shifted_chunk_parts.push_back(chunk_parts);
                        shifted_chunk_parts.push_back({chunk_parts[0] << (64 - component.shift), chunk_parts[1] << component.shift});
                        integral_type sum = (relay_chunk << component.shift) + chunk_parts[0];
                        output_values.push_back(value_type(sum));

                        std::vector<integral_type> sum_range_check;
                        integral_type sum_to_check = sum;
                        for (std::size_t i = 0; i < 7; ++i) {
                            sum_range_check.push_back(sum_to_check & mask_range_check);
                            sum_to_check >>= 8;
                        }
                        sum_range_check.push_back(sum_to_check);

                        auto cur_config = component.full_configuration[config_index];
                        // chunk, first, second
                        assignment.witness(component.W(cur_config.constraints[0][0].column), cur_config.constraints[0][0].row + strow) = chunk;
                        for (int j = 1; j < 3; ++j) {
                            assignment.witness(component.W(cur_config.constraints[0][j].column), cur_config.constraints[0][j].row + strow) = value_type(chunk_parts[j - 1]);
                        }
                        // sum, relay, first
                        assignment.witness(component.W(cur_config.constraints[1][0].column), cur_config.constraints[1][0].row + strow) = value_type(sum);
                        assignment.witness(component.W(cur_config.constraints[1][1].column), cur_config.constraints[1][1].row + strow) = value_type(relay_chunk);
                        assignment.witness(component.W(cur_config.constraints[1][2].column), cur_config.constraints[1][2].row + strow) = value_type(chunk_parts[0]);
                        // sum range_check
                        for (int j = 1; j < 9; ++j) {
                            assignment.witness(component.W(cur_config.constraints[2][j].column), cur_config.constraints[2][j].row + strow) = value_type(sum_range_check[j - 1]);
                        }
                        if (component.range_check_input) {
                            std::vector<integral_type> chunk_range_check;
                            integral_type chunk_to_check = integral_chunk;
                            for (std::size_t i = 0; i < 7; ++i) {
                                chunk_range_check.push_back(chunk_to_check & mask_range_check);
                                chunk_to_check >>= 8;
                            }
                            chunk_range_check.push_back(chunk_to_check);
                            // chunk range_check
                            for (int j = 1; j < 9; ++j) {
                                assignment.witness(component.W(cur_config.constraints[3][j].column), cur_config.constraints[3][j].row + strow) = value_type(chunk_range_check[j - 1]);
                            }
                        }

                        relay_chunk = chunk_parts[1];
                        config_index++;
                    }
                } else {
                    for (std::size_t index = 0; index < component.num_blocks; ++index) {
                        auto cur_config = component.full_configuration[index];

                        if (component.range_check_input) {
                            integral_type chunk_to_check = integral_type(var_value(assignment, instance_input.message[index]).data);
                            integral_type mask_range_check = (integral_type(1) << 8) - 1;
                            std::vector<integral_type> chunk_range_check;
                            for (std::size_t i = 0; i < 8; ++i) {
                                chunk_range_check.push_back(chunk_to_check & mask_range_check);
                                chunk_to_check >>= 8;
                            }
                            // chunk range_check
                            for (int j = 1; j < 9; ++j) {
                                assignment.witness(component.W(cur_config.constraints[0][j].column), cur_config.constraints[0][j].row + strow) = value_type(chunk_range_check[j - 1]);
                            }
                        }

                        assignment.witness(component.W(cur_config.copy_to[0].column),
                                           cur_config.copy_to[0].row + strow) =
                            var_value(assignment, instance_input.message[index]);
                        output_values.push_back(var_value(assignment, instance_input.message[index]));
                        config_index++;
                    }
                    output_values.push_back(value_type(component.padding_delimiter));
                }

                // output
                auto cur_config = component.full_configuration[config_index++];
                std::size_t idx = 0;
                value_type last_nonzero = value_type(1);
                value_type sum_s = value_type(0);
                for (std::size_t i = output_values.size() - ((output_values.size() - 1) % 17 + 1); i < output_values.size(); ++i) {
                    last_nonzero = output_values[i];
                    assignment.witness(component.W(cur_config.copy_to[idx].column), cur_config.copy_to[idx].row + strow) = last_nonzero;
                    value_type s = (i == output_values.size() - 1) ? value_type(1) : value_type(2);
                    assignment.witness(component.W(cur_config.constraints[idx][0].column), cur_config.constraints[idx++][0].row + strow) = s;
                    sum_s += s;
                }
                assignment.witness(component.W(cur_config.constraints[idx - 1][2].column), cur_config.constraints[idx - 1][2].row + strow) = value_type(1) / last_nonzero;
                for (int i = 0; i < component.num_padding_zeros - (component.shift == 0); ++i) {
                    assignment.witness(component.W(cur_config.copy_to[idx].column), cur_config.copy_to[idx].row + strow) = value_type(0);
                    assignment.witness(component.W(cur_config.constraints[idx][0].column), cur_config.constraints[idx++][0].row + strow) = value_type(0);
                }
                assignment.witness(component.W(cur_config.lookups[0][0].column), cur_config.lookups[0][0].row + strow) = sum_s * (value_type(34) - sum_s) - value_type(1);

                if (component.shift != 0) {
                    // additional range_check
                    integral_type mask_range_check = (integral_type(1) << 8) - 1;
                    for (std::size_t i = 0; i < shifted_chunk_parts.size(); ++i) {
                        cur_config = component.full_configuration[config_index++];
                        for (std::size_t j = 0; j < 2; ++j) {
                            assignment.witness(component.W(cur_config.constraints[2 * j][0].column), cur_config.constraints[2 * j][0].row + strow) = value_type(non_shifted_chunk_parts[i][j]);
                            assignment.witness(component.W(cur_config.constraints[2 * j][1].column), cur_config.constraints[2 * j][1].row + strow) = value_type(shifted_chunk_parts[i][j]);

                            integral_type chunk_to_check = shifted_chunk_parts[i][j];
                            std::vector<integral_type> chunk_range_check;
                            for (std::size_t i = 0; i < 8; ++i) {
                                chunk_range_check.push_back(chunk_to_check & mask_range_check);
                                chunk_to_check >>= 8;
                            }
                            // chunk range_check
                            for (int k = 1; k < 9; ++k) {
                                assignment.witness(component.W(cur_config.constraints[2 * j + 1][k].column), cur_config.constraints[2 * j + 1][k].row + strow) = value_type(chunk_range_check[k - 1]);
                            }
                        }
                    }
                }

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            void generate_assignments_constant(
                const padding_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename padding_component<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;

                assignment.constant(component.C(0), start_row_index) =  0;
                assignment.constant(component.C(0), start_row_index + 1) =  value_type(component.padding_delimiter);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_PADDING_HPP
