//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_DETAIL_LOOKUP_TABLE_DEFINITION_HPP
#define CRYPTO3_ZK_PLONK_DETAIL_LOOKUP_TABLE_DEFINITION_HPP

#include <string>
#include <map>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {
                    std::size_t next_power_of_two_minus_3(std::size_t x) {
                        std::size_t bit_count = 0;
                        const std::size_t original_x = x;
                        while (x >>= 1) {
                            bit_count++;
                        }
                        std::size_t result = (1 << (bit_count + 1)) - 2;
                        if (result <= original_x) {
                            result = (1 << (bit_count + 2)) - 2;
                        }
                        return result;
                    }
                };

                // Interface for lookup table definitions.
                template<typename FieldType>
                class lookup_subtable_definition{
                public:
                    std::vector<std::size_t> column_indices;
                    std::size_t begin;
                    std::size_t end;
                };

                template<typename FieldType>
                class lookup_table_definition{
                protected:
                    std::vector<std::vector<typename FieldType::value_type>> _table;
                public:
                    std::string table_name;
                    std::map<std::string, lookup_subtable_definition<FieldType>> subtables;

                    lookup_table_definition(const std::string table_name){
                        this->table_name = table_name;
                    }

                    virtual void generate() = 0;
                    virtual std::size_t get_columns_number() = 0;
                    virtual std::size_t get_rows_number() = 0;

                    const std::vector<std::vector<typename FieldType::value_type>> &get_table(){
                        if(_table.size() == 0){
                            generate();
                        }
                        return _table;
                    }
                    virtual ~lookup_table_definition() {};
                };

                template<typename FieldType>
                std::vector<std::string>
                get_tables_ordered_by_rows_number(const std::map<std::string, std::shared_ptr<lookup_table_definition<FieldType>>> &tables){
                    std::vector<std::pair<std::size_t, std::string>> before;
                    for(const auto& [k,table]:tables){
                        before.push_back(std::make_pair(table->get_rows_number(), k));
                    }
                    std::sort(before.begin(), before.end(), [](const std::pair<std::size_t, std::string> &lhs, const std::pair<std::size_t, std::string> &rhs) {
                        return lhs.first < rhs.first;
                    });
                    std::vector<std::string> result;
                    for(const auto& [k,table_name]:before){
                        result.push_back(table_name);
                    }
                    return result;
                }

                template<typename FieldType>
                class filled_lookup_table_definition:public lookup_table_definition<FieldType>{
                public:
                    filled_lookup_table_definition(lookup_table_definition<FieldType> &other):lookup_table_definition<FieldType>(other.table_name){
                        this->_table = other.get_table();
                    }
                    virtual void generate() {};
                    virtual ~filled_lookup_table_definition() {};
                    virtual std::size_t get_columns_number(){
                        return this->_table.size();
                    }
                    virtual std::size_t get_rows_number(){
                        return this->_table[0].size();
                    }
                };
                // Returned value -- new usable_rows.
                // All tables are necessary for circuit generation.
                template<typename FieldType, typename ArithmetizationParams, typename TableIdsMapType = std::map<std::string, std::size_t>>
                std::size_t pack_lookup_tables(
                    const TableIdsMapType &lookup_table_ids,
                    const std::map<std::string, std::shared_ptr<lookup_table_definition<FieldType>>> &lookup_tables,
                    plonk_constraint_system<FieldType, ArithmetizationParams> &bp,
                    plonk_assignment_table<FieldType, ArithmetizationParams> &assignment,
                    const std::vector<std::size_t> &constant_columns_ids,
                    std::size_t usable_rows
                ){
//                        std::cout << "Packing lookup tables" << std::endl;
//                        std::cout << "Usable rows before: " << usable_rows << std::endl;
                    std::size_t usable_rows_after = usable_rows;

                    // Compute first selector index.
                    std::size_t cur_selector_id = 0;
                    for(const auto &gate: bp.gates()){
                        cur_selector_id = std::max(cur_selector_id, gate.selector_index);
                    }
                    for(const auto &lookup_gate: bp.lookup_gates()){
                        cur_selector_id = std::max(cur_selector_id, lookup_gate.tag_index);
                    }
                    cur_selector_id++;

                    // Allocate constant columns
                    std::vector<plonk_column<FieldType>> constant_columns(
                        constant_columns_ids.size(), plonk_column<FieldType>(usable_rows, FieldType::value_type::zero())
                    );

                    std::size_t start_row = 1;
                    std::size_t table_index = 0;
                    std::vector<plonk_lookup_table<FieldType>> bp_lookup_tables(lookup_table_ids.size());
                    for( const auto&[k, table]:lookup_tables ){
//                            std::cout << "Packing table " << table->table_name << std::endl;
                        // Place table into constant_columns.
                        for( std::size_t i = 0; i < table->get_table().size(); i++ ){
                            if(constant_columns[i].size() < start_row + table->get_table()[i].size()){
                                constant_columns[i].resize(start_row + table->get_table()[i].size());
                                if( usable_rows_after < start_row + table->get_table()[i].size() ){
                                    usable_rows_after = start_row + table->get_table()[i].size();
                                }
                            }
                            for( std::size_t j = 0; j < table->get_table()[i].size(); j++ ){
                                constant_columns[i][start_row + j] = table->get_table()[i][j];
                            }
                        }

                        for( const auto &[subtable_name, subtable]:table->subtables ){
//                                std::cout << "Packing subtable " << subtable_name << std::endl;
                            // Create selector
                            plonk_column<FieldType> selector_column(usable_rows_after, FieldType::value_type::zero());
                            for(std::size_t k = subtable.begin; k <= subtable.end; k++){
                                selector_column[start_row + k] = FieldType::value_type::one();
                            }

                            std::string full_table_name = table->table_name + "/" + subtable_name;
                            bp_lookup_tables[lookup_table_ids.at(full_table_name) - 1] = plonk_lookup_table<FieldType>(subtable.column_indices.size(), cur_selector_id);
                            std::vector<plonk_variable<typename FieldType::value_type>> option;
                            for( const auto &column_index:subtable.column_indices ){
                                option.emplace_back( plonk_variable<typename FieldType::value_type>(
                                    constant_columns_ids[column_index], 0,
                                    false, plonk_variable<typename FieldType::value_type>::column_type::constant
                                ) );
                            }
                            bp_lookup_tables[lookup_table_ids.at(full_table_name) - 1].append_option(option);

                            assignment.fill_selector(cur_selector_id, selector_column);
                            // Create table declaration
                            table_index++;
                            cur_selector_id++;
                        }
                        start_row += table->get_rows_number();
                    }
                    for(std::size_t i = 0; i < bp_lookup_tables.size(); i++){
                        bp.add_lookup_table(std::move(bp_lookup_tables[i]));
                    }
                    for( std::size_t i = 0; i < constant_columns.size(); i++ ){
                        assignment.fill_constant(constant_columns_ids[i], constant_columns[i]);
                    }
//                        std::cout << "Usable rows after: " << usable_rows_after << std::endl;
                    return usable_rows_after;
                }

                template<typename FieldType, typename ArithmetizationParams,
                         typename TableIdsMapType = std::map<std::string, std::size_t>>
                std::size_t pack_lookup_tables_horizontal(
                    const TableIdsMapType &lookup_table_ids,
                    const std::map<std::string, std::shared_ptr<lookup_table_definition<FieldType>>> &lookup_tables,
                    plonk_constraint_system<FieldType, ArithmetizationParams> &bp,
                    plonk_assignment_table<FieldType, ArithmetizationParams> &assignment,
                    const std::vector<std::size_t> &constant_columns_ids,
                    std::size_t usable_rows,
                    std::size_t max_usable_rows = 524288
                ){
                    std::size_t usable_rows_after = usable_rows;

                    std::vector<std::string> ordered_table_names =
                        get_tables_ordered_by_rows_number<FieldType>(lookup_tables);
                    const std::size_t max_column_amount = std::accumulate(
                            lookup_tables.begin(), lookup_tables.end(), 0,
                            [](std::size_t max_amount, const auto &table){
                                return std::max(max_amount, table.second->get_columns_number());
                            });
                    BOOST_ASSERT_MSG(max_column_amount <= constant_columns_ids.size(),
                                     "Not enough constant columns for packing lookup tables.");

                    std::vector<std::tuple<std::reference_wrapper<const std::string>,
                                            std::size_t, std::size_t, std::size_t>> table_sizes;
                    for (const auto &table_name : ordered_table_names) {
                        const auto &table = lookup_tables.at(table_name);
                        // Check if the table can be folded: it needs to have no subtables smaller
                        // than max table rows
                        // This is a limitation of the packing algorithm
                        bool foldable = true;
                        if (table->get_rows_number() >= max_usable_rows) {
                            for (const auto subtable : table->subtables) {
                                // check if subtable is present in the indices
                                if (lookup_table_ids.find(table_name + "/" + subtable.first) !=
                                    lookup_table_ids.end()) {

                                    continue;
                                }
                                if (subtable.second.end - subtable.second.begin != table->get_rows_number() - 1) {
                                    foldable = false;
                                    break;
                                }
                            }
                        }
                        const std::size_t fold_count = foldable ?
                            (table->get_rows_number() + max_usable_rows - 1) / max_usable_rows
                            : 1;
                        const std::size_t column_count = table->get_columns_number() * fold_count;
                        const std::size_t rows_amount = (table->get_rows_number() + fold_count - 1) / fold_count;
                        if (rows_amount > max_usable_rows) {
                            // We need to increase the max_usable_rows to make it fit
                            // A proper optimizer would calculate a reasonable bound
                            return pack_lookup_tables_horizontal<FieldType, ArithmetizationParams, TableIdsMapType>(
                                lookup_table_ids, lookup_tables, bp, assignment, constant_columns_ids, usable_rows,
                                detail::next_power_of_two_minus_3(max_usable_rows));
                        }
                        table_sizes.emplace_back(table_name, column_count, rows_amount, fold_count);
                    }
                    // Now we can fold the smaller tables "below" the larger ones in some cases
                    std::vector<std::tuple<std::reference_wrapper<const std::string>,
                                            std::size_t, std::size_t, std::size_t,
                                            std::pair<std::size_t, std::size_t>>> layout;
                    std::size_t layout_x = 0;
                    std::vector<bool> laid_tables(ordered_table_names.size(), false);
                    // Quadratic layout calculation
                    for (std::size_t i = 0; i < ordered_table_names.size(); i++) {
                        if (laid_tables[i]) {
                            continue;
                        }
                        const auto &[table_name, column_count, rows_amount, fold_count] = table_sizes[i];
                        // First row is reserved for zeroes!
                        std::size_t layout_y = 1;
                        layout.emplace_back(table_name, column_count, rows_amount, fold_count,
                                            std::make_pair(layout_x, layout_y));
                        layout_y += rows_amount;
                        for (std::size_t j = i + 1; j < ordered_table_names.size(); j++) {
                            if (laid_tables[j]) {
                                continue;
                            }
                            const auto &[next_table_name, next_column_count, next_rows_amount, fold_count] =
                                table_sizes[j];
                            if (next_column_count > column_count ||
                                layout_y + next_rows_amount > max_usable_rows) {

                                continue;
                            }
                            laid_tables[j] = true;
                            layout.emplace_back(next_table_name, next_column_count, next_rows_amount,
                                                fold_count, std::make_pair(layout_x, layout_y));
                            layout_y += next_rows_amount;
                        }
                        usable_rows_after = std::max(usable_rows_after, layout_y);
                        layout_x += column_count;
                    }
                    if (layout_x > constant_columns_ids.size()) {
                        // We need to increase the max_usable_rows to make it fit
                        // A proper optimizer would calculate a reasonable bound
                        return pack_lookup_tables_horizontal<FieldType, ArithmetizationParams, TableIdsMapType>(
                            lookup_table_ids, lookup_tables, bp, assignment, constant_columns_ids, usable_rows,
                            detail::next_power_of_two_minus_3(max_usable_rows));
                    }
                    // std::cout << "Showing the layout:" << std::endl;
                    // for (const auto &[table_name, column_count, rows_amount, fold_count, layout_coords] : layout) {
                    //     const auto &[layout_x, layout_y] = layout_coords;
                    //     std::cout << table_name.get()
                    //               << " Columns: " << column_count << " Rows: " << rows_amount << " Fold: " << fold_count
                    //               << " LX: " << layout_x << " LY: " << layout_y << std::endl;
                    // }
                    // std::cout << "usable_rows_after: " << usable_rows_after << std::endl;
                    // Otherwise we can fit the current tables
                    std::sort(layout.begin(), layout.end(),
                                [](const auto &lhs, const auto &rhs) {
                                    const auto &[lhs_x, lhs_y] = std::get<4>(lhs);
                                    const auto &[rhs_x, rhs_y] = std::get<4>(rhs);
                                    return lhs_x < rhs_x || (lhs_x == rhs_x && lhs_y < rhs_y);
                                });
                    std::vector<plonk_lookup_table<FieldType>> bp_lookup_tables(lookup_table_ids.size());
                    std::vector<plonk_column<FieldType>> constant_columns(
                        constant_columns_ids.size(), plonk_column<FieldType>(usable_rows_after, FieldType::value_type::zero())
                    );
                    std::vector<plonk_column<FieldType>> selector_columns;
                    // Compute first selector index.
                    std::size_t cur_selector_id = 0;
                    for(const auto &gate: bp.gates()){
                        cur_selector_id = std::max(cur_selector_id, gate.selector_index);
                    }
                    for(const auto &lookup_gate: bp.lookup_gates()){
                        cur_selector_id = std::max(cur_selector_id, lookup_gate.tag_index);
                    }
                    cur_selector_id++;
                    const std::size_t first_selector_id = cur_selector_id;
                    std::map<std::pair<std::size_t, std::size_t>, std::size_t> selector_ids;
                    for (const auto &[table_name, column_count, rows_amount, fold_count, layout_coords] : layout) {
                        const auto &layout_x = std::get<0>(layout_coords);
                        const auto &layout_y = std::get<1>(layout_coords);
                        const auto &table = lookup_tables.at(table_name);
                        const std::size_t column_amount = table->get_columns_number();
                        const std::size_t table_rows_amount = table->get_rows_number();

                        for (std::size_t fold = 0; fold < fold_count; fold++) {
                            for (std::size_t column = layout_x + fold * column_amount;
                                    column < layout_x + (fold + 1) * column_amount; column++) {

                                for (std::size_t row = layout_y, table_row = 0; row < layout_y + rows_amount;
                                        row++, table_row++) {

                                    if (table_row < table_rows_amount) {
                                        constant_columns[column][row] =
                                            table->get_table()[column - layout_x - fold * column_amount]
                                                              [table_row];
                                    } else {
                                        constant_columns[column][row] =
                                            table->get_table()[column - layout_x - fold * column_amount]
                                                              [table_rows_amount - 1];
                                    }
                                }
                            }
                        }
                        for(const auto &[subtable_name, subtable]: table->subtables) {
                            std::string full_table_name = table->table_name + "/" + subtable_name;
                            // Check if table is actually in the circuit
                            if (lookup_table_ids.find(full_table_name) == lookup_table_ids.end()) {
                                continue;
                            }
                            // Check if the current rows are already included in some selector so that we reuse it
                            // Because folded table would not have a non-full subtable, this works
                            std::size_t next_selector;
                            if (selector_ids.find(std::make_pair(subtable.begin, subtable.end)) !=
                                selector_ids.end()) {

                                next_selector = selector_ids[std::make_pair(subtable.begin, subtable.end)];
                            } else {
                                BOOST_ASSERT_MSG(cur_selector_id < ArithmetizationParams::selector_columns,
                                                 "Not enough selector columns for packing lookup tables.");
                                next_selector = cur_selector_id++;
                                selector_ids[std::make_pair(subtable.begin, subtable.end)] = next_selector;
                                selector_columns.emplace_back(
                                    plonk_column<FieldType>(usable_rows_after, FieldType::value_type::zero()));
                            }
                            const std::size_t lookup_table_index = lookup_table_ids.at(full_table_name) - 1;
                            bp_lookup_tables[lookup_table_index] =
                                plonk_lookup_table<FieldType>(subtable.column_indices.size(), next_selector);
                            for(std::size_t fold = 0; fold < fold_count; fold++) {
                                std::vector<plonk_variable<typename FieldType::value_type>> option;
                                for(const auto &column_index : subtable.column_indices) {
                                    option.emplace_back( plonk_variable<typename FieldType::value_type>(
                                        constant_columns_ids[layout_x + fold * column_amount + column_index], 0,
                                        false, plonk_variable<typename FieldType::value_type>::column_type::constant
                                    ));
                                }
                                bp_lookup_tables[lookup_table_index].append_option(option);
                            }
                            // Fill selector column
                            for (std::size_t row = layout_y; row < layout_y + rows_amount; row++) {
                                selector_columns[next_selector - first_selector_id][row] =
                                    FieldType::value_type::one();
                            }
                        }
                    }
                    for(std::size_t i = 0; i < bp_lookup_tables.size(); i++){
                        bp.add_lookup_table(std::move(bp_lookup_tables[i]));
                    }
                    for(std::size_t i = 0; i < constant_columns.size(); i++){
                        assignment.fill_constant(constant_columns_ids[i], constant_columns[i]);
                    }
                    for (std::size_t i = 0; i < selector_columns.size(); i++) {
                        assignment.fill_selector(first_selector_id + i, selector_columns[i]);
                    }
                    return usable_rows_after;
                }
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_DETAIL_LOOKUP_TABLE_HPP
