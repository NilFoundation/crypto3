//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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
                template<typename FieldType, typename TableIdsMapType>
                std::size_t pack_lookup_tables(
                    const TableIdsMapType &lookup_table_ids,
                    const std::map<std::string, std::shared_ptr<lookup_table_definition<FieldType>>> &lookup_tables,
                    plonk_constraint_system<FieldType> &bp,
                    plonk_assignment_table<FieldType> &assignment,
                    const std::vector<std::size_t> &constant_columns_ids,
                    std::size_t usable_rows
                ){
                    // std::cout << "Packing lookup tables" << std::endl;
                    // std::cout << "Usable rows before: " << usable_rows << std::endl;
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
                    std::vector<plonk_column<FieldType>> selector_columns;

                    std::size_t start_row = 1;
                    std::vector<plonk_lookup_table<FieldType>> bp_lookup_tables(lookup_table_ids.size());
                    for( const auto&[k, table]:lookup_tables ){
                        // std::cout << "Packing table " << table->table_name << std::endl;
                        // Place table into constant_columns.
                        for( std::size_t i = 0; i < table->get_table().size(); i++ ){
                            auto end = start_row + table->get_table()[i].size();
                            if(constant_columns[i].size() < end){
                                constant_columns[i].resize(end);
                                if( usable_rows_after < end ){
                                    usable_rows_after = end;
                                }
                            }
                            for( std::size_t j = 0; j < table->get_table()[i].size(); j++ ){
                                constant_columns[i][start_row + j] = table->get_table()[i][j];
                            }
                        }

                        for( const auto &[subtable_name, subtable]:table->subtables ){
                            // std::cout << "Packing subtable " << subtable_name << std::endl;
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
                            selector_columns.push_back(std::move(selector_column));
                            // Create table declaration
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
                    // std::cout << "Usable rows after: " << usable_rows_after << std::endl;
                    return usable_rows_after;
                }

                template<typename FieldType, typename LookupTableIds>
                std::size_t pack_lookup_tables_horizontal(
                    const LookupTableIds &lookup_table_ids,
                    const std::map<std::string, std::shared_ptr<lookup_table_definition<FieldType>>> &lookup_tables,
                    plonk_constraint_system<FieldType> &bp,
                    plonk_assignment_table<FieldType> &assignment,
                    const std::vector<std::size_t> &constant_columns_ids,
                    std::size_t cur_selector_id,
                    std::size_t usable_rows,
                    std::size_t max_usable_rows = 524288
                ){
                    std::size_t usable_rows_after = usable_rows;

                    // Allocate constant columns
                    std::vector<plonk_column<FieldType>> constant_columns(
                        constant_columns_ids.size(), plonk_column<FieldType>(usable_rows, FieldType::value_type::zero())
                    );
                    std::vector<plonk_column<FieldType>> selector_columns;

                    std::vector<std::string> ordered_table_names = get_tables_ordered_by_rows_number<FieldType>(lookup_tables);

                    std::size_t start_row = 1;
                    std::vector<plonk_lookup_table<FieldType>> bp_lookup_tables(lookup_table_ids.size());
                    std::size_t start_constant_column = 0;
                    std::size_t prev_columns_number = 0;
                    std::size_t full_selector_id = 0;

                    for( const auto&table_name:ordered_table_names ){
                        const auto &table = lookup_tables.at(table_name);

                        if( table->get_rows_number() > max_usable_rows ){
                            usable_rows_after = max_usable_rows;
                            std::size_t options_number = table->get_rows_number() / max_usable_rows + 1;
                            start_constant_column += prev_columns_number;
                            std::size_t cur_constant_column = start_constant_column;
                            prev_columns_number = options_number * table->get_columns_number();

                            for(std::size_t i = start_constant_column; i < start_constant_column + prev_columns_number; i++){
                                constant_columns[i].resize(max_usable_rows);
                            }

                            if( full_selector_id == 0 ){
                                plonk_column<FieldType> selector_column(max_usable_rows, FieldType::value_type::one());
                                selector_column[0] = FieldType::value_type::zero();
                                assignment.fill_selector(cur_selector_id, selector_column);
                                full_selector_id = cur_selector_id;
                                cur_selector_id++;
                            }

                            if( table-> get_rows_number() % max_usable_rows == 0 ) options_number--;
                            std::size_t cur = 0;
                            for(std::size_t i = 0; i < options_number; i++){
                                for(std::size_t start_row = 1; start_row < max_usable_rows; start_row++, cur++){
                                    for(std::size_t k = 0; k < table->get_columns_number(); k++){
                                        if(cur < table->get_rows_number())
                                            constant_columns[cur_constant_column + k][start_row] = table->get_table()[k][cur];
                                        else
                                            constant_columns[cur_constant_column + k][start_row] = table->get_table()[k][table->get_rows_number()-1];
                                    }
                                }
                                cur_constant_column += table->get_columns_number();
                            }
                            for( const auto &[subtable_name, subtable]:table->subtables ){
                                if(subtable.begin != 0 || subtable.end != table->get_rows_number() -1)
                                    BOOST_ASSERT_MSG(false, "Only full big tables are supported now");
                                std::string full_table_name = table->table_name + "/" + subtable_name;
                                bp_lookup_tables[lookup_table_ids.at(full_table_name) - 1] = plonk_lookup_table<FieldType>(subtable.column_indices.size(), full_selector_id);
                                for(std::size_t i = 0; i < options_number; i++){
                                    std::vector<plonk_variable<typename FieldType::value_type>> option;
                                    for( const auto &column_index:subtable.column_indices ){
                                        option.emplace_back( plonk_variable<typename FieldType::value_type>(
                                            constant_columns_ids[start_constant_column + i * table->get_columns_number() + column_index], 0,
                                            false, plonk_variable<typename FieldType::value_type>::column_type::constant
                                        ) );
                                    }
                                    bp_lookup_tables[lookup_table_ids.at(full_table_name) - 1].append_option(option);
                                }
                            }
                            start_constant_column = cur_constant_column;
                            continue;
                        } else  if( start_row + table->get_rows_number() < max_usable_rows ){
                            if(prev_columns_number < table->get_columns_number()) prev_columns_number = table->get_columns_number();
                        } else if(table->get_rows_number() < max_usable_rows){
                            start_row = 1;
                            start_constant_column += prev_columns_number;
                            prev_columns_number = table->get_columns_number();
                        }

                        // Place table into constant_columns.
                        for( std::size_t i = 0; i < table->get_table().size(); i++ ){
                            if(constant_columns[start_constant_column + i].size() < start_row + table->get_table()[i].size()){
                                constant_columns[start_constant_column + i].resize(start_row + table->get_table()[i].size());
                                if( usable_rows_after < start_row + table->get_table()[i].size() ){
                                    usable_rows_after = start_row + table->get_table()[i].size();
                                }
                            }
                            for( std::size_t j = 0; j < table->get_table()[i].size(); j++ ){
                                constant_columns[start_constant_column + i][start_row + j] = table->get_table()[i][j];
                            }
                        }

                        std::map<std::pair<std::size_t, std::size_t>, std::size_t> selector_ids;
                        for( const auto &[subtable_name, subtable]:table->subtables ){
                            if( selector_ids.find(std::make_pair(subtable.begin, subtable.end)) != selector_ids.end() ){
                                // std::cout  << "selector for " << subtable_name << " from " << start_row + subtable.begin << " to " << start_row + subtable.end << std::endl;
                                auto selector_id = selector_ids[std::make_pair(subtable.begin, subtable.end)];
                                std::string full_table_name = table->table_name + "/" + subtable_name;
                                bp_lookup_tables[lookup_table_ids.at(full_table_name) - 1] = plonk_lookup_table<FieldType>(subtable.column_indices.size(), selector_id);
                                std::vector<plonk_variable<typename FieldType::value_type>> option;
                                for( const auto &column_index:subtable.column_indices ){
                                    option.emplace_back( plonk_variable<typename FieldType::value_type>(
                                        constant_columns_ids[column_index], 0,
                                        false, plonk_variable<typename FieldType::value_type>::column_type::constant
                                    ) );
                                }
                                bp_lookup_tables[lookup_table_ids.at(full_table_name) - 1].append_option(option);
                                continue;
                            }
                            // Create selector
                            plonk_column<FieldType> selector_column(usable_rows_after, FieldType::value_type::zero());
                            // std::cout  << "selector for " << subtable_name << " from " << start_row + subtable.begin << " to " << start_row + subtable.end << std::endl;
                            for(std::size_t k = subtable.begin; k <= subtable.end; k++){
                                selector_column[start_row + k] = FieldType::value_type::one();
                            }

                            std::string full_table_name = table->table_name + "/" + subtable_name;
                            bp_lookup_tables[lookup_table_ids.at(full_table_name) - 1] = plonk_lookup_table<FieldType>(subtable.column_indices.size(), cur_selector_id);
                            std::vector<plonk_variable<typename FieldType::value_type>> option;
                            for( const auto &column_index:subtable.column_indices ){
                                option.emplace_back( plonk_variable<typename FieldType::value_type>(
                                    constant_columns_ids[start_constant_column + column_index], 0,
                                    false, plonk_variable<typename FieldType::value_type>::column_type::constant
                                ) );
                            }
                            bp_lookup_tables[lookup_table_ids.at(full_table_name) - 1].append_option(option);

                            assignment.fill_selector(cur_selector_id, selector_column);
                            selector_ids[std::make_pair(subtable.begin, subtable.end)] = cur_selector_id;
                            selector_columns.push_back(std::move(selector_column));
                            // Create table declaration
                            cur_selector_id++;
                        }
                        start_row += table->get_rows_number();
                    }
                    for(std::size_t i = 0; i < bp_lookup_tables.size(); i++){
                        bp.add_lookup_table(std::move(bp_lookup_tables[i]));
                    }
                    for( std::size_t i = 0; i < constant_columns.size(); i++ ){
                        // for(std::size_t j = 0; j < 100; j++){
                        //     std::cout << constant_columns[i][j] << " ";
                        // }
                        // std::cout << std::endl;
                        assignment.fill_constant(constant_columns_ids[i], constant_columns[i]);
                    }
                    return usable_rows_after;
                }
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_DETAIL_LOOKUP_TABLE_HPP
