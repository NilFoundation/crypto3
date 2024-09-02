//---------------------------------------------------------------------------//
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_ZK_PLONK_LOOKUP_TABLE_HPP
#define CRYPTO3_MARSHALLING_ZK_PLONK_LOOKUP_TABLE_HPP

#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/zk/types/plonk/variable.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/lookup_constraint.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase, typename LookupTable>
                using plonk_lookup_table = nil::marshalling::types::bundle<
                    TTypeBase, std::tuple<
                        nil::marshalling::types::integral<TTypeBase, std::size_t>, // tag_index
                        nil::marshalling::types::integral<TTypeBase, std::size_t>, // columns_number

                        nil::marshalling::types::array_list<
                            TTypeBase,
                            typename variable<TTypeBase, typename LookupTable::variable_type>::type,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >
                    >
                >;

                template<typename Endianness, typename LookupTable>
                plonk_lookup_table<nil::marshalling::field_type<Endianness>, LookupTable>
                fill_plonk_lookup_table(const LookupTable &table){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using variable_type = typename LookupTable::variable_type;

                    nil::marshalling::types::array_list<
                        TTypeBase,
                        typename variable<TTypeBase, typename LookupTable::variable_type>::type,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_options;

                    for( std::size_t i = 0; i < table.lookup_options.size(); i++ ){
                        BOOST_ASSERT(table.lookup_options[i].size() == table.columns_number);
                        for( std::size_t j = 0; j < table.lookup_options[i].size(); j++){
                            filled_options.value().push_back(
                                fill_variable<Endianness, variable_type>(table.lookup_options[i][j])
                            );
                        }
                    }
                    return plonk_lookup_table<TTypeBase, LookupTable>(
                        std::make_tuple(
                            nil::marshalling::types::integral<TTypeBase, std::size_t>(table.tag_index),
                            nil::marshalling::types::integral<TTypeBase, std::size_t>(table.columns_number),
                            filled_options
                        )
                    );
                }

                template<typename Endianness, typename LookupTable>
                LookupTable make_plonk_lookup_table(
                    const plonk_lookup_table<nil::marshalling::field_type<Endianness>, LookupTable> &filled_table
                ) {
                    std::size_t tag_index = std::get<0>(filled_table.value()).value();
                    std::size_t columns_number = std::get<1>(filled_table.value()).value();
                    LookupTable result(columns_number, tag_index);

                    std::size_t op_n = std::get<2>(filled_table.value()).value().size() / columns_number;
                    BOOST_ASSERT(std::get<2>(filled_table.value()).value().size() % columns_number == 0);

                    std::size_t cur = 0;
                    for (std::size_t i = 0; i < op_n; i++) {
                        std::vector<typename LookupTable::variable_type> row;
                        for( std::size_t j = 0; j < columns_number; j++, cur++ ){
                            row.emplace_back(
                                make_variable<Endianness, typename LookupTable::variable_type>(
                                    std::get<2>(filled_table.value()).value().at(cur)
                                )
                            );
                        }
                        result.append_option(row);
                    }
                    return result;
                }

                template<typename TTypeBase, typename PlonkTable>
                using plonk_lookup_tables =
                    nil::marshalling::types::array_list<
                        TTypeBase, plonk_lookup_table<TTypeBase, PlonkTable>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    >;

                template<typename Endianness, typename PlonkTable, typename InputRange>
                plonk_lookup_tables<nil::marshalling::field_type<Endianness>, PlonkTable>
                    fill_plonk_lookup_tables(const InputRange &tables) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using result_type = nil::marshalling::types::array_list<
                        TTypeBase, plonk_lookup_table<TTypeBase, PlonkTable>,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<TTypeBase, std::size_t>>>;

                    result_type filled_tables;
                    for (const auto &table : tables) {
                        filled_tables.value().push_back(fill_plonk_lookup_table<Endianness, PlonkTable>(table));
                    }

                    return filled_tables;
                }

                template<typename Endianness, typename PlonkTable>
                std::vector<PlonkTable> make_plonk_lookup_tables(
                    const plonk_lookup_tables<nil::marshalling::field_type<Endianness>, PlonkTable> &filled_tables) {
                    std::vector<PlonkTable> tables;
                    for (std::size_t i = 0; i < filled_tables.value().size(); i++) {
                        tables.emplace_back(make_plonk_lookup_table<Endianness, PlonkTable>(filled_tables.value().at(i)));
                    }
                    return tables;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_ZK_PLONK_LOOKUP_TABLE_HPP
