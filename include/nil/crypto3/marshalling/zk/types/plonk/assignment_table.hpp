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

#ifndef CRYPTO3_MARSHALLING_ZK_PLONK_ASSIGNMENT_TABLE_HPP
#define CRYPTO3_MARSHALLING_ZK_PLONK_ASSIGNMENT_TABLE_HPP

#include <type_traits>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase, typename PlonkTable>
                using plonk_assignment_table = nil::marshalling::types::bundle<
                    TTypeBase, std::tuple<
                        nil::marshalling::types::integral<TTypeBase, std::size_t>, // usable_rows
                        nil::marshalling::types::integral<TTypeBase, std::size_t>, // columns_number
                        // table_values
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            field_element<TTypeBase, typename PlonkTable::field_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >
                    >
                >;

                template<typename Endianness, typename PlonkTable>
                plonk_assignment_table<nil::marshalling::field_type<Endianness>, PlonkTable> fill_assignment_table(
                    std::size_t usable_rows,
                    const PlonkTable &assignments
                ){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using result_type = plonk_assignment_table<nil::marshalling::field_type<Endianness>, PlonkTable>;

                    std::vector<typename PlonkTable::field_type::value_type> table_values;
                    for( std::size_t i = 0; i < PlonkTable::arithmetization_params::witness_columns; i++ ){
                        for( std::size_t j = 0; j < assignments.rows_amount(); j++ ){
                            table_values.push_back(assignments.witness(i)[j]);
                        }
                    }
                    for( std::size_t i = 0; i < PlonkTable::arithmetization_params::public_input_columns; i++ ){
                        for( std::size_t j = 0; j < assignments.rows_amount(); j++ ){
                            table_values.push_back(assignments.public_input(i)[j]);
                        }
                    }
                    for( std::size_t i = 0; i < PlonkTable::arithmetization_params::constant_columns; i++ ){
                        for( std::size_t j = 0; j < assignments.rows_amount(); j++ ){
                            table_values.push_back(assignments.constant(i)[j]);
                        }
                    }
                    for( std::size_t i = 0; i < PlonkTable::arithmetization_params::selector_columns; i++ ){
                        for( std::size_t j = 0; j < assignments.rows_amount(); j++ ){
                            table_values.push_back(assignments.selector(i)[j]);
                        }
                    }
                    return result_type(std::make_tuple(
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(usable_rows),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(PlonkTable::arithmetization_params::total_columns),
                        fill_field_element_vector<typename PlonkTable::field_type::value_type, Endianness>(table_values)
                    ));
                }
                template<typename Endianness, typename PlonkTable>
                std::pair<std::size_t, PlonkTable> make_assignment_table(const plonk_assignment_table<nil::marshalling::field_type<Endianness>, PlonkTable> filled_assignments){
                    auto values = make_field_element_vector<typename PlonkTable::field_type::value_type, Endianness>(std::get<2>(filled_assignments.value()));
                    auto rows_amount = values.size()/PlonkTable::arithmetization_params::total_columns;
                    std::size_t usable_rows =  std::get<0>(filled_assignments.value()).value();

                    // Size correctness check.
                    if (PlonkTable::arithmetization_params::total_columns != std::get<1>(filled_assignments.value()).value() ||
                        values.size() % PlonkTable::arithmetization_params::total_columns != 0
                    )
                        throw std::invalid_argument(
                            "Invalid arithmetization params. Expected columns number = " +
                            std::to_string(PlonkTable::arithmetization_params::total_columns) +
                            ", real columns number = " +
                            std::to_string(std::get<1>(filled_assignments.value()).value()) + ".");

                    if ( usable_rows >= rows_amount )
                        throw std::invalid_argument(
                            "Rows amount should be greater than usable rows amount. Rows amount = " +
                            std::to_string(rows_amount) +
                            ", usable rows amount = " + std::to_string(usable_rows));

                    typename PlonkTable::witnesses_container_type witnesses;
                    std::size_t cur = 0;
                    for(std::size_t i = 0; i < PlonkTable::arithmetization_params::witness_columns; i++){
                        witnesses[i].resize(rows_amount);
                        for(std::size_t j = 0; j < rows_amount; j++, cur++){
                            witnesses[i][j] = values[cur];
                        }
                    }
                    typename PlonkTable::public_input_container_type public_inputs;
                    for(std::size_t i = 0; i < PlonkTable::arithmetization_params::public_input_columns; i++){
                        public_inputs[i].resize(rows_amount);
                        for(std::size_t j = 0; j < rows_amount; j++, cur++){
                            public_inputs[i][j] = values[cur];
                        }
                    }
                    typename PlonkTable::constant_container_type constants;
                    for(std::size_t i = 0; i < PlonkTable::arithmetization_params::constant_columns; i++){
                        constants[i].resize(rows_amount);
                        for(std::size_t j = 0; j < rows_amount; j++, cur++){
                            constants[i][j] = values[cur];
                        }
                    }
                    typename PlonkTable::selector_container_type selectors;
                    for(std::size_t i = 0; i < PlonkTable::arithmetization_params::selector_columns; i++){
                        selectors[i].resize(rows_amount);
                        for(std::size_t j = 0; j < rows_amount; j++, cur++){
                            selectors[i][j] = values[cur];
                        }
                    }
                    return std::make_pair( usable_rows, PlonkTable(
                        typename PlonkTable::private_table_type(witnesses),
                        typename PlonkTable::public_table_type(public_inputs, constants, selectors)
                    ));
                }
            } //namespace types
        } // namespace marshalling
    } // namespace crypto3
} // namespace nil

#endif
