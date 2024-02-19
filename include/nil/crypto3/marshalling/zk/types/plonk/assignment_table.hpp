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
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase, typename PlonkTable>
                using plonk_assignment_table = nil::marshalling::types::bundle<
                    TTypeBase, std::tuple<
                        nil::marshalling::types::integral<TTypeBase, std::size_t>, // witness_amount
                        nil::marshalling::types::integral<TTypeBase, std::size_t>, // public_input_amount
                        nil::marshalling::types::integral<TTypeBase, std::size_t>, // constant_amount
                        nil::marshalling::types::integral<TTypeBase, std::size_t>, // selector_amount

                        nil::marshalling::types::integral<TTypeBase, std::size_t>, // usable_rows
                        nil::marshalling::types::integral<TTypeBase, std::size_t>, // rows_amount
                        // witnesses
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            field_element<TTypeBase, typename PlonkTable::field_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >,
                        // public_inputs
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            field_element<TTypeBase, typename PlonkTable::field_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >,
                        // constants
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            field_element<TTypeBase, typename PlonkTable::field_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >,
                        // selectors
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            field_element<TTypeBase, typename PlonkTable::field_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >
                    >
                >;

                template<typename FieldValueType, typename Endianness>
                nil::marshalling::types::array_list<
                    nil::marshalling::field_type<Endianness>,
                    field_element<nil::marshalling::field_type<Endianness>, FieldValueType>,
                    nil::marshalling::option::sequence_size_field_prefix<
                        nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>
                    fill_field_element_vector_from_columns_with_padding(
                        const std::vector<std::vector<FieldValueType>> &columns,
                        const std::size_t size,
                        const FieldValueType &padding) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using field_element_type = field_element<TTypeBase, FieldValueType>;
                    using field_element_vector_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        field_element_type,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<TTypeBase, std::size_t>>>;

                    field_element_vector_type result;
                    result.value().reserve(size * columns.size());
                    for (std::size_t column_number = 0; column_number < columns.size(); column_number++) {
                        for (std::size_t i = 0; i < columns[column_number].size(); i++) {
                            result.value().push_back(field_element_type(columns[column_number][i]));
                        }
                        for (std::size_t i = columns[column_number].size(); i < size; i++) {
                            result.value().push_back(field_element_type(padding));
                        }
                    }
                    return result;
                }

                template<typename FieldValueType, typename Endianness>
                std::vector<std::vector<FieldValueType>> make_field_element_columns_vector(
                    const nil::marshalling::types::array_list<
                        nil::marshalling::field_type<Endianness>,
                        field_element<nil::marshalling::field_type<Endianness>, FieldValueType>,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>
                        &field_elem_vector,
                    const std::size_t columns_amount,
                    const std::size_t rows_amount) {

                    std::vector<std::vector<FieldValueType>> result(
                        columns_amount, std::vector<FieldValueType>(rows_amount));
                    BOOST_ASSERT(field_elem_vector.value().size() == columns_amount * rows_amount);
                    std::size_t cur = 0;
                    for (std::size_t i = 0; i < columns_amount; i++) {
                        for (std::size_t j = 0; j < rows_amount; j++, cur++) {
                            result[i][j] = field_elem_vector.value()[cur].value();
                        }
                    }
                    return result;
                }

                template<typename Endianness, typename PlonkTable>
                plonk_assignment_table<nil::marshalling::field_type<Endianness>, PlonkTable> fill_assignment_table(
                    std::size_t usable_rows,
                    const PlonkTable &assignments
                ){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using result_type = plonk_assignment_table<nil::marshalling::field_type<Endianness>, PlonkTable>;
                    using value_type = typename PlonkTable::field_type::value_type;

                    return result_type(std::move(std::make_tuple(
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(assignments.witnesses_amount()),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(assignments.public_inputs_amount()),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(assignments.constants_amount()),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(assignments.selectors_amount()),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(usable_rows),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(assignments.rows_amount()),
                        fill_field_element_vector_from_columns_with_padding<value_type, Endianness>(
                            assignments.witnesses(),
                            assignments.rows_amount(),
                            0
                        ),
                        fill_field_element_vector_from_columns_with_padding<value_type, Endianness>(
                            assignments.public_inputs(),
                            assignments.rows_amount(),
                            0
                        ),
                        fill_field_element_vector_from_columns_with_padding<value_type, Endianness>(
                            assignments.constants(),
                            assignments.rows_amount(),
                            0
                        ),
                        fill_field_element_vector_from_columns_with_padding<value_type, Endianness>(
                            assignments.selectors(),
                            assignments.rows_amount(),
                            0
                        )
                    )));
                }
                template<typename Endianness, typename PlonkTable>
                std::pair<zk::snark::plonk_table_description<typename PlonkTable::field_type>, PlonkTable> make_assignment_table(
                        const plonk_assignment_table<nil::marshalling::field_type<Endianness>, PlonkTable> &filled_assignments){

                    using value_type = typename PlonkTable::field_type::value_type;

                    zk::snark::plonk_table_description<typename PlonkTable::field_type> desc(
                        std::get<0>(filled_assignments.value()).value(),
                        std::get<1>(filled_assignments.value()).value(),
                        std::get<2>(filled_assignments.value()).value(),
                        std::get<3>(filled_assignments.value()).value(),
                        std::get<4>(filled_assignments.value()).value(),
                        std::get<5>(filled_assignments.value()).value()
                    );

                    if ( desc.usable_rows_amount >= desc.rows_amount )
                        throw std::invalid_argument(
                            "Rows amount should be greater than usable rows amount. Rows amount = " +
                            std::to_string(desc.rows_amount) +
                            ", usable rows amount = " + std::to_string(desc.usable_rows_amount));

                    std::vector<std::vector<value_type>> witnesses =
                        make_field_element_columns_vector<value_type, Endianness>(
                            std::get<6>(filled_assignments.value()),
                            desc.witness_columns,
                            desc.rows_amount
                        );
                    std::vector<std::vector<value_type>> public_inputs =
                        make_field_element_columns_vector<value_type, Endianness>(
                            std::get<7>(filled_assignments.value()),
                            desc.public_input_columns,
                            desc.rows_amount
                        );
                    std::vector<std::vector<value_type>> constants =
                        make_field_element_columns_vector<value_type, Endianness>(
                            std::get<8>(filled_assignments.value()),
                            desc.constant_columns,
                            desc.rows_amount
                        );
                    std::vector<std::vector<value_type>> selectors =
                        make_field_element_columns_vector<value_type, Endianness>(
                            std::get<9>(filled_assignments.value()),
                            desc.selector_columns,
                            desc.rows_amount
                        );

                    return std::make_pair(desc, PlonkTable(
                        typename PlonkTable::private_table_type(witnesses),
                        typename PlonkTable::public_table_type(public_inputs, constants, selectors)
                    ));
                }
            } //namespace types
        } // namespace marshalling
    } // namespace crypto3
} // namespace nil

#endif
