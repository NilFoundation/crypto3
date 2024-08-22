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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_TABLE_DESCRIPTION_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_TABLE_DESCRIPTION_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <iostream>
#include <limits>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                // TODO(martun): this class actually does not depend on the FieldType.
                template<typename FieldType>
                struct plonk_table_description {
                    // Needed for marshalling.
                    using field_type = FieldType;

                    std::size_t witness_columns;
                    std::size_t public_input_columns;
                    std::size_t constant_columns;
                    std::size_t selector_columns;

                    std::size_t usable_rows_amount = 0;
                    std::size_t rows_amount = 0;

                    plonk_table_description(const std::size_t witness_columns,
                                            const std::size_t public_input_columns,
                                            const std::size_t constant_columns,
                                            const std::size_t selector_columns) :
                        witness_columns(witness_columns), public_input_columns(public_input_columns),
                        constant_columns(constant_columns), selector_columns(selector_columns)
                    {}

                    plonk_table_description(const std::size_t witness_columns,
                                            const std::size_t public_input_columns,
                                            const std::size_t constant_columns,
                                            const std::size_t selector_columns,
                                            const std::size_t usable_rows_amount,
                                            const std::size_t rows_amount) :
                        witness_columns(witness_columns), public_input_columns(public_input_columns),
                        constant_columns(constant_columns), selector_columns(selector_columns),
                        usable_rows_amount(usable_rows_amount), rows_amount(rows_amount)
                    {}

                    std::size_t global_index(const plonk_variable<typename FieldType::value_type> &a) const {
                        switch (a.type) {
                            case plonk_variable<typename FieldType::value_type>::column_type::witness:
                                return a.index;
                            case plonk_variable<typename FieldType::value_type>::column_type::public_input:
                                return witness_columns + a.index;
                            case plonk_variable<typename FieldType::value_type>::column_type::constant:
                                return witness_columns + public_input_columns + a.index;
                            case plonk_variable<typename FieldType::value_type>::column_type::selector:
                                return witness_columns + public_input_columns + constant_columns + a.index;
                            default:
                                std::cerr << "Invalid column type";
                                std::abort();
                                break;
                        }
                        /* unreachable*/
                        return std::numeric_limits<size_t>::max();
                    }

                    std::size_t table_width() const {
                        return witness_columns + public_input_columns + constant_columns + selector_columns;
                    }

                    bool operator==(const plonk_table_description &rhs) const {
                        return
                            rows_amount == rhs.rows_amount &&
                            usable_rows_amount == rhs.usable_rows_amount &&
                            witness_columns == rhs.witness_columns &&
                            public_input_columns == rhs.public_input_columns &&
                            constant_columns == rhs.constant_columns &&
                            selector_columns == rhs.selector_columns;
                    }
                    bool operator!=(const plonk_table_description &rhs) const {
                        return !(rhs == *this);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_TABLE_DESCRIPTION_HPP
