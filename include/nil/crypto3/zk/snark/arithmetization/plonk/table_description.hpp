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

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename ArithmetizationParams>
                struct plonk_table_description {
                    constexpr static const std::size_t witness_columns = ArithmetizationParams::witness_columns;
                    constexpr static const std::size_t public_input_columns = ArithmetizationParams::public_input_columns;
                    constexpr static const std::size_t constant_columns = ArithmetizationParams::constant_columns;
                    constexpr static const std::size_t selector_columns = ArithmetizationParams::selector_columns;

                    std::size_t rows_amount = 0;
                    std::size_t usable_rows_amount = 0;

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
                        }
                    }

                    std::size_t table_width() const {
                        return witness_columns + public_input_columns + constant_columns + selector_columns;
                    }
                };

#ifdef ZK_RUNTIME_CIRCUIT_DEFINITION
                template<typename FieldType>
                struct plonk_table_description {
                    std::size_t witness_columns;
                    std::size_t public_input_columns;
                    std::size_t constant_columns;
                    std::size_t selector_columns;

                    std::size_t rows_amount = 0;
                    std::size_t usable_rows_amount = 0;

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
                        }
                    }

                    std::size_t table_width() const {
                        return witness_columns + public_input_columns + constant_columns + selector_columns;
                    }
                };
#endif
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_TABLE_DESCRIPTION_HPP
