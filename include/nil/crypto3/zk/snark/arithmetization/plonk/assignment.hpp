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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_TABLE_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_TABLE_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                using plonk_column = std::vector<typename FieldType::value_type>;

                template<typename FieldType, typename ArithmetizationParams, typename ColumnType>
                struct plonk_private_table {

                protected:
                    std::array<ColumnType, ArithmetizationParams::witness_columns> witness_columns;

                public:
                    plonk_private_table(
                        std::array<ColumnType, ArithmetizationParams::witness_columns> witness_columns = {}) :
                        witness_columns(witness_columns) {
                    }

                    ColumnType witness(std::size_t index) const {
                        BOOST_ASSERT(index < ArithmetizationParams::witness_columns);

                        return witness_columns[index];
                    }

                    std::array<ColumnType, ArithmetizationParams::witness_columns> witnesses() const {
                        return witness_columns;
                    }

                    ColumnType operator[](std::size_t index) const {
                        if (index < ArithmetizationParams::witness_columns)
                            return witness_columns[index];
                        index -= ArithmetizationParams::witness_columns;
                    }

                    constexpr std::size_t size() const {
                        return witness_columns.size();
                    }
                };

                template<typename FieldType, typename ArithmetizationParams, typename ColumnType>
                struct plonk_public_table {

                protected:
                    std::array<ColumnType, ArithmetizationParams::public_input_columns> public_input_columns;
                    std::array<ColumnType, ArithmetizationParams::constant_columns> constant_columns;
                    std::array<ColumnType, ArithmetizationParams::selector_columns> selector_columns;

                public:
                    plonk_public_table(
                        std::array<ColumnType, ArithmetizationParams::public_input_columns> public_input_columns = {},
                        std::array<ColumnType, ArithmetizationParams::constant_columns> constant_columns = {},
                        std::array<ColumnType, ArithmetizationParams::selector_columns> selector_columns = {}) :
                        public_input_columns(public_input_columns),
                        constant_columns(constant_columns), selector_columns(selector_columns) {
                    }

                    ColumnType public_input(std::size_t index) const {
                        BOOST_ASSERT(index < ArithmetizationParams::public_input_columns);

                        return public_input_columns[index];
                    }

                    std::array<ColumnType, ArithmetizationParams::public_input_columns> public_inputs() const {
                        return public_input_columns;
                    }

                    std::size_t public_input_size() {
                        return public_input_columns.size();
                    }

                    ColumnType constant(std::size_t index) const {
                        BOOST_ASSERT(index < ArithmetizationParams::constant_columns);

                        return constant_columns[index];
                    }

                    std::array<ColumnType, ArithmetizationParams::constant_columns> constants() const {
                        return constant_columns;
                    }

                    std::size_t constant_size() {
                        return constant_columns.size();
                    }

                    ColumnType selector(std::size_t index) const {
                        BOOST_ASSERT(index < ArithmetizationParams::selector_columns);

                        return selector_columns[index];
                    }

                    std::array<ColumnType, ArithmetizationParams::selector_columns> selectors() const {
                        return selector_columns;
                    }

                    std::size_t selectors_size() {
                        return selector_columns.size();
                    }

                    ColumnType operator[](std::size_t index) const {
                        if (index < ArithmetizationParams::public_input_columns)
                            return public_input_columns[index];
                        index -= ArithmetizationParams::public_input_columns;
                        if (index < ArithmetizationParams::constant_columns)
                            return constant_columns[index];
                        index -= ArithmetizationParams::constant_columns;
                        if (index < ArithmetizationParams::selector_columns) {
                            return selector_columns[index];
                        }
                        index -= ArithmetizationParams::selector_columns;
                    }

                    constexpr std::size_t size() const {
                        return ArithmetizationParams::public_input_columns + ArithmetizationParams::constant_columns +
                               ArithmetizationParams::selector_columns;
                    }
                };

                template<typename FieldType, typename ArithmetizationParams, typename ColumnType>
                struct plonk_table {

                    using private_table_type = plonk_private_table<FieldType, ArithmetizationParams, ColumnType>;
                    using public_table_type = plonk_public_table<FieldType, ArithmetizationParams, ColumnType>;

                protected:
                    private_table_type _private_table;
                    public_table_type _public_table;

                public:
                    plonk_table(private_table_type private_table = private_table_type(),
                                public_table_type public_table = public_table_type()) :
                        _private_table(private_table),
                        _public_table(public_table) {
                    }

                    ColumnType witness(std::size_t index) const {
                        return _private_table.witness(index);
                    }

                    ColumnType public_input(std::size_t index) const {
                        return _public_table.public_input(index);
                    }

                    ColumnType constant(std::size_t index) const {
                        return _public_table.constant(index);
                    }

                    ColumnType selector(std::size_t index) const {
                        return _public_table.selector(index);
                    }

                    ColumnType operator[](std::size_t index) const {
                        if (index < _private_table.size())
                            return _private_table[index];
                        index -= _private_table.size();
                        if (index < _public_table.size())
                            return _public_table[index];
                    }

                    private_table_type private_table() const {
                        return _private_table;
                    }

                    public_table_type public_table() const {
                        return _public_table;
                    }

                    std::size_t size() const {
                        return _private_table.size() + _public_table.size();
                    }
                };

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_private_assignment_table =
                    plonk_private_table<FieldType, ArithmetizationParams, plonk_column<FieldType>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_public_assignment_table =
                    plonk_public_table<FieldType, ArithmetizationParams, plonk_column<FieldType>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_assignment_table = plonk_table<FieldType, ArithmetizationParams, plonk_column<FieldType>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_private_polynomial_table =
                    plonk_private_table<FieldType,
                                        ArithmetizationParams,
                                        math::polynomial<typename FieldType::value_type>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_public_polynomial_table =
                    plonk_public_table<FieldType,
                                       ArithmetizationParams,
                                       math::polynomial<typename FieldType::value_type>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_polynomial_table =
                    plonk_table<FieldType, ArithmetizationParams, math::polynomial<typename FieldType::value_type>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_private_polynomial_dfs_table =
                    plonk_private_table<FieldType,
                                        ArithmetizationParams,
                                        math::polynomial_dfs<typename FieldType::value_type>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_public_polynomial_dfs_table =
                    plonk_public_table<FieldType,
                                       ArithmetizationParams,
                                       math::polynomial_dfs<typename FieldType::value_type>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_polynomial_dfs_table =
                    plonk_table<FieldType, ArithmetizationParams, math::polynomial_dfs<typename FieldType::value_type>>;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_TABLE_HPP
