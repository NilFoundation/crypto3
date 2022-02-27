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

#ifndef CRYPTO3_ZK_PLONK_REDSHIFT_TABLE_HPP
#define CRYPTO3_ZK_PLONK_REDSHIFT_TABLE_HPP

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                using plonk_column = std::vector<typename FieldType::value_type>;

                template<typename FieldType, typename PlonkParams, typename ColumnType>
                class plonk_private_table {

                    std::array<ColumnType, PlonkParams::witness_columns> witness_columns;

                public:
                    plonk_private_table(std::array<ColumnType, PlonkParams::witness_columns> witness_columns = {}) :
                        witness_columns(witness_columns) {
                    }

                    ColumnType witness(std::size_t index) const {
                        assert(index < PlonkParams::witness_columns);
                        return witness_columns[index];
                    }

                    std::array<ColumnType, PlonkParams::witness_columns> witnesses() const {
                        return witness_columns;
                    }

                    ColumnType operator[](std::size_t index) const {
                        if (index < PlonkParams::witness_columns)
                            return witness_columns[index];
                        index -= PlonkParams::witness_columns;
                    }

                    std::size_t size() const {
                        return witness_columns.size();
                    }
                };

                template<typename FieldType, typename PlonkParams, typename ColumnType>
                class plonk_public_table {

                    std::vector<ColumnType> selector_columns;
                    std::vector<ColumnType> public_input_columns;
                    std::vector<ColumnType> constant_columns;

                public:
                    plonk_public_table(std::vector<ColumnType> selector_columns = {},
                                       std::vector<ColumnType>
                                           public_input_columns = {},
                                       std::vector<ColumnType>
                                           constant_columns = {}) :
                        selector_columns(selector_columns),
                        public_input_columns(public_input_columns),
                        constant_columns() {
                    }

                    ColumnType selector(std::size_t index) const {
                        assert(index < selector_columns.size());
                        return selector_columns[index];
                    }

                    std::vector<ColumnType> selectors() const {
                        return selector_columns;
                    }

                    ColumnType public_input(std::size_t index) const {
                        assert(index < public_input_columns.size());
                        return public_input_columns[index];
                    }

                    std::vector<ColumnType> public_inputs() const {
                        return public_input_columns;
                    }

                    ColumnType constant(std::size_t index) const {
                        assert(index < constant_columns.size());
                        return constant_columns[index];
                    }

                    std::vector<ColumnType> constants() const {
                        return constant_columns;
                    }

                    ColumnType operator[](std::size_t index) const {
                        if (index < selector_columns.size())
                            return selector_columns[index];
                        index -= selector_columns.size();
                        if (index < public_input_columns.size())
                            return public_input_columns[index];
                        index -= public_input_columns.size();
                        if (index < constant_columns.size())
                            return constant_columns[index];
                        index -= constant_columns.size();
                    }

                    std::size_t size() const {
                        return selector_columns.size() + public_input_columns.size() + constant_columns.size();
                    }
                };

                template<typename FieldType, typename PlonkParams, typename ColumnType>
                struct plonk_table {

                    using private_table_type = plonk_private_table<FieldType, PlonkParams, ColumnType>;
                    using public_table_type = plonk_public_table<FieldType, PlonkParams, ColumnType>;

                private:
                    private_table_type _private_table;
                    public_table_type _public_table;

                public:
                    plonk_table(private_table_type private_table = private_table_type(), 
                                public_table_type public_table = public_table_type()) :
                        _private_table(private_table), _public_table(public_table) {
                    }

                    ColumnType witness(std::size_t index) const {
                        return _private_table.witness(index);
                    }

                    ColumnType selector(std::size_t index) const {
                        return _public_table.selector(index);
                    }

                    ColumnType public_input(std::size_t index) const {
                        return _public_table.public_input(index);
                    }

                    ColumnType constant(std::size_t index) const {
                        return _public_table.constant(index);
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

                template<typename FieldType, typename PlonkParams>
                using plonk_private_assignment_table =
                    plonk_private_table<FieldType, PlonkParams, plonk_column<FieldType>>;

                template<typename FieldType, typename PlonkParams>
                using plonk_public_assignment_table =
                    plonk_public_table<FieldType, PlonkParams, plonk_column<FieldType>>;

                template<typename FieldType, typename PlonkParams>
                using plonk_assignment_table = plonk_table<FieldType, PlonkParams, plonk_column<FieldType>>;

                template<typename FieldType, typename PlonkParams>
                using plonk_private_polynomial_table =
                    plonk_private_table<FieldType, PlonkParams, math::polynomial<typename FieldType::value_type>>;

                template<typename FieldType, typename PlonkParams>
                using plonk_public_polynomial_table =
                    plonk_public_table<FieldType, PlonkParams, math::polynomial<typename FieldType::value_type>>;

                template<typename FieldType, typename PlonkParams>
                using plonk_polynomial_table =
                    plonk_table<FieldType, PlonkParams, math::polynomial<typename FieldType::value_type>>;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_TABLE_HPP
