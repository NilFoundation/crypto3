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

                    using witnesses_container_type = std::array<ColumnType, ArithmetizationParams::WitnessColumns>;

                protected:

                    witnesses_container_type _witness;

                public:
                    plonk_private_table(
                        witnesses_container_type witness_columns = {}) :
                        _witness(witness_columns) {
                    }

                    constexpr std::size_t witness_size() {
                        return _witness.size();
                    }

                    ColumnType witness(std::uint32_t index) const {
                        assert(index < ArithmetizationParams::WitnessColumns);
                        return _witness[index];
                    }

                    witnesses_container_type witnesses() const {
                        return _witness;
                    }

                    ColumnType operator[](std::uint32_t index) const {
                        if (index < ArithmetizationParams::WitnessColumns)
                            return _witness[index];
                        index -= ArithmetizationParams::WitnessColumns;
                    }

                    constexpr std::size_t size() const {
                        return _witness.size();
                    }
                };

                template<typename FieldType, typename ArithmetizationParams, typename ColumnType>
                struct plonk_public_table {

                    using public_input_container_type = std::array<ColumnType, ArithmetizationParams::PublicInputColumns>;
                    using constant_container_type = std::array<ColumnType, ArithmetizationParams::ConstantColumns>;
                    using selector_container_type = std::array<ColumnType, ArithmetizationParams::SelectorColumns>;

                protected:

                    public_input_container_type _public_inputs;
                    constant_container_type _constants;
                    selector_container_type _selectors;

                public:
                    plonk_public_table(
                        public_input_container_type public_input_columns = {},
                        constant_container_type constant_columns = {},
                        selector_container_type selector_columns = {}) :
                        _public_inputs(public_input_columns),
                        _constants(constant_columns),
                        _selectors(selector_columns) {
                    }

                    constexpr std::size_t public_input_size() {
                        return _public_inputs.size();
                    }

                    ColumnType public_input(std::uint32_t index) const {
                        assert(index < public_input_size());
                        return _public_inputs[index];
                    }

                    public_input_container_type public_inputs() const {
                        return _public_inputs;
                    }

                    constexpr std::size_t constant_size() {
                        return _constants.size();
                    }

                    ColumnType constant(std::uint32_t index) const {
                        assert(index < constant_size());
                        return _constants[index];
                    }

                    constant_container_type constants() const {
                        return _constants;
                    }

                    constexpr std::size_t selector_size() {
                        return _selectors.size();
                    }

                    ColumnType selector(std::uint32_t index) const {
                        assert(index < selector_size());
                        return _selectors[index];
                    }

                    selector_container_type selectors() const {
                        return _selectors;
                    }

                    ColumnType operator[](std::uint32_t index) const {
                        if (index < public_input_size())
                            return public_input(index);
                        index -= public_input_size();
                        if (index < constant_size())
                            return constant(index);
                        index -= constant_size();
                        if (index < selector_size()) {
                            return selector(index);
                        }
                        index -= selector_size();
                    }

                    constexpr std::size_t size() const {
                        return public_input_size() +
                               constant_size() +
                               selector_size();
                    }
                };

                template<typename FieldType, typename ArithmetizationParams, typename ColumnType>
                struct plonk_table {

                    using private_table_type = plonk_private_table<FieldType,
                        ArithmetizationParams, ColumnType>;
                    using public_table_type = plonk_public_table<FieldType,
                        ArithmetizationParams, ColumnType>;

                protected:

                    private_table_type _private_table;
                    public_table_type _public_table;

                public:
                    plonk_table(private_table_type private_table = private_table_type(), 
                                public_table_type public_table = public_table_type()) :
                        _private_table(private_table), _public_table(public_table) {
                    }

                    ColumnType witness(std::uint32_t index) const {
                        return _private_table.witness(index);
                    }

                    ColumnType public_input(std::uint32_t index) const {
                        return _public_table.public_input(index);
                    }

                    ColumnType constant(std::uint32_t index) const {
                        return _public_table.constant(index);
                    }

                    ColumnType selector(std::uint32_t index) const {
                        return _public_table.selector(index);
                    }

                    ColumnType operator[](std::uint32_t index) const {
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
                    plonk_public_table<FieldType, ArithmetizationParams,
                        plonk_column<FieldType>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_assignment_table = plonk_table<FieldType, ArithmetizationParams,
                        plonk_column<FieldType>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_private_polynomial_table =
                    plonk_private_table<FieldType, ArithmetizationParams,
                        math::polynomial<typename FieldType::value_type>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_public_polynomial_table =
                    plonk_public_table<FieldType, ArithmetizationParams,
                        math::polynomial<typename FieldType::value_type>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_polynomial_table =
                    plonk_table<FieldType, ArithmetizationParams,
                        math::polynomial<typename FieldType::value_type>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_private_polynomial_dfs_table =
                    plonk_private_table<FieldType, ArithmetizationParams,
                        math::polynomial_dfs<typename FieldType::value_type>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_public_polynomial_dfs_table =
                    plonk_public_table<FieldType, ArithmetizationParams,
                        math::polynomial_dfs<typename FieldType::value_type>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_polynomial_dfs_table =
                    plonk_table<FieldType, ArithmetizationParams,
                        math::polynomial_dfs<typename FieldType::value_type>>;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_TABLE_HPP
