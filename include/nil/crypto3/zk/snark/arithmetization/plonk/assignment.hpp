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

#include <algorithm>

#include <nil/crypto3/zk/snark/arithmetization/plonk/padding.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>

namespace nil {
    namespace blueprint {
        template<typename ArithmetizationType>
        class assignment;
    } // namespace blueprint
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                struct plonk_constraint_system;

                template<typename FieldType>
                using plonk_column = std::vector<typename FieldType::value_type>;

                template<typename FieldType, typename ColumnType>
                class plonk_table;

                template<typename FieldType, typename ColumnType>
                class plonk_private_table {
                public:
                    using witnesses_container_type = std::vector<ColumnType>;

                protected:

                    witnesses_container_type _witnesses;

                public:
                    plonk_private_table(
                        witnesses_container_type witness_columns = {}) :
                        _witnesses(std::move(witness_columns)) {
                    }

                    plonk_private_table(std::size_t witnesses_amount) :
                        _witnesses(witnesses_amount) {
                    }

                    void resize_witnesses(std::uint32_t new_size) {
                        _witnesses.resize(new_size);
                    }

                    std::uint32_t witnesses_amount() const {
                        return _witnesses.size();
                    }

                    std::uint32_t witness_column_size(std::uint32_t index) const {
                        return _witnesses[index].size();
                    }

                    const ColumnType& witness(std::uint32_t index) const {
                        assert(index < _witnesses.size());
                        return _witnesses[index];
                    }

                    const witnesses_container_type& witnesses() const {
                        return _witnesses;
                    }

                    witnesses_container_type move_witnesses() {
                        return std::move(_witnesses);
                    }

                    const ColumnType& operator[](std::uint32_t index) const {
                        if (index < _witnesses.size())
                            return _witnesses[index];
                        throw std::out_of_range("Public table index out of range.");
                    }

                    constexpr std::uint32_t size() const {
                        return witnesses_amount();
                    }

                    bool operator==(plonk_private_table<FieldType, ColumnType> const &other) const {
                        return _witnesses == other._witnesses;
                    }

                    friend std::uint32_t basic_padding<FieldType, ColumnType>(
                        plonk_table<FieldType, ColumnType> &table);

                    friend std::uint32_t zk_padding<FieldType, ColumnType>(
                        plonk_table<FieldType, ColumnType> &table,
                        typename nil::crypto3::random::algebraic_engine<FieldType> alg_rnd
                    );

                    friend class nil::blueprint::assignment<plonk_constraint_system<FieldType>>;
                };

                template<typename FieldType, typename ColumnType>
                class plonk_public_table {
                public:
                    using public_input_container_type = std::vector<ColumnType>;
                    using constant_container_type = std::vector<ColumnType>;
                    using selector_container_type = std::vector<ColumnType>;

                protected:

                    public_input_container_type _public_inputs;
                    constant_container_type _constants;
                    selector_container_type _selectors;

                public:
                    plonk_public_table(
                        public_input_container_type public_input_columns = {},
                        constant_container_type constant_columns = {},
                        selector_container_type selector_columns = {})
                            : _public_inputs(std::move(public_input_columns))
                            , _constants(std::move(constant_columns))
                            , _selectors(std::move(selector_columns)) {
                    }

                    plonk_public_table(std::size_t public_inputs_amount,
                                       std::size_t constants_amount,
                                       std::size_t selectors_amount)
                        : _public_inputs(public_inputs_amount)
                        , _constants(constants_amount)
                        , _selectors(selectors_amount) {
                    }

                    std::uint32_t public_inputs_amount() const {
                        return _public_inputs.size();
                    }

                    void resize_public_inputs(std::uint32_t new_size) {
                        _public_inputs.resize(new_size);
                    }

                    std::uint32_t public_input_column_size(std::uint32_t index) const {
                        return _public_inputs[index].size();
                    }

                    const ColumnType& public_input(std::uint32_t index) const {
                        assert(index < public_inputs_amount());
                        return _public_inputs[index];
                    }

                    const public_input_container_type& public_inputs() const {
                        return _public_inputs;
                    }

                    public_input_container_type move_public_inputs() {
                        return std::move(_public_inputs);
                    }

                    std::uint32_t constants_amount() const {
                        return _constants.size();
                    }

                    void resize_constants(std::uint32_t new_size) {
                        _constants.resize(new_size);
                    }

                    std::uint32_t constant_column_size(std::uint32_t index) const {
                        return _constants[index].size();
                    }

                    const ColumnType& constant(std::uint32_t index) const {
                        assert(index < constants_amount());
                        return _constants[index];
                    }

                    const constant_container_type& constants() const {
                        return _constants;
                    }

                    constant_container_type move_constants() {
                        return std::move(_constants);
                    }

                    constexpr std::uint32_t selectors_amount() const {
                        return _selectors.size();
                    }

                    void resize_selectors(std::uint32_t new_size) {
                        _selectors.resize(new_size);
                    }

                    std::uint32_t selector_column_size(std::uint32_t index) const {
                        return _selectors[index].size();
                    }

                    const ColumnType& selector(std::uint32_t index) const {
                        assert(index < selectors_amount());
                        return _selectors[index];
                    }

                    const selector_container_type& selectors() const {
                        return _selectors;
                    }

                    selector_container_type move_selectors() {

                        return std::move(_selectors);
                    }

                    void fill_constant(std::uint32_t index, const ColumnType& column) {
                        BOOST_ASSERT(index < constants_amount());
                        BOOST_ASSERT(_constants[index].size() == 0);

                        _constants[index] = column;
                    }

                    void fill_selector(std::uint32_t index, const ColumnType& column) {
                        BOOST_ASSERT(index < selectors_amount());
                        BOOST_ASSERT(_selectors[index].size() == 0);

                        _selectors[index] = column;
                    }

                    const ColumnType& operator[](std::uint32_t index) const {
                        if (index < public_inputs_amount())
                            return public_input(index);
                        index -= public_inputs_amount();
                        if (index < constants_amount())
                            return constant(index);
                        index -= constants_amount();
                        if (index < selectors_amount()) {
                            return selector(index);
                        }
                        throw std::out_of_range("Public table index out of range.");
                    }

                    constexpr std::uint32_t size() const {
                        return public_inputs_amount() + constants_amount() + selectors_amount();
                    }

                    bool operator==(plonk_public_table<FieldType, ColumnType> const &other) const {
                        return _public_inputs == other._public_inputs &&
                               _constants == other._constants &&
                               _selectors == other._selectors;
                    }

                    friend std::uint32_t basic_padding<FieldType, ColumnType>(
                        plonk_table<FieldType, ColumnType> &table);

                    friend std::uint32_t zk_padding<FieldType, ColumnType>(
                        plonk_table<FieldType, ColumnType> &table,
                        typename nil::crypto3::random::algebraic_engine<FieldType> alg_rnd
                    );

                    friend class nil::blueprint::assignment<plonk_constraint_system<FieldType>>;
                };

                template<typename FieldType, typename ColumnType>
                class plonk_table {
                public:
                    using field_type = FieldType;
                    using column_type = ColumnType;
                    using private_table_type = plonk_private_table<FieldType, ColumnType>;
                    using public_table_type = plonk_public_table<FieldType, ColumnType>;
                    using witnesses_container_type = typename private_table_type::witnesses_container_type;
                    using public_input_container_type = typename public_table_type::public_input_container_type;
                    using constant_container_type = typename public_table_type::constant_container_type;
                    using selector_container_type = typename public_table_type::selector_container_type;

                protected:
                    // These are normally created by the assigner, or read from a file.
                    private_table_type _private_table;
                    public_table_type _public_table;

                public:
                    virtual ~plonk_table() = default;

                    plonk_table(private_table_type private_table = {},
                                public_table_type public_table = {})
                        : _private_table(std::move(private_table))
                        , _public_table(std::move(public_table)) {
                    }

                    plonk_table(std::size_t witnesses_amount,
                                std::size_t public_inputs_amount,
                                std::size_t constants_amount,
                                std::size_t selectors_amount)
                        : _private_table(witnesses_amount)
                        , _public_table(public_inputs_amount, constants_amount, selectors_amount) {
                    }

                    const ColumnType& witness(std::uint32_t index) const {
                        return _private_table.witness(index);
                    }

                    const ColumnType& public_input(std::uint32_t index) const {
                        return _public_table.public_input(index);
                    }

                    const ColumnType& constant(std::uint32_t index) const {
                        return _public_table.constant(index);
                    }

                    const ColumnType& selector(std::uint32_t index) const {
                        return _public_table.selector(index);
                    }

                    virtual void fill_constant(std::uint32_t index, const ColumnType& column) {
                        _public_table.fill_constant(index, column);
                    }

                    virtual void fill_selector(std::uint32_t index, const ColumnType& column) {
                        _public_table.fill_selector(index, column);
                    }

                    const witnesses_container_type& witnesses() const {
                        return _private_table.witnesses();
                    }

                    const public_input_container_type& public_inputs() const {
                        return _public_table.public_inputs();
                    }

                    const constant_container_type& constants() const {
                        return _public_table.constants();
                    }

                    const selector_container_type& selectors() const {
                        return _public_table.selectors();
                    }

                    virtual void resize_witnesses(std::uint32_t new_size) {
                        _private_table.resize_witnesses(new_size);
                    }

                    virtual void resize_public_inputs(std::uint32_t new_size) {
                        _public_table.resize_public_inputs(new_size);
                    }

                    virtual void resize_constants(std::uint32_t new_size) {
                        _public_table.resize_constants(new_size);
                    }

                    virtual void resize_selectors(std::uint32_t new_size) {
                        _public_table.resize_selectors(new_size);
                    }

                    const ColumnType& operator[](std::uint32_t index) const {
                        if (index < _private_table.size())
                            return _private_table[index];
                        index -= _private_table.size();
                        if (index < _public_table.size())
                            return _public_table[index];
                        throw std::out_of_range("Private table index out of range.");
                    }

                    const private_table_type& private_table() const {
                        return _private_table;
                    }

                    private_table_type move_private_table() {
                        return std::move(_private_table);
                    }

                    const public_table_type& public_table() const {
                        return _public_table;
                    }

                    public_table_type move_public_table() {
                        return std::move(_public_table);
                    }

                    std::uint32_t size() const {
                        return _private_table.size() + _public_table.size();
                    }

                    std::uint32_t witnesses_amount() const {
                        return _private_table.witnesses_amount();
                    }

                    std::uint32_t witness_column_size(std::uint32_t index) const {
                        return _private_table.witness_column_size(index);
                    }

                    std::uint32_t public_inputs_amount() const {
                        return _public_table.public_inputs_amount();
                    }

                    std::uint32_t public_input_column_size(std::uint32_t index) const {
                        return _public_table.public_input_column_size(index);
                    }

                    std::uint32_t constants_amount() const {
                        return _public_table.constants_amount();
                    }

                    std::uint32_t constant_column_size(std::uint32_t index) const {
                        return _public_table.constant_column_size(index);
                    }

                    std::uint32_t selectors_amount() const {
                        return _public_table.selectors_amount();
                    }

                    std::uint32_t selector_column_size(std::uint32_t index) const {
                        return _public_table.selector_column_size(index);
                    }

                    std::uint32_t rows_amount() const {
                        std::uint32_t rows_amount = 0;

                        for (std::uint32_t w_index = 0; w_index <
                                                       witnesses_amount(); w_index++) {
                            rows_amount = std::max(rows_amount, witness_column_size(w_index));
                        }

                        for (std::uint32_t pi_index = 0; pi_index <
                                                       public_inputs_amount(); pi_index++) {
                            rows_amount = std::max(rows_amount, public_input_column_size(pi_index));
                        }

                        for (std::uint32_t c_index = 0; c_index <
                                                      constants_amount(); c_index++) {
                            rows_amount = std::max(rows_amount, constant_column_size(c_index));
                        }

                        for (std::uint32_t s_index = 0; s_index <
                                                      selectors_amount(); s_index++) {
                            rows_amount = std::max(rows_amount, selector_column_size(s_index));
                        }

                        return rows_amount;
                    }

                    bool operator==(plonk_table<FieldType, ColumnType> const &other) const {
                        return _private_table == other._private_table && _public_table == other._public_table;
                    }

                    friend std::uint32_t basic_padding<FieldType, ColumnType>(
                        plonk_table &table);

                    friend std::uint32_t zk_padding<FieldType, ColumnType>(
                        plonk_table &table,
                        typename nil::crypto3::random::algebraic_engine<FieldType> alg_rnd
                    );
                };

                template<typename FieldType>
                using plonk_private_assignment_table =
                    plonk_private_table<FieldType, plonk_column<FieldType>>;

                template<typename FieldType>
                using plonk_public_assignment_table =
                    plonk_public_table<FieldType, plonk_column<FieldType>>;

                template<typename FieldType>
                using plonk_assignment_table = plonk_table<FieldType, plonk_column<FieldType>>;

                template<typename FieldType>
                using plonk_private_polynomial_table =
                    plonk_private_table<FieldType,
                                        math::polynomial<typename FieldType::value_type>>;

                template<typename FieldType>
                using plonk_public_polynomial_table =
                    plonk_public_table<FieldType,
                                       math::polynomial<typename FieldType::value_type>>;

                template<typename FieldType>
                using plonk_polynomial_table =
                    plonk_table<FieldType, math::polynomial<typename FieldType::value_type>>;

                template<typename FieldType>
                using plonk_private_polynomial_dfs_table =
                    plonk_private_table<FieldType,
                                        math::polynomial_dfs<typename FieldType::value_type>>;

                template<typename FieldType>
                using plonk_public_polynomial_dfs_table =
                    plonk_public_table<FieldType,
                                       math::polynomial_dfs<typename FieldType::value_type>>;

                template<typename FieldType>
                using plonk_polynomial_dfs_table =
                    plonk_table<FieldType, math::polynomial_dfs<typename FieldType::value_type>>;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_TABLE_HPP
