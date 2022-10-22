//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_ASSIGNMENT_PLONK_HPP
#define CRYPTO3_BLUEPRINT_ASSIGNMENT_PLONK_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/zk/detail/get_component_id.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {

            template<typename ArithmetizationType, std::size_t... BlueprintParams>
            class private_assignment;

            template<typename ArithmetizationType, std::size_t... BlueprintParams>
            class public_assignment;

            template<typename ArithmetizationType, std::size_t... BlueprintParams>
            class assignment;

            template<typename BlueprintFieldType,
                    typename ArithmetizationParams>
            class private_assignment<zk::snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams>>
                    : public zk::snark::plonk_private_assignment_table<BlueprintFieldType,
                            ArithmetizationParams> {

                typedef zk::snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                zk::snark::plonk_table_description<BlueprintFieldType,
                        ArithmetizationParams> &_table_description;
            public:
                private_assignment(zk::snark::plonk_private_assignment_table<BlueprintFieldType,
                        ArithmetizationParams> assigment_table,
                                                   zk::snark::plonk_table_description<BlueprintFieldType,
                                                           ArithmetizationParams> &table_description) :
                        zk::snark::plonk_private_assignment_table<BlueprintFieldType,
                                ArithmetizationParams>(assigment_table), _table_description(table_description) {
                }

                private_assignment(
                        zk::snark::plonk_table_description<BlueprintFieldType,
                                ArithmetizationParams> &table_description) :
                        zk::snark::plonk_private_assignment_table<BlueprintFieldType,
                                ArithmetizationParams>(), _table_description(table_description) {
                }

                typename BlueprintFieldType::value_type &witness(std::uint32_t witness_index, std::uint32_t row_index) {
                    // BLUEPRINT_ASSERT(witness_index < ArithmetizationParams::WitnessColumns);
                    return this->_witness[witness_index][row_index];
                }

                zk::snark::plonk_column<BlueprintFieldType> &operator[](std::size_t index) {
                    if (index < this->witness_size()) {
                        return witness(index);
                    }
                    index -= this->witness_size();

                    // Usupposed input
                    return this->witness(0);
                }

                zk::snark::plonk_table_description<BlueprintFieldType,
                        ArithmetizationParams> table_description() const {
                    return _table_description;
                }

                std::size_t padding() {

                    if (_table_description.usable_rows_amount == 0) {
                        _table_description.usable_rows_amount =
                                _table_description.rows_amount;
                        _table_description.rows_amount = std::pow(2,
                                                                  std::ceil(std::log2(_table_description.rows_amount)));

                        if (_table_description.rows_amount < 8)
                            _table_description.rows_amount = 8;
                    }

                    for (std::size_t w_index = 0; w_index <
                                                  this->witness_size(); w_index++) {

                        this->_witness[w_index].resize(_table_description.rows_amount,
                                                              decltype(this->_witness)::value_type::value_type::zero());
                    }


                    return _table_description.rows_amount;
                }
            };

            template<typename BlueprintFieldType,
                    typename ArithmetizationParams>
            class public_assignment<zk::snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams>>
                    : public zk::snark::plonk_public_assignment_table<BlueprintFieldType,
                            ArithmetizationParams> {

                using zk_type = zk::snark::plonk_public_assignment_table<BlueprintFieldType,
                        ArithmetizationParams>;

                typedef zk::snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                using var = zk::snark::plonk_variable<BlueprintFieldType>;

                zk::snark::plonk_table_description<BlueprintFieldType,
                        ArithmetizationParams> &_table_description;

                using component_selector_map_type = std::map<
                    detail::blueprint_component_id_type,
                    std::size_t>;

                component_selector_map_type selector_map;

                std::size_t next_selector_index = 0;

                std::size_t allocated_public_input_rows = 0;
                std::size_t selector_index = 0;
            public:
                // public_assignment(
                //         std::array<std::vector<typename BlueprintFieldType::value_type>, ArithmetizationParams::public_input> public_input,
                //         std::array<std::vector<typename BlueprintFieldType::value_type>, ArithmetizationParams::constant> constant,
                //         std::array<std::vector<typename BlueprintFieldType::value_type>, ArithmetizationParams::selector> selector,
                //         zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> &table_description_in,
                //         std::map<std::size_t, std::size_t> selector_map_in,
                //         std::size_t next_selector_index_in, std::size_t allocated_public_input_rows_in,
                //         std::size_t selector_index_in) :
                //         zk::snark::plonk_public_assignment_table<BlueprintFieldType, ArithmetizationParams>(
                //                 public_input, constant, selector),
                //         _table_description(table_description_in), selector_map(selector_map_in),
                //         next_selector_index(next_selector_index_in),
                //         allocated_public_input_rows(allocated_public_input_rows_in),
                //         selector_index(selector_index_in) {
                // }

                public_assignment(
                        zk::snark::plonk_table_description<BlueprintFieldType,
                                ArithmetizationParams> &table_description) :
                        zk::snark::plonk_public_assignment_table<BlueprintFieldType,
                                ArithmetizationParams>(),
                        _table_description(table_description) {
                }

                zk::snark::plonk_column<BlueprintFieldType> &selector(std::size_t selector_index) {
                    // assert(selector_index < this->selector.size());
                    this->_selectors[selector_index].resize(_table_description.rows_amount);
                    return this->_selectors[selector_index];
                }

                typename component_selector_map_type::iterator selectors_end() {
                    return selector_map.end();
                }

                template<typename ComponentType>
                typename component_selector_map_type::iterator find_selector(
                    ComponentType &component) {

                    return selector_map.find(detail::get_component_id(component));
                }

                template<typename ComponentType>
                std::size_t allocate_selector(
                    ComponentType &component,
                    std::size_t selectors_amount) {

                    std::size_t selector_index = next_selector_index;
                    selector_map[detail::get_component_id(component)] = selector_index;
                    next_selector_index += selectors_amount;
                    return selector_index;
                }

                void enable_selector(const std::size_t selector_index,
                                     const std::size_t row_index) {

                    selector(selector_index)[row_index] = 1;
                }

                void enable_selector(const std::size_t selector_index,
                                     const std::size_t begin_row_index,
                                     const std::size_t end_row_index,
                                     const std::size_t index_step = 1) {

                    for (std::size_t row_index = begin_row_index; row_index <= end_row_index; row_index += index_step) {

                        enable_selector(selector_index, row_index);
                    }
                }

                std::size_t add_selector(const std::vector<std::size_t> row_indices) {

                    std::size_t max_row_index = *std::max_element(row_indices.begin(), row_indices.end());
                    zk::snark::plonk_column<BlueprintFieldType> selector_column(max_row_index + 1,
                                                                            BlueprintFieldType::value_type::zero());
                    for (std::size_t row_index: row_indices) {
                        selector_column[row_index] = BlueprintFieldType::value_type::one();
                    }
                    this->_selectors[selector_index] = selector_column;
                    selector_index++;
                    return selector_index - 1;
                }

                std::size_t add_selector(std::size_t row_index) {
                    return add_selector(std::vector<std::size_t>({row_index}));
                }

                std::size_t add_selector(const std::initializer_list<std::size_t> &&row_start_indices,
                                         const std::initializer_list<std::size_t> &&offsets) {

                    std::vector<std::size_t> row_indices(row_start_indices.size() *
                                                         offsets.size());
                    std::vector<std::size_t>::iterator row_indices_iterator = row_indices.begin();

                    for (std::size_t start_row_index: row_start_indices) {
                        for (std::size_t offset: offsets) {
                            *row_indices_iterator = start_row_index + offset;
                            row_indices_iterator++;
                        }
                    }

                    return add_selector(row_indices);
                }

                std::size_t add_selector(const std::initializer_list<std::size_t> &&row_start_indices,
                                         const std::size_t offset) {

                    return add_selector(row_start_indices, {offset});
                }

                // std::size_t
                //     add_selector(std::size_t begin_row_index, std::size_t end_row_index, std::size_t index_step = 1) {

                //     static std::size_t selector_index = 0;
                //     snark::plonk_column<BlueprintFieldType> selector_column(end_row_index + 1,
                //                                                             BlueprintFieldType::value_type::zero());
                //     for (std::size_t row_index = begin_row_index; row_index <= end_row_index; row_index += index_step) {
                //         selector_column[row_index] = BlueprintFieldType::value_type::one();
                //     }
                //     this->_selectors[selector_index] = selector_column;
                //     selector_index++;
                //     return selector_index - 1;
                // }

                zk::snark::plonk_column<BlueprintFieldType> &public_input(std::size_t public_input_index) {
                    // assert(public_input_index < this->public_input.size());
                    this->_public_inputs[public_input_index].resize(_table_description.rows_amount);
                    return this->_public_inputs[public_input_index];
                }

                zk::snark::plonk_column<BlueprintFieldType> &constant(std::size_t constant_index) {
                    // assert(constant_index < this->constant.size());
                    this->_constants[constant_index].resize(_table_description.rows_amount);
                    return this->_constants[constant_index];
                }

                zk::snark::plonk_column<BlueprintFieldType> &operator[](std::size_t index) {
                    if (index < this->public_input.size()) {
                        return public_input(index);
                    }
                    index -= this->public_input.size();
                    if (index < this->constant.size()) {
                        return constant(index);
                    }
                    index -= this->constant.size();
                    if (index < this->selector.size()) {
                        return this->selector(index);
                    }
                    index -= this->selector.size();

                    // Usupposed input
                    return this->public_input(0);
                }

                zk::snark::plonk_table_description<BlueprintFieldType,
                        ArithmetizationParams> table_description() const {
                    return _table_description;
                }

                std::size_t padding() {
                    if (_table_description.usable_rows_amount == 0) {

                        _table_description.usable_rows_amount =
                                _table_description.rows_amount;

                        _table_description.rows_amount = std::pow(2,
                                                                  std::ceil(std::log2(_table_description.rows_amount)));

                        if (_table_description.rows_amount < 4)
                            _table_description.rows_amount = 4;
                    }

                    for (std::size_t pi_index = 0; pi_index <
                                                   this->public_input.size(); pi_index++) {

                        this->_public_inputs[pi_index].resize(_table_description.rows_amount,
                                                                    decltype(this->public_input)::value_type::value_type::zero());
                    }

                    for (std::size_t c_index = 0; c_index <
                                                  this->constant.size(); c_index++) {

                        this->_constants[c_index].resize(_table_description.rows_amount,
                                                               decltype(this->constant)::value_type::value_type::zero());
                    }

                    for (std::size_t s_index = 0; s_index <
                                                  this->selector.size(); s_index++) {

                        this->_selectors[s_index].resize(_table_description.rows_amount,
                                                               decltype(this->selector)::value_type::value_type::zero());
                    }

                    return _table_description.rows_amount;
                }

                var allocate_public_input(typename BlueprintFieldType::value_type data) {


                    public_input(0)[allocated_public_input_rows] = data;
                    allocated_public_input_rows++;
                    return var(0, allocated_public_input_rows - 1, false, var::column_type::public_input);
                }

                std::size_t get_next_selector_index() const {
                    return next_selector_index;
                };

                std::size_t get_allocated_public_input_rows() const {
                    return allocated_public_input_rows;
                };

                std::size_t get_selector_index() const {
                    return selector_index;
                };
            };

            template<typename BlueprintFieldType,
                    typename ArithmetizationParams>
            class assignment<zk::snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams>> {

                using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>;

                using var = zk::snark::plonk_variable<BlueprintFieldType>;

                private_assignment<ArithmetizationType> &_private_assignment;
                public_assignment<ArithmetizationType> &_public_assignment;

            public:
                assignment(
                        private_assignment<ArithmetizationType> &private_assignment,
                        public_assignment<ArithmetizationType> &public_assignmen) :
                        _private_assignment(private_assignment), _public_assignment(public_assignmen) {

                }

                // private_assignment interface
                typename BlueprintFieldType::value_type &witness(std::size_t witness_index,
                    std::uint32_t row_index) {
                    return _private_assignment.witness(witness_index, row_index);
                }

                // public_assignment interface
                zk::snark::plonk_column<BlueprintFieldType> &selector(std::size_t selector_index) {
                    return _public_assignment.selector(selector_index);
                }

                std::size_t add_selector(const std::vector<std::size_t> row_indices) {
                    return _public_assignment.add_selector(std::move(row_indices));
                }

                std::size_t add_selector(std::size_t row_index) {
                    return _public_assignment.add_selector(row_index);
                }

                std::size_t add_selector(const std::initializer_list<std::size_t> &&row_start_indices,
                                         const std::initializer_list<std::size_t> &&offsets) {
                    return _public_assignment.add_selector(row_start_indices, offsets);
                }

                std::size_t add_selector(const std::initializer_list<std::size_t> &&row_start_indices,
                                         const std::size_t offset) {
                    return _public_assignment.add_selector(row_start_indices, offset);
                }

                std::size_t
                add_selector(std::size_t begin_row_index, std::size_t end_row_index, std::size_t index_step = 1) {
                    return _public_assignment.add_selector(begin_row_index, end_row_index, index_step);
                }

                zk::snark::plonk_column<BlueprintFieldType> &public_input(std::size_t public_input_index) {
                    return _public_assignment.public_input(public_input_index);
                }

                zk::snark::plonk_column<BlueprintFieldType> &constant(std::size_t constant_index) {
                    return _public_assignment.constant(constant_index);
                }

                var allocate_public_input(typename BlueprintFieldType::value_type data) {
                    return _public_assignment.allocate_public_input(data);
                }

                // shared interface
                zk::snark::plonk_column<BlueprintFieldType> &operator[](std::size_t index) {
                    if (index < this->witness_size()) {
                        return _private_assignment[index];
                    }

                    index -= this->witness_size();
                    return _public_assignment[index];
                }

                zk::snark::plonk_table_description<BlueprintFieldType,
                        ArithmetizationParams> table_description() const {
                    return _public_assignment.table_description();
                }

                std::size_t padding() {
                    std::size_t rows = _private_assignment.padding();
                    rows = _public_assignment.padding();
                    return rows;
                }

                typename BlueprintFieldType::value_type var_value(const var &a) {
                    typename BlueprintFieldType::value_type result;
                    if (a.type == var::column_type::witness) {
                        result = witness(a.index, a.rotation);
                    } else if (a.type == var::column_type::public_input) {
                        result = public_input(a.index)[a.rotation];
                    } else {
                        result = constant(a.index)[a.rotation];
                    }

                    return result;
                }
            };

        }    // namespace blueprint
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_ASSIGNMENT_PLONK_HPP
