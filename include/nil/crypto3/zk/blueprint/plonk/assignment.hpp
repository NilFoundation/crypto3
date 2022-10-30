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

#include <algorithm>

#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/crypto3/zk/assert.hpp>

#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/zk/detail/get_component_id.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {

            template<typename ArithmetizationType, std::size_t... BlueprintParams>
            class assignment;

            template<typename BlueprintFieldType,
                    typename ArithmetizationParams>
            class assignment<zk::snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams>>
                    : public zk::snark::plonk_assignment_table<BlueprintFieldType,
                            ArithmetizationParams> {

                using zk_type = zk::snark::plonk_assignment_table<BlueprintFieldType,
                        ArithmetizationParams>;

                typedef zk::snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                using var = zk::snark::plonk_variable<BlueprintFieldType>;

                using component_selector_map_type = std::map<
                    detail::blueprint_component_id_type,
                    std::size_t>;

                component_selector_map_type selector_map;

                std::size_t next_selector_index = 0;

                std::uint32_t _allocated_rows = 0;
            public:

                assignment() :
                        zk::snark::plonk_assignment_table<BlueprintFieldType,
                                ArithmetizationParams>() {
                }

                typename BlueprintFieldType::value_type &selector(std::size_t selector_index,
                    std::uint32_t row_index) {

                    assert(selector_index < this->_public_table._selectors.size());

                    if (this->_public_table._selectors[selector_index].size() <= row_index)
                        this->_public_table._selectors[selector_index].resize(row_index + 1);

                    return this->_public_table._selectors[selector_index][row_index];
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

                    // if (next_selector_index >= this->_public_table._selectors.size()){
                    //     this->_public_table._selectors.resize(next_selector_index);
                    // }
                    std::size_t selector_index = next_selector_index;
                    selector_map[detail::get_component_id(component)] = selector_index;
                    next_selector_index += selectors_amount;
                    return selector_index;
                }

                std::uint32_t allocated_rows() const {
                    return _allocated_rows;
                }

                void enable_selector(const std::size_t selector_index,
                                     const std::size_t row_index) {

                    selector(selector_index, row_index) = BlueprintFieldType::value_type::one();
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
                    this->_public_table._selectors[next_selector_index] = selector_column;
                    next_selector_index++;
                    return next_selector_index - 1;
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

                typename BlueprintFieldType::value_type &witness(std::uint32_t witness_index, std::uint32_t row_index) {
                    BLUEPRINT_ASSERT(witness_index < ArithmetizationParams::WitnessColumns);

                    if (this->_private_table._witnesses[witness_index].size() <= row_index)
                        this->_private_table._witnesses[witness_index].resize(row_index + 1);

                    _allocated_rows = std::max(_allocated_rows, row_index + 1);
                    return this->_private_table._witnesses[witness_index][row_index];
                }

                typename BlueprintFieldType::value_type witness(std::uint32_t witness_index, std::uint32_t row_index) const {
                    BLUEPRINT_ASSERT(witness_index < ArithmetizationParams::WitnessColumns);
                    BLUEPRINT_ASSERT(row_index < this->_private_table._witnesses[witness_index].size());

                    return this->_private_table._witnesses[witness_index][row_index];
                }

                typename BlueprintFieldType::value_type &public_input(std::size_t public_input_index,
                    std::uint32_t row_index) {

                    BLUEPRINT_ASSERT(public_input_index < zk_type::public_inputs_amount());

                    if (zk_type::public_input_column_size(public_input_index) <= row_index)
                        this->_public_table._public_inputs[public_input_index].resize(row_index + 1);

                    return this->_public_table._public_inputs[public_input_index][row_index];
                }

                typename BlueprintFieldType::value_type public_input(
                    std::uint32_t public_input_index, std::uint32_t row_index) const {

                    BLUEPRINT_ASSERT(public_input_index < zk_type::public_inputs_amount());
                    BLUEPRINT_ASSERT(row_index < zk_type::public_input_column_size(public_input_index));

                    return zk_type::public_input(public_input_index)[row_index];
                }

                typename BlueprintFieldType::value_type &constant(std::size_t constant_index,
                    std::uint32_t row_index) {

                    assert(constant_index < zk_type::constants_amount());

                    if (zk_type::constant_column_size(constant_index) <= row_index)
                        this->_public_table._constants[constant_index].resize(row_index + 1);

                    _allocated_rows = std::max(_allocated_rows, row_index + 1);
                    return this->_public_table._constants[constant_index][row_index];
                }

                typename BlueprintFieldType::value_type constant(
                    std::uint32_t constant_index, std::uint32_t row_index) const {

                    BLUEPRINT_ASSERT(constant_index < zk_type::constants_amount());
                    BLUEPRINT_ASSERT(row_index < zk_type::constant_column_size(constant_index));

                    return zk_type::constant(constant_index)[row_index];
                }
            };

            template<typename BlueprintFieldType,
                    typename ArithmetizationParams>
            typename BlueprintFieldType::value_type var_value(
                    const zk::snark::plonk_assignment_table<BlueprintFieldType,
                            ArithmetizationParams> &input_assignment,
                    const zk::snark::plonk_variable<BlueprintFieldType> &input_var) {
                switch(input_var.type){
                    case zk::snark::plonk_variable<BlueprintFieldType>::column_type::witness:
                        return input_assignment.witness(input_var.index)[input_var.rotation];
                    case zk::snark::plonk_variable<BlueprintFieldType>::column_type::public_input:
                        return input_assignment.public_input(input_var.index)[input_var.rotation];
                    default:
                        return input_assignment.constant(input_var.index)[input_var.rotation];
                }
            }

        }    // namespace blueprint
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_ASSIGNMENT_PLONK_HPP
