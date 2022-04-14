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

#ifndef CRYPTO3_ZK_BLUEPRINT_ASSIGNMENT_PLONK_HPP
#define CRYPTO3_ZK_BLUEPRINT_ASSIGNMENT_PLONK_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {

            template<typename ArithmetizationType, std::size_t... BlueprintParams>
            class blueprint_private_assignment_table;

            template<typename ArithmetizationType, std::size_t... BlueprintParams>
            class blueprint_public_assignment_table;

            template<typename ArithmetizationType, std::size_t... BlueprintParams>
            class blueprint_assignment_table;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            class blueprint_private_assignment_table<snark::plonk_constraint_system<BlueprintFieldType,
                                                        ArithmetizationParams>>
                : public snark::plonk_private_assignment_table<BlueprintFieldType,
                                                               ArithmetizationParams> {

                typedef snark::plonk_constraint_system<BlueprintFieldType,
                                                       ArithmetizationParams> ArithmetizationType;

                snark::plonk_table_description<BlueprintFieldType,
                        ArithmetizationParams> &_table_description;
            public:
                blueprint_private_assignment_table(
                    snark::plonk_table_description<BlueprintFieldType,
                        ArithmetizationParams> &table_description) :
                    snark::plonk_private_assignment_table<BlueprintFieldType,
                        ArithmetizationParams>(), _table_description(table_description) {
                }

                snark::plonk_column<BlueprintFieldType> &witness(std::size_t witness_index) {
                    assert(witness_index < ArithmetizationParams::WitnessColumns);
                    this->witness_columns[witness_index].resize(_table_description.rows_amount);
                    return this->witness_columns[witness_index];
                }

                snark::plonk_column<BlueprintFieldType> &operator[](std::size_t index) {
                    if (index < ArithmetizationParams::WitnessColumns) {
                        return witness(index);
                    }
                    index -= ArithmetizationParams::WitnessColumns;

                    // Usupposed input
                    return this->witness(0);
                }

                snark::plonk_table_description<BlueprintFieldType,
                        ArithmetizationParams> table_description() const {
                    return _table_description;
                }

                std::size_t padding(){

                    if (_table_description.usable_rows_amount == 0) {
                        _table_description.usable_rows_amount =
                            _table_description.rows_amount;
                        _table_description.rows_amount = std::pow(2,
                            std::ceil(std::log2(_table_description.rows_amount)));

                        if (_table_description.rows_amount < 4)
                            _table_description.rows_amount = 4;

                        for (std::size_t w_index = 0; w_index <
                            ArithmetizationParams::WitnessColumns; w_index++){

                            this->witness_columns[w_index].resize(_table_description.rows_amount);
                        }
                    }

                    return _table_description.rows_amount;
                }
            };

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            class blueprint_public_assignment_table<snark::plonk_constraint_system<BlueprintFieldType,
                                                        ArithmetizationParams>>
                : public snark::plonk_public_assignment_table<BlueprintFieldType,
                                                              ArithmetizationParams> {

                typedef snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams> ArithmetizationType;

                using var = snark::plonk_variable<BlueprintFieldType>;

                snark::plonk_table_description<BlueprintFieldType,
                        ArithmetizationParams> &_table_description;

                std::size_t allocated_public_input_rows = 0;
            public:
                blueprint_public_assignment_table(
                    snark::plonk_table_description<BlueprintFieldType,
                        ArithmetizationParams> &table_description) :
                    snark::plonk_public_assignment_table<BlueprintFieldType,
                                                         ArithmetizationParams>(),
                    _table_description(table_description) {
                }

                snark::plonk_column<BlueprintFieldType> &selector(std::size_t selector_index) {
                    if (selector_index >= this->selector_columns.size()) {
                        this->selector_columns.resize(selector_index + 1);
                    }
                    this->selector_columns[selector_index].resize(_table_description.rows_amount);
                    return this->selector_columns[selector_index];
                }

                std::size_t add_selector(const std::vector<std::size_t> &&row_indices) {
                    static std::size_t selector_index = 0;
                    std::size_t max_row_index = *std::max_element(row_indices.begin(), row_indices.end());
                    snark::plonk_column<BlueprintFieldType> selector_column(max_row_index + 1,
                                                                            BlueprintFieldType::value_type::zero());
                    for (std::size_t row_index : row_indices) {
                        selector_column[row_index] = BlueprintFieldType::value_type::one();
                    }
                    this->selector_columns[selector_index] = selector_column;
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

                    for(std::size_t row_start_index: row_start_indices){
                        for(std::size_t offset: offsets){
                            *row_indices_iterator = row_start_index + offset;
                            row_indices_iterator++;
                        }
                    }

                    return add_selector(row_indices);
                }

                std::size_t add_selector(const std::initializer_list<std::size_t> &&row_start_indices,
                    const std::size_t offset) {

                    return add_selector(row_start_indices, {offset});
                }

                std::size_t
                    add_selector(std::size_t begin_row_index, std::size_t end_row_index, std::size_t index_step = 1) {

                    static std::size_t selector_index = 0;
                    snark::plonk_column<BlueprintFieldType> selector_column(end_row_index + 1,
                                                                            BlueprintFieldType::value_type::zero());
                    for (std::size_t row_index = begin_row_index; row_index <= end_row_index; row_index += index_step) {
                        selector_column[row_index] = BlueprintFieldType::value_type::one();
                    }
                    this->selector_columns[selector_index] = selector_column;
                    selector_index++;
                    return selector_index - 1;
                }

                void enable_selector(std::size_t selector_index, const std::vector<std::size_t> &&row_indices) {
                    assert(selector_index < this->selector_columns.size());

                    for (std::size_t row_index : row_indices) {
                        this->selector_columns[selector_index][row_index] = BlueprintFieldType::value_type::one();
                    }
                }

                void enable_selector(std::size_t selector_index, std::size_t row_index) {
                    assert(selector_index < this->selector_columns.size());

                    enable_selector(selector_index, std::vector<std::size_t>({row_index}));
                }

                void
                    enable_selector(std::size_t selector_index, std::size_t begin_row_index, std::size_t end_row_index, std::size_t index_step = 1) {
                    
                    assert(selector_index < this->selector_columns.size());

                    for (std::size_t row_index = begin_row_index; row_index <= end_row_index; row_index += index_step) {
                        this->selector_columns[selector_index][row_index] = BlueprintFieldType::value_type::one();
                    }
                }

                snark::plonk_column<BlueprintFieldType> &public_input(std::size_t public_input_index) {
                    assert(public_input_index < this->public_input_columns.size());
                    this->public_input_columns[public_input_index].resize(_table_description.rows_amount);
                    return this->public_input_columns[public_input_index];
                }

                snark::plonk_column<BlueprintFieldType> &constant(std::size_t constant_index) {
                    assert(constant_index < this->constant_columns.size());
                    this->constant_columns[constant_index].resize(_table_description.rows_amount);
                    return this->constant_columns[constant_index];
                }

                snark::plonk_column<BlueprintFieldType> &operator[](std::size_t index) {
                    if (index < this->public_input_columns.size()) {
                        return public_input(index);
                    }
                    index -= this->public_input_columns.size();
                    if (index < this->constant_columns.size()) {
                        return constant(index);
                    }
                    index -= this->constant_columns.size();
                    if (index < this->selector_columns.size()) {
                        return this->selector(index);
                    }
                    index -= this->selector_columns.size();

                    // Usupposed input
                    return this->public_input(0);
                }

                snark::plonk_table_description<BlueprintFieldType,
                        ArithmetizationParams> table_description() const {
                    return _table_description;
                }

                std::size_t padding(){
                    if (_table_description.usable_rows_amount == 0) {

                        _table_description.usable_rows_amount =
                            _table_description.rows_amount;

                        _table_description.rows_amount = std::pow(2,
                            std::ceil(std::log2(_table_description.rows_amount)));

                        if (_table_description.rows_amount < 4)
                            _table_description.rows_amount = 4;

                        for (std::size_t pi_index = 0; pi_index <
                            this->public_input_columns.size(); pi_index++) {

                            this->public_input_columns[pi_index].resize(_table_description.rows_amount);
                        }

                        for (std::size_t c_index = 0; c_index <
                            this->constant_columns.size(); c_index++) {

                            this->constant_columns[c_index].resize(_table_description.rows_amount);
                        }

                        for (std::size_t s_index = 0; s_index <
                            this->selector_columns.size(); s_index++) {

                            this->selector_columns[s_index].resize(_table_description.rows_amount);
                        }

                    }

                    return _table_description.rows_amount;
                }

                var allocate_public_input(typename BlueprintFieldType::value_type data) {
                    public_input(0)[allocated_public_input_rows] = data;
                    allocated_public_input_rows++;
                    return var(0, allocated_public_input_rows - 1, false, var::column_type::public_input);
                }
            };

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            class blueprint_assignment_table<snark::plonk_constraint_system<BlueprintFieldType,
                                                        ArithmetizationParams>> {
                
                using ArithmetizationType = snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams>;

                using var = snark::plonk_variable<BlueprintFieldType>;

                blueprint_private_assignment_table<ArithmetizationType> &_private_assignment;
                blueprint_public_assignment_table<ArithmetizationType> &_public_assignment;

                public:
                blueprint_assignment_table(
                        blueprint_private_assignment_table<ArithmetizationType> &private_assignment,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignmen): 
                            _private_assignment(private_assignment), _public_assignment(public_assignmen) {

                }

                // private_assignment interface
                snark::plonk_column<BlueprintFieldType> &witness(std::size_t witness_index) {
                    return _private_assignment.witness(witness_index);
                }    

                // public_assignment interface
                snark::plonk_column<BlueprintFieldType> &selector(std::size_t selector_index) {
                    return _public_assignment.selector(selector_index);
                }

                std::size_t add_selector(const std::vector<std::size_t> &&row_indices) {
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

                void enable_selector(std::size_t selector_index, const std::vector<std::size_t> &&row_indices) {
                    _public_assignment.enable_selector(selector_index, std::move(row_indices));
                }

                void enable_selector(std::size_t selector_index, std::size_t row_index) {
                    _public_assignment.enable_selector(selector_index, row_index);
                }

                void
                    enable_selector(std::size_t selector_index, std::size_t begin_row_index, std::size_t end_row_index, std::size_t index_step = 1) {
                    
                    _public_assignment.enable_selector(selector_index, begin_row_index, end_row_index, index_step);
                }

                snark::plonk_column<BlueprintFieldType> &public_input(std::size_t public_input_index) {
                    return _public_assignment.public_input(public_input_index);
                }

                snark::plonk_column<BlueprintFieldType> &constant(std::size_t constant_index) {
                    return _public_assignment.constant(constant_index);
                }

                var allocate_public_input(typename BlueprintFieldType::value_type data) {
                    return _public_assignment.allocate_public_input(data);
                }

                // shared interface
                snark::plonk_column<BlueprintFieldType> &operator[](std::size_t index) {
                    if (index < ArithmetizationParams::WitnessColumns) {
                        return _private_assignment[index];
                    }

                    index -= ArithmetizationParams::WitnessColumns;
                    return _public_assignment[index];
                }

                snark::plonk_table_description<BlueprintFieldType,
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
                        result = witness(a.index)[a.rotation];
                    } else if (a.type == var::column_type::public_input) {
                        result = public_input(a.index)[a.rotation];
                    } else {
                        result = constant(a.index)[a.rotation];
                    }

                    return result;
                }
            };

        }    // namespace zk
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_ASSIGNMENT_PLONK_HPP
