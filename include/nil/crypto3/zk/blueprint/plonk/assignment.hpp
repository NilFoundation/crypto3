//---------------------------------------------------------------------------//
// Copyright (c) 2020-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#include <boost/assert.hpp>

#include <nil/crypto3/zk/assert.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

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
            class private_assignment_table<zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public zk::snark::plonk_private_assignment_table<BlueprintFieldType,
                                                               ArithmetizationParams> {

                typedef zk::snark::plonk_constraint_system<BlueprintFieldType> ArithmetizationType;

                 &_table_description;
            public:
                private_assignment_table(
                    snark::plonk_table_description<BlueprintFieldType,
                        ArithmetizationParams> &table_description) :
                    snark::plonk_private_assignment_table<BlueprintFieldType,
                        ArithmetizationParams>(), _table_description(table_description) {

                }

                zk::snark::plonk_column<BlueprintFieldType> &witness(std::uint32_t witness_index) {
                    BLUEPRINT_ASSERT(witness_index < ArithmetizationParams::WitnessColumns);
                    this->witness_columns[witness_index].resize(_table_description.rows_amount);
                    return this->witness_columns[witness_index];
                }

                zk::snark::plonk_column<BlueprintFieldType> &operator[](std::uint32_t index) {
                    if (index < this->witness_size()) {
                        return witness(index);
                    }
                    index -= this->witness_size();

                    // Usupposed input
                    return this->witness(0);
                }

                std::uint32_t padding(){

                    if (_table_description.usable_rows_amount == 0) {
                        _table_description.usable_rows_amount =
                            _table_description.rows_amount;
                        _table_description.rows_amount = std::pow(2,
                            std::ceil(std::log2(_table_description.rows_amount)));

                        if (_table_description.rows_amount < 8)
                            _table_description.rows_amount = 8;
                    }
                    
                    for (std::uint32_t w_index = 0; w_index <
                        ArithmetizationParams::WitnessColumns; w_index++){

                        this->witness_columns[w_index].resize(_table_description.rows_amount,
                            decltype(this->witness_columns)::value_type::value_type::zero());
                    }
                    

                    return _table_description.rows_amount;
                }
            };

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            class public_assignment<zk::snark::plonk_constraint_system<BlueprintFieldType>> {

                using zk_type = zk::snark::plonk_public_assignment_table<BlueprintFieldType,
                                                              ArithmetizationParams>;

                typename zk_type::public_input_container_type _public_input;
                typename zk_type::constant_container_type _constant;

                typedef zk::snark::plonk_constraint_system<BlueprintFieldType> ArithmetizationType;

                using var = zk::snark::plonk_variable<BlueprintFieldType>;

                zk::snark::plonk_table_description<BlueprintFieldType,
                        ArithmetizationParams> &_table_description;

                std::size_t allocated_public_input_rows = 0;

            public:

                public_assignment_table(
                    zk::snark::plonk_table_description<BlueprintFieldType,
                        ArithmetizationParams> &table_description) :
                    zk::snark::plonk_public_assignment_table<BlueprintFieldType,
                                                         ArithmetizationParams>(),
                    _table_description(table_description) {
                }

                snark::plonk_column<BlueprintFieldType> &public_input(std::size_t public_input_index) {
                    BLUEPRINT_ASSERT(public_input_index < this->public_input_columns.size());
                    this->public_input_columns[public_input_index].resize(_table_description.rows_amount);
                    return this->public_input_columns[public_input_index];
                }

                snark::plonk_column<BlueprintFieldType> &constant(std::size_t constant_index) {
                    BLUEPRINT_ASSERT(constant_index < this->constant_columns.size());
                    this->constant_columns[constant_index].resize(_table_description.rows_amount);
                    return this->constant_columns[constant_index];
                }

                snark::plonk_column<BlueprintFieldType> &operator[](std::uint32_t index) {
#ifdef BLUEPRINT_DEBUG
                    BLUEPRINT_ASSERT(index < _public_input.size() + _constant.size())
#endif

                    if (index < _public_input.size()) {
                        return public_input(index);
                    }
                    index -= _public_input.size();
                    if (index < _constant.size()) {
                        return constant(index);
                    }
                    index -= _constant.size();

                    // Usupposed input
                    return this->public_input(0);
                }

                std::size_t padding(){
                    if (_table_description.usable_rows_amount == 0) {

                        _table_description.usable_rows_amount =
                            _table_description.rows_amount;

                        _table_description.rows_amount = std::pow(2,
                            std::ceil(std::log2(_table_description.rows_amount)));

                        if (_table_description.rows_amount < 4)
                            _table_description.rows_amount = 4;
                    }

                    for (std::size_t pi_index = 0; pi_index <
                        this->public_input_columns.size(); pi_index++) {

                        this->public_input_columns[pi_index].resize(_table_description.rows_amount,
                            decltype(this->public_input_columns)::value_type::value_type::zero());
                    }

                    for (std::size_t c_index = 0; c_index <
                        this->constant_columns.size(); c_index++) {

                        this->constant_columns[c_index].resize(_table_description.rows_amount,
                            decltype(this->constant_columns)::value_type::value_type::zero());
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
            class assignment<snark::plonk_constraint_system<BlueprintFieldType>> {
                
                using ArithmetizationType = snark::plonk_constraint_system<BlueprintFieldType>;

                using var = snark::plonk_variable<BlueprintFieldType>;

                private_assignment_table<ArithmetizationType> &_private_assignment;
                public_assignment_table<ArithmetizationType> &_public_assignment;

                public:
                assignment(
                        private_assignment_table<ArithmetizationType> &private_assignment,
                        public_assignment_table<ArithmetizationType> &public_assignmen): 
                            _private_assignment(private_assignment), _public_assignment(public_assignmen) {

                }

                std::size_t allocate_rows(std::size_t required_amount = 1) {
                    std::size_t result = _table_description.rows_amount;
                    _table_description.rows_amount += required_amount;
                    return result;
                }

                std::size_t allocate_row() {
                    return allocate_rows(1);
                }

                // private_assignment interface
                snark::plonk_column<BlueprintFieldType> &witness(std::size_t witness_index) {
                    return _private_assignment.witness(witness_index);
                }

                snark::plonk_column<BlueprintFieldType> &public_input(std::uint32_t public_input_index) {
                    return _public_assignment.public_input(public_input_index);
                }

                snark::plonk_column<BlueprintFieldType> &constant(std::uint32_t constant_index) {
                    return _public_assignment.constant(constant_index);
                }

                var allocate_public_input(typename BlueprintFieldType::value_type data) {
                    return _public_assignment.allocate_public_input(data);
                }

                // shared interface
                snark::plonk_column<BlueprintFieldType> &operator[](std::uint32_t index) {
                    if (index < ArithmetizationParams::WitnessColumns) {
                        return _private_assignment[index];
                    }

                    index -= ArithmetizationParams::WitnessColumns;
                    return _public_assignment[index];
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

        }    // namespace blueprint
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_ASSIGNMENT_PLONK_HPP
