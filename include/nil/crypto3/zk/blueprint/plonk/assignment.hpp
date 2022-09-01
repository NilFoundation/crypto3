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
            public:
                private_assignment_table() :
                    snark::plonk_private_assignment_table<BlueprintFieldType,
                        ArithmetizationParams>() {

                }

                zk::snark::plonk_column<BlueprintFieldType> &witness(std::uint32_t witness_index) {
                    BLUEPRINT_ASSERT(witness_index < ArithmetizationParams::WitnessColumns);
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

                std::size_t allocated_public_input_rows = 0;

            public:

                public_assignment_table() :
                    zk::snark::plonk_public_assignment_table<BlueprintFieldType,
                                                         ArithmetizationParams>(){
                }

                snark::plonk_column<BlueprintFieldType> &public_input(std::size_t public_input_index) {
                    BLUEPRINT_ASSERT(public_input_index < this->public_input_columns.size());
                    return this->public_input_columns[public_input_index];
                }

                snark::plonk_column<BlueprintFieldType> &constant(std::size_t constant_index) {
                    BLUEPRINT_ASSERT(constant_index < this->constant_columns.size());
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
