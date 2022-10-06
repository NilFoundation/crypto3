//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_BLUEPRINT_PLONK_HPP
#define CRYPTO3_ZK_BLUEPRINT_BLUEPRINT_PLONK_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {

            template<typename ArithmetizationType, std::size_t... BlueprintParams>
            class blueprint;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            class blueprint<snark::plonk_constraint_system<BlueprintFieldType,
                                                           ArithmetizationParams>>
                : public snark::plonk_constraint_system<BlueprintFieldType,
                                                        ArithmetizationParams> {

                typedef snark::plonk_constraint_system<BlueprintFieldType,
                                                       ArithmetizationParams> ArithmetizationType;

                snark::plonk_table_description<BlueprintFieldType,
                        ArithmetizationParams> &_table_description;
            public:
                typedef BlueprintFieldType blueprint_field_type;

                blueprint(snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> arithmetization_type_in, snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> &table_description) :
                        ArithmetizationType(arithmetization_type_in), _table_description(table_description) { }

                blueprint(snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> &table_description) :
                    ArithmetizationType(), _table_description(table_description) {
                    _table_description.rows_amount = 0;
                }

                std::size_t allocate_rows(std::size_t required_amount = 1) {
                    std::size_t result = _table_description.rows_amount;
                    _table_description.rows_amount += required_amount;
                    return result;
                }

                std::size_t allocate_row() {
                    return allocate_rows(1);
                }

                // TODO: should put constraint in some storage and return its index
                snark::plonk_constraint<BlueprintFieldType>
                    add_constraint(const snark::plonk_constraint<BlueprintFieldType> &constraint) {
                    return constraint;
                }

                void add_gate(std::size_t selector_index,
                              const snark::plonk_constraint<BlueprintFieldType> &constraint) {
                    this->_gates.emplace_back(selector_index, constraint);
                }

                void add_gate(std::size_t selector_index,
                              const std::initializer_list<snark::plonk_constraint<BlueprintFieldType>> &constraints) {
                    this->_gates.emplace_back(selector_index, constraints);
                }

                void add_gate(snark::plonk_gate<BlueprintFieldType, snark::plonk_constraint<BlueprintFieldType>> &gate) {
                    this->_gates.emplace_back(gate);
                }

                snark::plonk_constraint<BlueprintFieldType>
                    add_bit_check(const snark::plonk_variable<BlueprintFieldType> &bit_variable) {
                    return add_constraint(bit_variable * (bit_variable - 1));
                }

                void add_copy_constraint(const snark::plonk_copy_constraint<BlueprintFieldType> &copy_constraint) {
                    if (copy_constraint.first == copy_constraint.second) {
                        return;
                    }
                    this->_copy_constraints.emplace_back(copy_constraint);
                }

                snark::plonk_lookup_constraint<BlueprintFieldType>
                    add_lookup_constraint(std::vector<math::non_linear_term<snark::plonk_variable<BlueprintFieldType>>> lookup_input, 
                    std::vector<snark::plonk_variable<BlueprintFieldType>> lookup_value) {
                    snark::plonk_lookup_constraint<BlueprintFieldType> lookup_constraint;
                    lookup_constraint.lookup_input = lookup_input;
                    lookup_constraint.lookup_value = lookup_value;
                    return lookup_constraint;
                }


                void add_lookup_gate(std::size_t selector_index,
                              const std::initializer_list<snark::plonk_lookup_constraint<BlueprintFieldType>> &constraints) {
                    this->_lookup_gates.emplace_back(selector_index, constraints);
                }

                snark::plonk_table_description<BlueprintFieldType,
                        ArithmetizationParams> table_description() const {
                    return _table_description;
                }
            };
        }    // namespace zk
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_BLUEPRINT_PLONK_HPP
