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

#ifndef CRYPTO3_ZK_BLUEPRINT_BLUEPRINT_PLONK_HPP
#define CRYPTO3_ZK_BLUEPRINT_BLUEPRINT_PLONK_HPP

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>

#include <nil/crypto3/zk/components/blueprint_variable.hpp>
#include <nil/crypto3/zk/components/blueprint_linear_combination.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType>
                class blueprint;

                template<typename BlueprintFieldType, std::size_t WitnessColumns>
                class blueprint<snark::plonk_constraint_system<BlueprintFieldType, WitnessColumns>> :
                    public snark::plonk_constraint_system<BlueprintFieldType, WitnessColumns>> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, WitnessColumns> ArithmetizationType;
                public:
                    
                    blueprint() : ArithmetizationType(){
                    }

                    std::size_t allocate_rows(std::size_t required_amount = 1) {
                        static std::size_t next_row = 0;
                        std::size_t result = next_row;
                        next_row += required_amount;
                        return result;
                    }

                    void add_gate(std::size_t selector_index, const snark::plonk_constraint<TBlueprintField> &constraint) {
                        constraint_system.gates.emplace_back(selector_index, constraint);
                    }

                    void add_gate(std::size_t selector_index,
                                  const std::initializer_list<snark::plonk_constraint<TBlueprintField>> &constraints) {
                        constraint_system.gates.emplace_back(selector_index, constraints);
                    }

                    void add_copy_constraint(value_type &A, value_type &B) {
                        if (A.copy_constraint_index == 0 && B.copy_constraint_index == 0){
                            std::vector<value_type> copy_constraint = {A, B};
                            copy_constraints.push_back(copy_constraint);
                            A.copy_constraint_index = B.copy_constraint_index = copy_constraints.size() + 1;
                        } else {

                            if (A.copy_constraint_index != B.copy_constraint_index){
                                value_type &left = A;
                                value_type &right = B;
                                if (copy_constraints[A.copy_constraint_index].size() < 
                                    copy_constraints[B.copy_constraint_index].size()){
                                    left = B;
                                    right = A;
                                }

                                std::copy(copy_constraints[right.copy_constraint_index].begin(), 
                                    copy_constraints[right.copy_constraint_index].end(),
                                    copy_constraints[left.copy_constraint_index].end());
                                for (value_type & var: copy_constraints[right.copy_constraint_index]){
                                    var.copy_constraint_index = left.copy_constraint_index;
                                }

                                copy_constraints[right.copy_constraint_index].resize(0);
                            }
                        }
                    }

                    bool is_satisfied() const {
                        return constraint_system.is_satisfied(assignments);
                    }

                    std::size_t num_constraints() const {
                        return constraint_system.num_constraints();
                    }

                    constexpr std::size_t num_wires() {
                        return WitnessColumns;
                    }

                    snark::plonk_variable_assignment<TBlueprintField, WitnessColumns> full_variable_assignment() const {
                        return assignments;
                    }

                    ArithmetizationType get_constraint_system() const {
                        return constraint_system;
                    }

                    friend class blueprint_variable<TBlueprintField>;
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_BLUEPRINT_PLONK_HPP
