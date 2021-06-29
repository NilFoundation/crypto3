//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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
// @file Declaration of interfaces for a component that can be created from an R1CS constraint system.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_COMPONENT_FROM_R1CS_HPP
#define CRYPTO3_ZK_BLUEPRINT_COMPONENT_FROM_R1CS_HPP

#include <map>

#include <nil/crypto3/zk/components/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename FieldType>
                class component_from_r1cs : public component<FieldType> {

                    const std::vector<blueprint_variable_vector<FieldType>> vars;
                    const snark::r1cs_constraint_system<FieldType> cs;
                    std::map<std::size_t, std::size_t> cs_to_vars;

                public:
                    component_from_r1cs(blueprint<FieldType> &bp,
                                        const std::vector<blueprint_variable_vector<FieldType>> &vars,
                                        const snark::r1cs_constraint_system<FieldType> &cs) :
                        component<FieldType>(bp),
                        vars(vars), cs(cs) {
                        cs_to_vars[0] = 0; /* constant term maps to constant term */

                        std::size_t cs_var_idx = 1;
                        for (auto va : vars) {
                            for (auto v : va) {
                                cs_to_vars[cs_var_idx] = v.index;
                                ++cs_var_idx;
                            }
                        }

                        assert(cs_var_idx - 1 == cs.num_variables());
                    }

                    void generate_r1cs_constraints() {
                        for (std::size_t i = 0; i < cs.num_constraints(); ++i) {
                            const snark::r1cs_constraint<FieldType> &constr = cs.constraints[i];
                            snark::r1cs_constraint<FieldType> translated_constr;

                            for (const linear_term<FieldType> &t : constr.a.terms) {
                                translated_constr.a.terms.emplace_back(
                                    linear_term<FieldType>(variable<FieldType>(cs_to_vars[t.index]), t.coeff));
                            }

                            for (const linear_term<FieldType> &t : constr.b.terms) {
                                translated_constr.b.terms.emplace_back(
                                    linear_term<FieldType>(variable<FieldType>(cs_to_vars[t.index]), t.coeff));
                            }

                            for (const linear_term<FieldType> &t : constr.c.terms) {
                                translated_constr.c.terms.emplace_back(
                                    linear_term<FieldType>(variable<FieldType>(cs_to_vars[t.index]), t.coeff));
                            }

                            this->bp.add_r1cs_constraint(translated_constr);
                        }
                    }
                    void generate_r1cs_witness(const snark::r1cs_primary_input<FieldType> &primary_input,
                                               const snark::r1cs_auxiliary_input<FieldType> &auxiliary_input) {
                        assert(cs.num_inputs() == primary_input.size());
                        assert(cs.num_variables() == primary_input.size() + auxiliary_input.size());

                        for (std::size_t i = 0; i < primary_input.size(); ++i) {
                            this->bp.val(variable<FieldType>(cs_to_vars[i + 1])) = primary_input[i];
                        }

                        for (std::size_t i = 0; i < auxiliary_input.size(); ++i) {
                            this->bp.val(variable<FieldType>(cs_to_vars[primary_input.size() + i + 1])) =
                                auxiliary_input[i];
                        }
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_COMPONENT_FROM_R1CS_HPP
