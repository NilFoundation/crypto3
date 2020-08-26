//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a gadget that can be created from an R1CS constraint system.
//---------------------------------------------------------------------------//

#ifndef GADGET_FROM_R1CS_HPP_
#define GADGET_FROM_R1CS_HPP_

#include <map>

#include <nil/crypto3/zk/snark/gadget.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class gadget_from_r1cs : public gadget<FieldType> {

                private:
                    const std::vector<pb_variable_array<FieldType>> vars;
                    const r1cs_constraint_system<FieldType> cs;
                    std::map<std::size_t, std::size_t> cs_to_vars;

                public:
                    gadget_from_r1cs(protoboard<FieldType> &pb,
                                     const std::vector<pb_variable_array<FieldType>> &vars,
                                     const r1cs_constraint_system<FieldType> &cs);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness(const r1cs_primary_input<FieldType> &primary_input,
                                               const r1cs_auxiliary_input<FieldType> &auxiliary_input);
                };

                template<typename FieldType>
                gadget_from_r1cs<FieldType>::gadget_from_r1cs(protoboard<FieldType> &pb,
                                                              const std::vector<pb_variable_array<FieldType>> &vars,
                                                              const r1cs_constraint_system<FieldType> &cs) :
                    gadget<FieldType>(pb),
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

                template<typename FieldType>
                void gadget_from_r1cs<FieldType>::generate_r1cs_constraints() {
                    for (std::size_t i = 0; i < cs.num_constraints(); ++i) {
                        const r1cs_constraint<FieldType> &constr = cs.constraints[i];
                        r1cs_constraint<FieldType> translated_constr;

                        for (const linear_term<FieldType> &t : constr.a.terms) {
                            translated_constr.a.terms.emplace_back(
                                linear_term<FieldType>(pb_variable<FieldType>(cs_to_vars[t.index]), t.coeff));
                        }

                        for (const linear_term<FieldType> &t : constr.b.terms) {
                            translated_constr.b.terms.emplace_back(
                                linear_term<FieldType>(pb_variable<FieldType>(cs_to_vars[t.index]), t.coeff));
                        }

                        for (const linear_term<FieldType> &t : constr.c.terms) {
                            translated_constr.c.terms.emplace_back(
                                linear_term<FieldType>(pb_variable<FieldType>(cs_to_vars[t.index]), t.coeff));
                        }

                        this->pb.add_r1cs_constraint(translated_constr);
                    }
                }

                template<typename FieldType>
                void gadget_from_r1cs<FieldType>::generate_r1cs_witness(
                    const r1cs_primary_input<FieldType> &primary_input,
                    const r1cs_auxiliary_input<FieldType> &auxiliary_input) {
                    assert(cs.num_inputs() == primary_input.size());
                    assert(cs.num_variables() == primary_input.size() + auxiliary_input.size());

                    for (std::size_t i = 0; i < primary_input.size(); ++i) {
                        this->pb.val(pb_variable<FieldType>(cs_to_vars[i + 1])) = primary_input[i];
                    }

                    for (std::size_t i = 0; i < auxiliary_input.size(); ++i) {
                        this->pb.val(pb_variable<FieldType>(cs_to_vars[primary_input.size() + i + 1])) =
                            auxiliary_input[i];
                    }
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // GADGET_FROM_R1CS_HPP_
