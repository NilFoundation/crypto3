//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef USCS_EXAMPLES_HPP_
#define USCS_EXAMPLES_HPP_

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/uscs/uscs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A USCS example comprises a USCS constraint system, USCS input, and USCS witness.
                 */
                template<typename FieldType>
                struct uscs_example {
                    uscs_constraint_system<FieldType> constraint_system;
                    uscs_primary_input<FieldType> primary_input;
                    uscs_auxiliary_input<FieldType> auxiliary_input;

                    uscs_example<FieldType>() = default;
                    uscs_example<FieldType>(const uscs_example<FieldType> &other) = default;
                    uscs_example<FieldType>(const uscs_constraint_system<FieldType> &constraint_system,
                                         const uscs_primary_input<FieldType> &primary_input,
                                         const uscs_auxiliary_input<FieldType> &auxiliary_input) :
                        constraint_system(constraint_system),
                        primary_input(primary_input), auxiliary_input(auxiliary_input) {};
                    uscs_example<FieldType>(uscs_constraint_system<FieldType> &&constraint_system,
                                         uscs_primary_input<FieldType> &&primary_input,
                                         uscs_auxiliary_input<FieldType> &&auxiliary_input) :
                        constraint_system(std::move(constraint_system)),
                        primary_input(std::move(primary_input)), auxiliary_input(std::move(auxiliary_input)) {};
                };

                /**
                 * Generate a USCS example such that:
                 * - the number of constraints of the USCS constraint system is num_constraints;
                 * - the number of variables of the USCS constraint system is (approximately) num_constraints;
                 * - the number of inputs of the USCS constraint system is num_inputs;
                 * - the USCS input consists of ``full'' field elements (typically require the whole log|Field| bits to
                 * represent).
                 */
                template<typename FieldType>
                uscs_example<FieldType> generate_uscs_example_with_field_input(const size_t num_constraints,
                                                                            const size_t num_inputs);

                /**
                 * Generate a USCS example such that:
                 * - the number of constraints of the USCS constraint system is num_constraints;
                 * - the number of variables of the USCS constraint system is (approximately) num_constraints;
                 * - the number of inputs of the USCS constraint system is num_inputs;
                 * - the USCS input consists of binary values (as opposed to ``full'' field elements).
                 */
                template<typename FieldType>
                uscs_example<FieldType> generate_uscs_example_with_binary_input(const size_t num_constraints,
                                                                             const size_t num_inputs);

                template<typename FieldType>
                uscs_example<FieldType> generate_uscs_example_with_field_input(const size_t num_constraints,
                                                                            const size_t num_inputs) {
                    algebra::enter_block("Call to generate_uscs_example_with_field_input");

                    assert(num_inputs >= 1);
                    assert(num_constraints >= num_inputs);

                    uscs_constraint_system<FieldType> cs;
                    cs.primary_input_size = num_inputs;
                    cs.auxiliary_input_size = num_constraints - num_inputs;

                    uscs_variable_assignment<FieldType> full_variable_assignment;
                    for (size_t i = 0; i < num_constraints; ++i) {
                        full_variable_assignment.emplace_back(FieldType(std::rand()));
                    }

                    for (size_t i = 0; i < num_constraints; ++i) {
                        size_t x, y, z;

                        do {
                            x = std::rand() % num_constraints;
                            y = std::rand() % num_constraints;
                            z = std::rand() % num_constraints;
                        } while (x == z || y == z);

                        const FieldType x_coeff = FieldType(std::rand());
                        const FieldType y_coeff = FieldType(std::rand());
                        const FieldType val = (std::rand() % 2 == 0 ? FieldType::one() : -FieldType::one());
                        const FieldType z_coeff =
                            (val - x_coeff * full_variable_assignment[x] - y_coeff * full_variable_assignment[y]) *
                            full_variable_assignment[z].inverse();

                        uscs_constraint<FieldType> constr;
                        constr.add_term(x + 1, x_coeff);
                        constr.add_term(y + 1, y_coeff);
                        constr.add_term(z + 1, z_coeff);

                        cs.add_constraint(constr);
                    }

                    /* split variable assignment */
                    uscs_primary_input<FieldType> primary_input(full_variable_assignment.begin(),
                        full_variable_assignment.begin() + num_inputs);
                    uscs_primary_input<FieldType> auxiliary_input(full_variable_assignment.begin() + num_inputs,
                        full_variable_assignment.end());

                    /* sanity checks */
                    assert(cs.num_variables() == full_variable_assignment.size());
                    assert(cs.num_variables() >= num_inputs);
                    assert(cs.num_inputs() == num_inputs);
                    assert(cs.num_constraints() == num_constraints);
                    assert(cs.is_satisfied(primary_input, auxiliary_input));

                    algebra::leave_block("Call to generate_uscs_example_with_field_input");

                    return uscs_example<FieldType>(std::move(cs), std::move(primary_input), std::move(auxiliary_input));
                }

                template<typename FieldType>
                uscs_example<FieldType> generate_uscs_example_with_binary_input(const size_t num_constraints,
                                                                             const size_t num_inputs) {
                    algebra::enter_block("Call to generate_uscs_example_with_binary_input");

                    assert(num_inputs >= 1);

                    uscs_constraint_system<FieldType> cs;
                    cs.primary_input_size = num_inputs;
                    cs.auxiliary_input_size = num_constraints;

                    uscs_variable_assignment<FieldType> full_variable_assignment;
                    for (size_t i = 0; i < num_inputs; ++i) {
                        full_variable_assignment.push_back(FieldType(std::rand() % 2));
                    }

                    size_t lastvar = num_inputs - 1;
                    for (size_t i = 0; i < num_constraints; ++i) {
                        ++lastvar;

                        /* chose two random bits and XOR them together */
                        const size_t u = (i == 0 ? std::rand() % num_inputs : std::rand() % i);
                        const size_t v = (i == 0 ? std::rand() % num_inputs : std::rand() % i);

                        uscs_constraint<FieldType> constr;
                        constr.add_term(u + 1, 1);
                        constr.add_term(v + 1, 1);
                        constr.add_term(lastvar + 1, 1);
                        constr.add_term(0, -FieldType::one());    // shift constant term (which is 0) by 1

                        cs.add_constraint(constr);
                        full_variable_assignment.push_back(full_variable_assignment[u] + full_variable_assignment[v] -
                                                           full_variable_assignment[u] * full_variable_assignment[v] -
                                                           full_variable_assignment[u] * full_variable_assignment[v]);
                    }

                    /* split variable assignment */
                    uscs_primary_input<FieldType> primary_input(full_variable_assignment.begin(),
                        full_variable_assignment.begin() + num_inputs);
                    uscs_primary_input<FieldType> auxiliary_input(full_variable_assignment.begin() + num_inputs,
                        full_variable_assignment.end());

                    /* sanity checks */
                    assert(cs.num_variables() == full_variable_assignment.size());
                    assert(cs.num_variables() >= num_inputs);
                    assert(cs.num_inputs() == num_inputs);
                    assert(cs.num_constraints() == num_constraints);
                    assert(cs.is_satisfied(primary_input, auxiliary_input));

                    algebra::leave_block("Call to generate_uscs_example_with_binary_input");

                    return uscs_example<FieldType>(std::move(cs), std::move(primary_input), std::move(auxiliary_input));
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // USCS_EXAMPLES_HPP_
