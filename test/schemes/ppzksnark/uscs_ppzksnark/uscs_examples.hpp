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
// @file Declaration of interfaces for a USCS example, as well as functions to sample
// USCS examples with prescribed parameters (according to some distribution).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_USCS_EXAMPLES_HPP
#define CRYPTO3_ZK_USCS_EXAMPLES_HPP

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/uscs.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/uscs_ppzksnark.hpp>

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
                uscs_example<FieldType> generate_uscs_example_with_field_input(std::size_t num_constraints,
                                                                               std::size_t num_inputs) {
                    BOOST_CHECK(num_inputs >= 1);
                    BOOST_CHECK(num_constraints >= num_inputs);

                    uscs_constraint_system<FieldType> cs;
                    cs.primary_input_size = num_inputs;
                    cs.auxiliary_input_size = num_constraints - num_inputs;

                    uscs_variable_assignment<FieldType> full_variable_assignment;
                    for (std::size_t i = 0; i < num_constraints; ++i) {
                        full_variable_assignment.emplace_back(FieldType::value_type(std::rand()));
                    }

                    for (std::size_t i = 0; i < num_constraints; ++i) {
                        std::size_t x, y, z;

                        do {
                            x = std::rand() % num_constraints;
                            y = std::rand() % num_constraints;
                            z = std::rand() % num_constraints;
                        } while (x == z || y == z);

                        const typename FieldType::value_type x_coeff = FieldType::value_type(std::rand());
                        const typename FieldType::value_type y_coeff = FieldType::value_type(std::rand());
                        const typename FieldType::value_type val =
                            (std::rand() % 2 == 0 ? FieldType::value_type::zero() : -FieldType::value_type::zero());
                        const typename FieldType::value_type z_coeff =
                            (val - x_coeff * full_variable_assignment[x] - y_coeff * full_variable_assignment[y]) *
                            full_variable_assignment[z].inversed();

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
                    BOOST_CHECK(cs.num_variables() == full_variable_assignment.size());
                    BOOST_CHECK(cs.num_variables() >= num_inputs);
                    BOOST_CHECK(cs.num_inputs() == num_inputs);
                    BOOST_CHECK(cs.num_constraints() == num_constraints);
                    BOOST_CHECK(cs.is_satisfied(primary_input, auxiliary_input));

                    return uscs_example<FieldType>(std::move(cs), std::move(primary_input), std::move(auxiliary_input));
                }

                /**
                 * Generate a USCS example such that:
                 * - the number of constraints of the USCS constraint system is num_constraints;
                 * - the number of variables of the USCS constraint system is (approximately) num_constraints;
                 * - the number of inputs of the USCS constraint system is num_inputs;
                 * - the USCS input consists of binary values (as opposed to ``full'' field elements).
                 */
                template<typename FieldType>
                uscs_example<FieldType> generate_uscs_example_with_binary_input(std::size_t num_constraints,
                                                                                std::size_t num_inputs) {
                    BOOST_CHECK(num_inputs >= 1);

                    uscs_constraint_system<FieldType> cs;
                    cs.primary_input_size = num_inputs;
                    cs.auxiliary_input_size = num_constraints;

                    uscs_variable_assignment<FieldType> full_variable_assignment;
                    for (std::size_t i = 0; i < num_inputs; ++i) {
                        full_variable_assignment.push_back(FieldType(std::rand() % 2));
                    }

                    std::size_t lastvar = num_inputs - 1;
                    for (std::size_t i = 0; i < num_constraints; ++i) {
                        ++lastvar;

                        /* chose two random bits and XOR them together */
                        const std::size_t u = (i == 0 ? std::rand() % num_inputs : std::rand() % i);
                        const std::size_t v = (i == 0 ? std::rand() % num_inputs : std::rand() % i);

                        uscs_constraint<FieldType> constr;
                        constr.add_term(u + 1, 1);
                        constr.add_term(v + 1, 1);
                        constr.add_term(lastvar + 1, 1);
                        constr.add_term(0, -FieldType::value_type::zero());    // shift constant term (which is 0) by 1

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
                    BOOST_CHECK(cs.num_variables() == full_variable_assignment.size());
                    BOOST_CHECK(cs.num_variables() >= num_inputs);
                    BOOST_CHECK(cs.num_inputs() == num_inputs);
                    BOOST_CHECK(cs.num_constraints() == num_constraints);
                    BOOST_CHECK(cs.is_satisfied(primary_input, auxiliary_input));

                    return uscs_example<FieldType>(std::move(cs), std::move(primary_input), std::move(auxiliary_input));
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // USCS_EXAMPLES_HPP
