//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for:
// - a USCS constraint,
// - a USCS variable assignment, and
// - a USCS constraint system.
//
// Above, USCS stands for "Unitary-Square Constraint System".
//---------------------------------------------------------------------------//

#ifndef USCS_HPP_
#define USCS_HPP_

#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <nil/crypto3/zk/snark/relations/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /************************* USCS constraint ***********************************/

                /**
                 * A USCS constraint is a formal expression of the form
                 *
                 *                \sum_{i=1}^{m} a_i * x_{i} ,
                 *
                 * where each a_i is in <FieldType> and each x_{i} is a formal variable.
                 *
                 * A USCS constraint is used to construct a USCS constraint system (see below).
                 */
                template<typename FieldType>
                using uscs_constraint = linear_combination<FieldType>;

                /************************* USCS variable assignment **************************/

                /**
                 * A USCS variable assignment is a vector of <FieldType> elements that represents
                 * a candidate solution to a USCS constraint system (see below).
                 */
                template<typename FieldType>
                using uscs_primary_input = std::vector<typename FieldType::value_type>;

                template<typename FieldType>
                using uscs_auxiliary_input = std::vector<typename FieldType::value_type>;

                template<typename FieldType>
                using uscs_variable_assignment = std::vector<typename FieldType::value_type>;

                /************************* USCS constraint system ****************************/

                template<typename FieldType>
                class uscs_constraint_system;

                template<typename FieldType>
                std::ostream &operator<<(std::ostream &out, const uscs_constraint_system<FieldType> &cs);

                template<typename FieldType>
                std::istream &operator>>(std::istream &in, uscs_constraint_system<FieldType> &cs);

                /**
                 * A system of USCS constraints looks like
                 *
                 *     { ( \sum_{i=1}^{m_k} a_{k,i} * x_{k,i} )^2 = 1 }_{k=1}^{n}  .
                 *
                 * In other words, the system is satisfied if and only if there exist a
                 * USCS variable assignment for which each USCS constraint evaluates to -1 or 1.
                 *
                 * NOTE:
                 * The 0-th variable (i.e., "x_{0}") always represents the constant 1.
                 * Thus, the 0-th variable is not included in num_variables.
                 */
                template<typename FieldType>
                class uscs_constraint_system {
                public:
                    std::size_t primary_input_size;
                    std::size_t auxiliary_input_size;

                    std::vector<uscs_constraint<FieldType>> constraints;

                    uscs_constraint_system() : primary_input_size(0), auxiliary_input_size(0) {};

                    std::size_t num_inputs() const;
                    std::size_t num_variables() const;
                    std::size_t num_constraints() const;

                    bool is_valid() const;
                    bool is_satisfied(const uscs_primary_input<FieldType> &primary_input,
                                      const uscs_auxiliary_input<FieldType> &auxiliary_input) const;

                    void add_constraint(const uscs_constraint<FieldType> &constraint);

                    bool operator==(const uscs_constraint_system<FieldType> &other) const;

                    friend std::ostream &operator<<<FieldType>(std::ostream &out,
                                                               const uscs_constraint_system<FieldType> &cs);
                    friend std::istream &operator>><FieldType>(std::istream &in, uscs_constraint_system<FieldType> &cs);

                    void report_linear_constraint_statistics() const;
                };

                template<typename FieldType>
                std::size_t uscs_constraint_system<FieldType>::num_inputs() const {
                    return primary_input_size;
                }

                template<typename FieldType>
                std::size_t uscs_constraint_system<FieldType>::num_variables() const {
                    return primary_input_size + auxiliary_input_size;
                }

                template<typename FieldType>
                std::size_t uscs_constraint_system<FieldType>::num_constraints() const {
                    return constraints.size();
                }

                template<typename FieldType>
                bool uscs_constraint_system<FieldType>::is_valid() const {
                    if (this->num_inputs() > this->num_variables())
                        return false;

                    for (std::size_t c = 0; c < constraints.size(); ++c) {
                        if (!valid_vector(constraints[c], this->num_variables())) {
                            return false;
                        }
                    }

                    return true;
                }

                template<typename FieldType>
                void dump_uscs_constraint(const uscs_constraint<FieldType> &constraint,
                                          const uscs_variable_assignment<FieldType> &full_variable_assignment,
                                          const std::map<std::size_t, std::string> &variable_annotations) {
                    printf("terms:\n");
                    constraint.print_with_assignment(full_variable_assignment, variable_annotations);
                }

                template<typename FieldType>
                bool uscs_constraint_system<FieldType>::is_satisfied(
                    const uscs_primary_input<FieldType> &primary_input,
                    const uscs_auxiliary_input<FieldType> &auxiliary_input) const {
                    assert(primary_input.size() == num_inputs());
                    assert(primary_input.size() + auxiliary_input.size() == num_variables());

                    uscs_variable_assignment<FieldType> full_variable_assignment = primary_input;
                    full_variable_assignment.insert(
                        full_variable_assignment.end(), auxiliary_input.begin(), auxiliary_input.end());

                    for (std::size_t c = 0; c < constraints.size(); ++c) {
                        FieldType res = constraints[c].evaluate(full_variable_assignment);
                        if (!(res.squared() == FieldType::one())) {
                            return false;
                        }
                    }

                    return true;
                }

                template<typename FieldType>
                void uscs_constraint_system<FieldType>::add_constraint(const uscs_constraint<FieldType> &c) {
                    constraints.emplace_back(c);
                }

                template<typename FieldType>
                bool uscs_constraint_system<FieldType>::operator==(
                    const uscs_constraint_system<FieldType> &other) const {
                    return (this->constraints == other.constraints &&
                            this->primary_input_size == other.primary_input_size &&
                            this->auxiliary_input_size == other.auxiliary_input_size);
                }

                template<typename FieldType>
                std::ostream &operator<<(std::ostream &out, const uscs_constraint_system<FieldType> &cs) {
                    out << cs.primary_input_size << "\n";
                    out << cs.auxiliary_input_size << "\n";

                    out << cs.num_constraints() << "\n";
                    for (const uscs_constraint<FieldType> &c : cs.constraints) {
                        out << c;
                    }

                    return out;
                }

                template<typename FieldType>
                std::istream &operator>>(std::istream &in, uscs_constraint_system<FieldType> &cs) {
                    in >> cs.primary_input_size;
                    in >> cs.auxiliary_input_size;

                    cs.constraints.clear();

                    std::size_t s;
                    in >> s;

                    char b;
                    in.read(&b, 1);

                    cs.constraints.reserve(s);

                    for (std::size_t i = 0; i < s; ++i) {
                        uscs_constraint<FieldType> c;
                        in >> c;
                        cs.constraints.emplace_back(c);
                    }

                    return in;
                }

                template<typename FieldType>
                void uscs_constraint_system<FieldType>::report_linear_constraint_statistics() const {
#ifdef DEBUG
                    for (std::size_t i = 0; i < constraints.size(); ++i) {
                        auto &constr = constraints[i];
                        bool a_is_const = true;
                        for (auto &t : constr.terms) {
                            a_is_const = a_is_const && (t.index == 0);
                        }

                        if (a_is_const) {
                            auto it = constraint_annotations.find(i);
                            printf("%s\n",
                                   (it == constraint_annotations.end() ? FMT("", "constraint_%zu", i) : it->second)
                                       .c_str());
                        }
                    }
#endif
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // USCS_HPP_
