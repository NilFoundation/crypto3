//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for:
//
// - a R1CS constraint,
// - a R1CS variable assignment, and
// - a R1CS constraint system.
//
// Above, R1CS stands for "Rank-1 Constraint System".
//---------------------------------------------------------------------------//

#ifndef R1CS_HPP_
#define R1CS_HPP_

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

                /************************* R1CS constraint ***********************************/

                template<typename FieldType>
                class r1cs_constraint;

                template<typename FieldType>
                std::ostream &operator<<(std::ostream &out, const r1cs_constraint<FieldType> &c);

                template<typename FieldType>
                std::istream &operator>>(std::istream &in, r1cs_constraint<FieldType> &c);

                /**
                 * A R1CS constraint is a formal expression of the form
                 *
                 *                < A , X > * < B , X > = < C , X > ,
                 *
                 * where X = (x_0,x_1,...,x_m) is a vector of formal variables and A,B,C each
                 * consist of 1+m elements in <FieldType>.
                 *
                 * A R1CS constraint is used to construct a R1CS constraint system (see below).
                 */
                template<typename FieldType>
                class r1cs_constraint {
                public:
                    linear_combination<FieldType> a, b, c;

                    r1cs_constraint() {};
                    r1cs_constraint(const linear_combination<FieldType> &a,
                                    const linear_combination<FieldType> &b,
                                    const linear_combination<FieldType> &c);

                    r1cs_constraint(const std::initializer_list<linear_combination<FieldType>> &A,
                                    const std::initializer_list<linear_combination<FieldType>> &B,
                                    const std::initializer_list<linear_combination<FieldType>> &C);

                    bool operator==(const r1cs_constraint<FieldType> &other) const;

                    friend std::ostream &operator<<<FieldType>(std::ostream &out, const r1cs_constraint<FieldType> &c);
                    friend std::istream &operator>><FieldType>(std::istream &in, r1cs_constraint<FieldType> &c);
                };

                /************************* R1CS variable assignment **************************/

                /**
                 * A R1CS variable assignment is a vector of <FieldType> elements that represents
                 * a candidate solution to a R1CS constraint system (see below).
                 */

                /* TODO: specify that it does *NOT* include the constant 1 */
                template<typename FieldType>
                using r1cs_primary_input = std::vector<typename FieldType::value_type>;

                template<typename FieldType>
                using r1cs_auxiliary_input = std::vector<typename FieldType::value_type>;

                template<typename FieldType>
                using r1cs_variable_assignment =
                    std::vector<typename FieldType::value_type>; /* note the changed name! (TODO: remove this comment
 * after
                                            primary_input transition is complete) */

                /************************* R1CS constraint system ****************************/

                template<typename FieldType>
                class r1cs_constraint_system;

                template<typename FieldType>
                std::ostream &operator<<(std::ostream &out, const r1cs_constraint_system<FieldType> &cs);

                template<typename FieldType>
                std::istream &operator>>(std::istream &in, r1cs_constraint_system<FieldType> &cs);

                /**
                 * A system of R1CS constraints looks like
                 *
                 *     { < A_k , X > * < B_k , X > = < C_k , X > }_{k=1}^{n}  .
                 *
                 * In other words, the system is satisfied if and only if there exist a
                 * USCS variable assignment for which each R1CS constraint is satisfied.
                 *
                 * NOTE:
                 * The 0-th variable (i.e., "x_{0}") always represents the constant 1.
                 * Thus, the 0-th variable is not included in num_variables.
                 */
                template<typename FieldType>
                class r1cs_constraint_system {
                public:
                    std::size_t primary_input_size;
                    std::size_t auxiliary_input_size;

                    std::vector<r1cs_constraint<FieldType>> constraints;

                    r1cs_constraint_system() : primary_input_size(0), auxiliary_input_size(0) {
                    }

                    std::size_t num_inputs() const;
                    std::size_t num_variables() const;
                    std::size_t num_constraints() const;

                    bool is_valid() const;
                    bool is_satisfied(const r1cs_primary_input<FieldType> &primary_input,
                                      const r1cs_auxiliary_input<FieldType> &auxiliary_input) const;

                    void add_constraint(const r1cs_constraint<FieldType> &c);

                    void swap_AB_if_beneficial();

                    bool operator==(const r1cs_constraint_system<FieldType> &other) const;

                    friend std::ostream &operator<<<FieldType>(std::ostream &out,
                                                               const r1cs_constraint_system<FieldType> &cs);
                    friend std::istream &operator>><FieldType>(std::istream &in, r1cs_constraint_system<FieldType> &cs);
                };

                template<typename FieldType>
                r1cs_constraint<FieldType>::r1cs_constraint(const linear_combination<FieldType> &a,
                                                            const linear_combination<FieldType> &b,
                                                            const linear_combination<FieldType> &c) :
                    a(a),
                    b(b), c(c) {
                }

                template<typename FieldType>
                r1cs_constraint<FieldType>::r1cs_constraint(
                    const std::initializer_list<linear_combination<FieldType>> &A,
                    const std::initializer_list<linear_combination<FieldType>> &B,
                    const std::initializer_list<linear_combination<FieldType>> &C) {
                    for (auto lc_A : A) {
                        a.terms.insert(a.terms.end(), lc_A.terms.begin(), lc_A.terms.end());
                    }
                    for (auto lc_B : B) {
                        b.terms.insert(b.terms.end(), lc_B.terms.begin(), lc_B.terms.end());
                    }
                    for (auto lc_C : C) {
                        c.terms.insert(c.terms.end(), lc_C.terms.begin(), lc_C.terms.end());
                    }
                }

                template<typename FieldType>
                bool r1cs_constraint<FieldType>::operator==(const r1cs_constraint<FieldType> &other) const {
                    return (this->a == other.a && this->b == other.b && this->c == other.c);
                }

                template<typename FieldType>
                std::ostream &operator<<(std::ostream &out, const r1cs_constraint<FieldType> &c) {
                    out << c.a;
                    out << c.b;
                    out << c.c;

                    return out;
                }

                template<typename FieldType>
                std::istream &operator>>(std::istream &in, r1cs_constraint<FieldType> &c) {
                    in >> c.a;
                    in >> c.b;
                    in >> c.c;

                    return in;
                }

                template<typename FieldType>
                std::size_t r1cs_constraint_system<FieldType>::num_inputs() const {
                    return primary_input_size;
                }

                template<typename FieldType>
                std::size_t r1cs_constraint_system<FieldType>::num_variables() const {
                    return primary_input_size + auxiliary_input_size;
                }

                template<typename FieldType>
                std::size_t r1cs_constraint_system<FieldType>::num_constraints() const {
                    return constraints.size();
                }

                template<typename FieldType>
                bool r1cs_constraint_system<FieldType>::is_valid() const {
                    if (this->num_inputs() > this->num_variables())
                        return false;

                    for (std::size_t c = 0; c < constraints.size(); ++c) {
                        if (!(constraints[c].a.is_valid(this->num_variables()) &&
                              constraints[c].b.is_valid(this->num_variables()) &&
                              constraints[c].c.is_valid(this->num_variables()))) {
                            return false;
                        }
                    }

                    return true;
                }

                template<typename FieldType>
                bool r1cs_constraint_system<FieldType>::is_satisfied(
                    const r1cs_primary_input<FieldType> &primary_input,
                    const r1cs_auxiliary_input<FieldType> &auxiliary_input) const {
                    assert(primary_input.size() == num_inputs());
                    assert(primary_input.size() + auxiliary_input.size() == num_variables());

                    r1cs_variable_assignment<FieldType> full_variable_assignment = primary_input;
                    full_variable_assignment.insert(
                        full_variable_assignment.end(), auxiliary_input.begin(), auxiliary_input.end());

                    for (std::size_t c = 0; c < constraints.size(); ++c) {
                        const FieldType ares = constraints[c].a.evaluate(full_variable_assignment);
                        const FieldType bres = constraints[c].b.evaluate(full_variable_assignment);
                        const FieldType cres = constraints[c].c.evaluate(full_variable_assignment);

                        if (!(ares * bres == cres)) {
                            return false;
                        }
                    }

                    return true;
                }

                template<typename FieldType>
                void r1cs_constraint_system<FieldType>::add_constraint(const r1cs_constraint<FieldType> &c) {
                    constraints.emplace_back(c);
                }

                template<typename FieldType>
                void r1cs_constraint_system<FieldType>::swap_AB_if_beneficial() {
                    std::vector<bool> touched_by_A(this->num_variables() + 1, false),
                        touched_by_B(this->num_variables() + 1, false);

                    for (std::size_t i = 0; i < this->constraints.size(); ++i) {
                        for (std::size_t j = 0; j < this->constraints[i].a.terms.size(); ++j) {
                            touched_by_A[this->constraints[i].a.terms[j].index] = true;
                        }

                        for (std::size_t j = 0; j < this->constraints[i].b.terms.size(); ++j) {
                            touched_by_B[this->constraints[i].b.terms[j].index] = true;
                        }
                    }

                    std::size_t non_zero_A_count = 0, non_zero_B_count = 0;
                    for (std::size_t i = 0; i < this->num_variables() + 1; ++i) {
                        non_zero_A_count += touched_by_A[i] ? 1 : 0;
                        non_zero_B_count += touched_by_B[i] ? 1 : 0;
                    }

                    if (non_zero_B_count > non_zero_A_count) {
                        for (std::size_t i = 0; i < this->constraints.size(); ++i) {
                            std::swap(this->constraints[i].a, this->constraints[i].b);
                        }
                    }
                }

                template<typename FieldType>
                bool r1cs_constraint_system<FieldType>::operator==(
                    const r1cs_constraint_system<FieldType> &other) const {
                    return (this->constraints == other.constraints &&
                            this->primary_input_size == other.primary_input_size &&
                            this->auxiliary_input_size == other.auxiliary_input_size);
                }

                template<typename FieldType>
                std::ostream &operator<<(std::ostream &out, const r1cs_constraint_system<FieldType> &cs) {
                    out << cs.primary_input_size << "\n";
                    out << cs.auxiliary_input_size << "\n";

                    out << cs.num_constraints() << "\n";
                    for (const r1cs_constraint<FieldType> &c : cs.constraints) {
                        out << c;
                    }

                    return out;
                }

                template<typename FieldType>
                std::istream &operator>>(std::istream &in, r1cs_constraint_system<FieldType> &cs) {
                    in >> cs.primary_input_size;
                    in >> cs.auxiliary_input_size;

                    cs.constraints.clear();

                    std::size_t s;
                    in >> s;

                    char b;
                    in.read(&b, 1);

                    cs.constraints.reserve(s);

                    for (std::size_t i = 0; i < s; ++i) {
                        r1cs_constraint<FieldType> c;
                        in >> c;
                        cs.constraints.emplace_back(c);
                    }

                    return in;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // R1CS_HPP_
