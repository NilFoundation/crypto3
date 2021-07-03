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
// @file Declaration of interfaces for:
//
// - a R1CS constraint,
// - a R1CS variable assignment, and
// - a R1CS constraint system.
//
// Above, R1CS stands for "Rank-1 Constraint System".
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_R1CS_HPP
#define CRYPTO3_ZK_R1CS_HPP

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
                struct r1cs_constraint {

                    linear_combination<FieldType> a, b, c;

                    r1cs_constraint() {};
                    r1cs_constraint(const linear_combination<FieldType> &a,
                                    const linear_combination<FieldType> &b,
                                    const linear_combination<FieldType> &c) :
                        a(a),
                        b(b), c(c) {
                    }

                    r1cs_constraint(const std::initializer_list<linear_combination<FieldType>> &A,
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

                    bool operator==(const r1cs_constraint<FieldType> &other) const {
                        return (this->a == other.a && this->b == other.b && this->c == other.c);
                    }
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
                using r1cs_variable_assignment = std::vector<typename FieldType::value_type>;

                /************************* R1CS constraint system ****************************/

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
                struct r1cs_constraint_system {

                    std::size_t primary_input_size;
                    std::size_t auxiliary_input_size;

                    std::vector<r1cs_constraint<FieldType>> constraints;

                    r1cs_constraint_system() : primary_input_size(0), auxiliary_input_size(0) {
                    }

                    std::size_t num_inputs() const {
                        return primary_input_size;
                    }

                    std::size_t num_variables() const {
                        return primary_input_size + auxiliary_input_size;
                    }

                    std::size_t num_constraints() const {
                        return constraints.size();
                    }

                    bool is_valid() const {
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

                    bool is_satisfied(const r1cs_primary_input<FieldType> &primary_input,
                                      const r1cs_auxiliary_input<FieldType> &auxiliary_input) const {
                        assert(primary_input.size() == num_inputs());
                        assert(primary_input.size() + auxiliary_input.size() == num_variables());

                        r1cs_variable_assignment<FieldType> full_variable_assignment = primary_input;
                        full_variable_assignment.insert(
                            full_variable_assignment.end(), auxiliary_input.begin(), auxiliary_input.end());

                        for (std::size_t c = 0; c < constraints.size(); ++c) {
                            const typename FieldType::value_type ares =
                                constraints[c].a.evaluate(full_variable_assignment);
                            const typename FieldType::value_type bres =
                                constraints[c].b.evaluate(full_variable_assignment);
                            const typename FieldType::value_type cres =
                                constraints[c].c.evaluate(full_variable_assignment);

                            if (!(ares * bres == cres)) {
                                return false;
                            }
                        }

                        return true;
                    }

                    void add_constraint(const r1cs_constraint<FieldType> &c) {
                        constraints.emplace_back(c);
                    }

                    void swap_AB_if_beneficial() {
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

                    bool operator==(const r1cs_constraint_system<FieldType> &other) const {
                        return (this->constraints == other.constraints &&
                                this->primary_input_size == other.primary_input_size &&
                                this->auxiliary_input_size == other.auxiliary_input_size);
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_HPP
