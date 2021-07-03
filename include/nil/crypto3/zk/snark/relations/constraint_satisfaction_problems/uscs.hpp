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
// - a USCS constraint,
// - a USCS variable assignment, and
// - a USCS constraint system.
//
// Above, USCS stands for "Unitary-Square Constraint System".
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_USCS_HPP
#define CRYPTO3_ZK_USCS_HPP

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
                struct uscs_constraint_system {

                    std::size_t primary_input_size;
                    std::size_t auxiliary_input_size;

                    std::vector<uscs_constraint<FieldType>> constraints;

                    uscs_constraint_system() : primary_input_size(0), auxiliary_input_size(0) {};

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
                            if (!valid_vector(constraints[c], this->num_variables())) {
                                return false;
                            }
                        }

                        return true;
                    }

                    bool is_satisfied(const uscs_primary_input<FieldType> &primary_input,
                                      const uscs_auxiliary_input<FieldType> &auxiliary_input) const {
                        assert(primary_input.size() == num_inputs());
                        assert(primary_input.size() + auxiliary_input.size() == num_variables());

                        uscs_variable_assignment<FieldType> full_variable_assignment = primary_input;
                        full_variable_assignment.insert(
                            full_variable_assignment.end(), auxiliary_input.begin(), auxiliary_input.end());

                        for (std::size_t c = 0; c < constraints.size(); ++c) {
                            typename FieldType::value_type res = constraints[c].evaluate(full_variable_assignment);
                            if (!(res.squared() == FieldType::value_type::one())) {
                                return false;
                            }
                        }

                        return true;
                    }

                    void add_constraint(const uscs_constraint<FieldType> &constraint) {
                        constraints.emplace_back(constraint);
                    }

                    bool operator==(const uscs_constraint_system<FieldType> &other) const {
                        return (this->constraints == other.constraints &&
                                this->primary_input_size == other.primary_input_size &&
                                this->auxiliary_input_size == other.auxiliary_input_size);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_USCS_HPP
