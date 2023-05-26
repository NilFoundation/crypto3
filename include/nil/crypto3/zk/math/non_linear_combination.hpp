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
// @file Declaration of interfaces for:
// - a variable (i.e., x_i),
// - a linear term (i.e., a_i * x_i), and
// - a linear combination (i.e., sum_i a_i * x_i).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_MATH_NON_LINEAR_COMBINATION_HPP
#define CRYPTO3_ZK_MATH_NON_LINEAR_COMBINATION_HPP

#include <vector>
#include <nil/crypto3/zk/math/expression.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            /**
             * Forward declaration.
             */
            template<typename VariableType>
            struct non_linear_combination {

                using term_type = term<VariableType>;
                using variable_type = VariableType;
                
                std::vector<term_type> terms;

                non_linear_combination() {};

                non_linear_combination(const VariableType &var) {
                    this->add_term(var);
                }

                non_linear_combination(const term_type &nlt) {
                    this->add_term(nlt);
                }

                non_linear_combination(const std::vector<term_type> &terms) : terms(terms) {
                }

                /* for supporting range-based for loops over non_linear_combination */
                typename std::vector<term_type>::const_iterator begin() const {
                    return terms.begin();
                }

                typename std::vector<term_type>::const_iterator end() const {
                    return terms.end();
                }

                void add_term(const VariableType &var) {
                    this->terms.emplace_back(term_type(var));
                }
                void add_term(const VariableType &var, const typename VariableType::assignment_type &field_coeff) {
                    this->terms.emplace_back(term_type(var) * field_coeff);
                }
                void add_term(const term_type &nlt) {
                    this->terms.emplace_back(nlt);
                }

                non_linear_combination operator*(const typename VariableType::assignment_type &field_coeff) const {
                    non_linear_combination result;
                    result.terms.reserve(this->terms.size());
                    for (const term_type &nlt : this->terms) {
                        result.terms.emplace_back(nlt * field_coeff);
                    }
                    return result;
                }

                non_linear_combination operator+(const non_linear_combination &other) const {
                    non_linear_combination result;

                    result.terms.insert(result.terms.end(), this->terms.begin(), this->terms.end());
                    result.terms.insert(result.terms.end(), other.terms.begin(), other.terms.end());

                    return result;
                }
                non_linear_combination operator-(const non_linear_combination &other) const {
                    return (*this) + (-other);
                }
                non_linear_combination operator-() const {
                    return (*this) * (-VariableType::assignment_type::one());
                }

                void sort() {
                    std::sort(terms.begin(), terms.end());
                    std::vector<term_type> new_terms;

                    if (terms.size()) {
                        new_terms.push_back(terms[0]);

                        for (std::size_t i = 1; i < terms.size(); i++) {
                            if (terms[i].vars == terms[i - 1].vars) {
                                (new_terms.end() - 1)->coeff += terms[i].coeff;
                            } else {
                                new_terms.push_back(terms[i]);
                            }
                        }
                    }
                }

                bool operator==(const non_linear_combination &other) {

                    this->sort();
                    other.sort();

                    return (this->terms == other.terms);
                }

                std::size_t max_degree() const {
                    std::size_t max_degree = 0;
                    for (const term_type &nlt : this->terms) {
                        max_degree = std::max(max_degree, nlt.vars.size());
                    }
                    return max_degree;
                }
            };

            template<typename VariableType>
            non_linear_combination<VariableType>
                operator*(const typename VariableType::assignment_type &field_coeff,
                          const non_linear_combination<VariableType> &lc) {
                return lc * field_coeff;
            }

            template<typename VariableType>
            non_linear_combination<VariableType> operator*(const non_linear_combination<VariableType> &A,
                                                           const non_linear_combination<VariableType> &B) {
                non_linear_combination<VariableType> result;
                result.terms.reserve(A.terms.size() * B.terms.size());

                for (const typename non_linear_combination<VariableType>::term_type &this_nlt : A.terms) {
                    for (const typename non_linear_combination<VariableType>::term_type &other_nlt : B.terms) {
                        result.terms.emplace_back(this_nlt * other_nlt);
                    }
                }
                return result;
            }

            template<typename VariableType>
            non_linear_combination<VariableType> operator*(const VariableType &var,
                                                           const non_linear_combination<VariableType> &A) {
                non_linear_combination<VariableType> result;
                result.terms.reserve(A.terms.size());

                for (const typename non_linear_combination<VariableType>::term_type &this_nlt : A.terms) {
                    result.terms.emplace_back(this_nlt * var);
                }
                return result;
            }

            template<typename VariableType>
            non_linear_combination<VariableType> operator*(const non_linear_combination<VariableType> &A,
                                                           const VariableType &var) {
                non_linear_combination<VariableType> result;
                result.terms.reserve(A.terms.size());

                for (const typename non_linear_combination<VariableType>::term_type &this_nlt : A.terms) {
                    result.terms.emplace_back(this_nlt * var);
                }
                return result;
            }

            template<typename VariableType>
            non_linear_combination<VariableType>
                operator+(const typename VariableType::assignment_type &field_coeff,
                          const non_linear_combination<VariableType> &lc) {
                return non_linear_combination<VariableType>(field_coeff) + lc;
            }

            template<typename VariableType>
            non_linear_combination<VariableType>
                operator+(const term<VariableType> &nlt,
                          const non_linear_combination<VariableType> &lc) {
                return non_linear_combination<VariableType>(nlt) + lc;
            }

            template<typename VariableType>
            non_linear_combination<VariableType>
                operator+(const non_linear_combination<VariableType> &lc,
                          const typename VariableType::assignment_type &field_coeff) {

                return field_coeff + lc;
            }

            template<typename VariableType>
            non_linear_combination<VariableType>
                operator-(const typename VariableType::assignment_type &field_coeff,
                          const non_linear_combination<VariableType> &lc) {
                return non_linear_combination<VariableType>(field_coeff) - lc;
            }

            template<typename VariableType>
            non_linear_combination<VariableType>
                operator-(const non_linear_combination<VariableType> &lc,
                          const typename VariableType::assignment_type &field_coeff) {

                return -(field_coeff - lc);
            }

            template<typename VariableType>
            non_linear_combination<VariableType>
                operator-(const term<VariableType> &term,
                          const non_linear_combination<VariableType> &lc) {
                return non_linear_combination<VariableType>(term) - lc;
            }

            template<typename VariableType>
            non_linear_combination<VariableType>
                operator-(const non_linear_combination<VariableType> &lc,
                    const term<VariableType> &term) {
                return lc - non_linear_combination<VariableType>(term);
            }
        }    // namespace math
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_MATH_NON_LINEAR_COMBINATION_HPP
