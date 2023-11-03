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
#include <unordered_map>
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
                using assignment_type = typename VariableType::assignment_type;

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
                
                std::size_t max_degree() const {
                    std::size_t max_degree = 0;
                    for (const term_type &nlt : this->terms) {
                        max_degree = std::max(max_degree, nlt.get_vars().size());
                    }
                    return max_degree;
                }

                void sort_terms_by_degree() {
                    std::sort(this->terms.begin(), this->terms.end(),[](term_type const& left, term_type const& right) {
                            return left.get_vars().size() > right.get_vars().size();
                        });
                }

                // Merges equal terms, and if some term has coefficient of 0, removes it.
                void merge_equal_terms() {
                    std::unordered_map<term_type, assignment_type> unique_terms;
                    for (const auto& term: this->terms) {
                        // Create a new term with variables only.
                        term_type vars(term.get_vars());
                        auto it = unique_terms.find(vars);
                        if (it != unique_terms.end()) {
                            unique_terms[vars] += term.get_coeff();
                        } else {
                            unique_terms[vars] = term.get_coeff();
                        }
                    }
                    this->terms.clear();
                    for (const auto& it: unique_terms) {
                        if (it.second != assignment_type::zero()) {
                            this->terms.emplace_back(it.first.get_vars(), it.second);
                        }
                    }
                }
                
                bool operator==(const non_linear_combination &other) const {
                    if (this->terms.size() != other.terms.size())
                        return false;

                    // Put both terms and other->terms into a hashmap, and check if
                    // everything is equal.
                    std::unordered_map<term_type, int> terms_map;
                    for (const auto& term: this->terms) {
                        auto iter = terms_map.find(term);
                        if (iter != terms_map.end()) {
                            iter->second++;
                        } else {
                            terms_map[term] = 1;
                        }
                    }

                    for (const auto& term: other.terms) {
                        auto iter = terms_map.find(term);
                        if (iter != terms_map.end()) {
                            iter->second--;
                        } else {
                            return false;
                        }
                    }

                    for (const auto& entry: terms_map) {
                        if (entry.second != 0)
                            return false;
                    }
                    return true;
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

            // Used in the unit tests, so we can use BOOST_CHECK_EQUALS, and see
            // the values of terms, when the check fails.
            template<typename VariableType>
            std::ostream& operator<<(std::ostream& os, const non_linear_combination<VariableType> &comb) {
                bool first = true;
                for (const auto& term: comb.terms) {
                    if (!first)
                        os << " + ";
                    os << term;
                    first = false;
                }
                return os;
            }

        }    // namespace math
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_MATH_NON_LINEAR_COMBINATION_HPP
