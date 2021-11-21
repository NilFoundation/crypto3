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

#ifndef CRYPTO3_ZK_LINEAR_COMBINATION_HPP
#define CRYPTO3_ZK_LINEAR_COMBINATION_HPP

#include <nil/crypto3/zk/snark/relations/variable.hpp>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Forward declaration.
                 */
                template<typename FieldType, bool RotationSupport>
                struct linear_combination;

                /****************************** Linear term **********************************/

                /**
                 * A linear term represents a formal expression of the form "coeff * x_{index}".
                 */
                template<typename FieldType, bool RotationSupport = false>
                class linear_term;

                template<typename FieldType>
                class linear_term<FieldType, false> {
                    typedef FieldType field_type;
                    typedef typename field_type::value_type field_value_type;

                    constexpr static const bool RotationSupport = false;

                public:
                    typename variable<FieldType, RotationSupport>::index_type index;
                    field_value_type coeff;

                    linear_term() {};
                    linear_term(const variable<field_type> &var) : index(var.index), coeff(field_value_type::one()) {
                    }

                    linear_term operator*(const field_value_type &field_coeff) const {
                        linear_term result(this->index);
                        result.coeff = field_coeff * this->coeff;
                        return result;
                    }

                    linear_combination<field_type, RotationSupport> operator+(
                        const linear_combination<field_type, RotationSupport> &other) const {
                        return linear_combination<field_type, RotationSupport>(*this) + other;
                    }

                    linear_combination<field_type, RotationSupport> operator-(
                        const linear_combination<field_type, RotationSupport> &other) const {
                        return (*this) + (-other);
                    }

                    linear_term operator-() const {
                        return linear_term(this->index) *(-this->coeff);
                    }

                    bool operator==(const linear_term &other) const {
                        return (this->index == other.index && this->coeff == other.coeff);
                    }
                };

                template<typename FieldType, bool RotationSupport>
                linear_term<FieldType, RotationSupport> operator*(const typename FieldType::value_type &field_coeff,
                                                 const linear_term<FieldType, RotationSupport> &lt) {
                    return lt * field_coeff;
                }

                template<typename FieldType, bool RotationSupport>
                linear_combination<FieldType, RotationSupport> operator+(const typename FieldType::value_type &field_coeff,
                                                        const linear_term<FieldType, RotationSupport> &lt) {
                    return linear_combination<FieldType, RotationSupport>(field_coeff) + lt;
                }

                template<typename FieldType, bool RotationSupport>
                linear_combination<FieldType, RotationSupport> operator-(const typename FieldType::value_type &field_coeff,
                                                        const linear_term<FieldType, RotationSupport> &lt) {
                    return linear_combination<FieldType, RotationSupport>(field_coeff) - lt;
                }

                /***************************** Linear combination ****************************/

                /**
                 * A linear combination represents a formal expression of the form "sum_i coeff_i * x_{index_i}".
                 */
                template<typename FieldType>
                class linear_combination<FieldType, false> {
                    typedef FieldType field_type;
                    typedef typename field_type::value_type field_value_type;
                    
                    constexpr static const bool RotationSupport = false;

                public:
                    std::vector<linear_term<FieldType, RotationSupport>> terms;

                    linear_combination() {};
                    linear_combination(const field_value_type &field_coeff) {
                        this->add_term(linear_term<FieldType, RotationSupport>(0) * field_coeff);
                    }
                    linear_combination(const variable<FieldType, RotationSupport> &var) {
                        this->add_term(var);
                    }
                    linear_combination(const linear_term<FieldType, RotationSupport> &lt) {
                        this->add_term(lt);
                    }
                    linear_combination(const std::vector<linear_term<FieldType, RotationSupport>> &all_terms) {
                        if (all_terms.empty()) {
                            return;
                        }

                        terms = all_terms;
                        std::sort(terms.begin(), terms.end(),
                                  [](linear_term<FieldType, RotationSupport> a, linear_term<FieldType, RotationSupport> b) { return a.index < b.index; });

                        auto result_it = terms.begin();
                        for (auto it = ++terms.begin(); it != terms.end(); ++it) {
                            if (it->index == result_it->index) {
                                result_it->coeff += it->coeff;
                            } else {
                                *(++result_it) = *it;
                            }
                        }
                        terms.resize((result_it - terms.begin()) + 1);
                    }

                    /* for supporting range-based for loops over linear_combination */
                    typename std::vector<linear_term<FieldType, RotationSupport>>::const_iterator begin() const {
                        return terms.begin();
                    }

                    typename std::vector<linear_term<FieldType, RotationSupport>>::const_iterator end() const {
                        return terms.end();
                    }

                    void add_term(const variable<FieldType, RotationSupport> &var) {
                        this->terms.emplace_back(linear_term<FieldType, RotationSupport>(var));
                    }
                    void add_term(const variable<FieldType, RotationSupport> &var, const field_value_type &field_coeff) {
                        this->terms.emplace_back(linear_term<FieldType, RotationSupport>(var) * field_coeff);
                    }
                    void add_term(const linear_term<FieldType, RotationSupport> &lt) {
                        this->terms.emplace_back(lt);
                    }

                    field_value_type evaluate(const std::vector<field_value_type> &assignment) const {
                        field_value_type acc = field_value_type::zero();
                        for (auto &lt : terms) {
                            acc += (lt.index == 0 ? field_value_type::one() : assignment[lt.index - 1]) * lt.coeff;
                        }
                        return acc;
                    }
                    linear_combination operator*(const field_value_type &field_coeff) const {
                        linear_combination result;
                        result.terms.reserve(this->terms.size());
                        for (const linear_term<FieldType, RotationSupport> &lt : this->terms) {
                            result.terms.emplace_back(lt * field_coeff);
                        }
                        return result;
                    }
                    linear_combination operator+(const linear_combination &other) const {
                        linear_combination result;

                        auto it1 = this->terms.begin();
                        auto it2 = other.terms.begin();

                        /* invariant: it1 and it2 always point to unprocessed items in the corresponding linear
                         * combinations
                         */
                        while (it1 != this->terms.end() && it2 != other.terms.end()) {
                            if (it1->index < it2->index) {
                                result.terms.emplace_back(*it1);
                                ++it1;
                            } else if (it1->index > it2->index) {
                                result.terms.emplace_back(*it2);
                                ++it2;
                            } else {
                                /* it1->index == it2->index */
                                result.terms.emplace_back(
                                    linear_term<FieldType, RotationSupport>(variable<FieldType, RotationSupport>(it1->index)) * (it1->coeff + it2->coeff));
                                ++it1;
                                ++it2;
                            }
                        }

                        if (it1 != this->terms.end()) {
                            result.terms.insert(result.terms.end(), it1, this->terms.end());
                        } else {
                            result.terms.insert(result.terms.end(), it2, other.terms.end());
                        }

                        return result;
                    }
                    linear_combination operator-(const linear_combination &other) const {
                        return (*this) + (-other);
                    }
                    linear_combination operator-() const {
                        return (*this) * (-field_value_type::one());
                    }

                    bool operator==(const linear_combination &other) const {

                        std::vector<linear_term<FieldType, RotationSupport>> thisterms = this->terms;
                        std::sort(thisterms.begin(), thisterms.end(),
                                  [](linear_term<FieldType, RotationSupport> a, linear_term<FieldType, RotationSupport> b) { return a.index < b.index; });

                        std::vector<linear_term<FieldType, RotationSupport>> otherterms = other.terms;
                        std::sort(otherterms.begin(), otherterms.end(),
                                  [](linear_term<FieldType, RotationSupport> a, linear_term<FieldType, RotationSupport> b) { return a.index < b.index; });

                        return (thisterms == otherterms);
                    }

                    bool is_valid(size_t num_variables) const {
                        /* check that all terms in linear combination are sorted */
                        for (std::size_t i = 1; i < terms.size(); ++i) {
                            if (terms[i - 1].index >= terms[i].index) {
                                return false;
                            }
                        }

                        /* check that the variables are in proper range. as the variables
                           are sorted, it suffices to check the last term */
                        if ((--terms.end())->index >= num_variables) {
                            return false;
                        }

                        return true;
                    }
                };

                template<typename FieldType, bool RotationSupport>
                linear_combination<FieldType, RotationSupport> operator*(const typename FieldType::value_type &field_coeff,
                                                        const linear_combination<FieldType, RotationSupport> &lc) {
                    return lc * field_coeff;
                }

                template<typename FieldType, bool RotationSupport>
                linear_combination<FieldType, RotationSupport> operator+(const typename FieldType::value_type &field_coeff,
                                                        const linear_combination<FieldType, RotationSupport> &lc) {
                    return linear_combination<FieldType, RotationSupport>(field_coeff) + lc;
                }

                template<typename FieldType, bool RotationSupport>
                linear_combination<FieldType, RotationSupport> operator-(const typename FieldType::value_type &field_coeff,
                                                        const linear_combination<FieldType, RotationSupport> &lc) {
                    return linear_combination<FieldType, RotationSupport>(field_coeff) - lc;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_LINEAR_COMBINATION_HPP
