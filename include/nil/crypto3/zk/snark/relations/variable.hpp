//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for:
// - a variable (i.e., x_i),
// - a linear term (i.e., a_i * x_i), and
// - a linear combination (i.e., sum_i a_i * x_i).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_VARIABLE_HPP
#define CRYPTO3_ZK_VARIABLE_HPP

#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Mnemonic typedefs.
                 */
                typedef std::size_t var_index_t;
                typedef long integer_coeff_t;

                /**
                 * Forward declaration.
                 */
                template<typename FieldType>
                struct linear_term;

                /**
                 * Forward declaration.
                 */
                template<typename FieldType>
                struct linear_combination;

                /********************************* Variable **********************************/

                /**
                 * A variable represents a formal expression of the form "x_{index}".
                 */
                template<typename FieldType>
                struct variable {

                    var_index_t index;

                    variable(const var_index_t index = 0) : index(index) {};

                    linear_term<FieldType> operator*(const integer_coeff_t int_coeff) const {
                        return linear_term<FieldType>(*this, int_coeff);
                    }

                    linear_term<FieldType> operator*(const typename FieldType::value_type &field_coeff) const {
                        return linear_term<FieldType>(*this, field_coeff);
                    }

                    linear_combination<FieldType> operator+(const linear_combination<FieldType> &other) const {
                        linear_combination<FieldType> result;

                        result.add_term(*this);
                        result.terms.insert(result.terms.begin(), other.terms.begin(), other.terms.end());

                        return result;
                    }

                    linear_combination<FieldType> operator-(const linear_combination<FieldType> &other) const {
                        return (*this) + (-other);
                    }

                    linear_term<FieldType> operator-() const {
                        return linear_term<FieldType>(*this, -FieldType::value_type::zero());
                    }

                    bool operator==(const variable<FieldType> &other) const {
                        return (this->index == other.index);
                    }
                };

                template<typename FieldType>
                linear_term<FieldType> operator*(const integer_coeff_t int_coeff, const variable<FieldType> &var) {
                    return linear_term<FieldType>(var, int_coeff);
                }

                template<typename FieldType>
                linear_term<FieldType> operator*(const typename FieldType::value_type &field_coeff,
                                                 const variable<FieldType> &var) {
                    return linear_term<FieldType>(var, field_coeff);
                }

                template<typename FieldType>
                linear_combination<FieldType> operator+(const integer_coeff_t int_coeff,
                                                        const variable<FieldType> &var) {
                    return linear_combination<FieldType>(int_coeff) + var;
                }

                template<typename FieldType>
                linear_combination<FieldType> operator+(const typename FieldType::value_type &field_coeff,
                                                        const variable<FieldType> &var) {
                    return linear_combination<FieldType>(field_coeff) + var;
                }

                template<typename FieldType>
                linear_combination<FieldType> operator-(const integer_coeff_t int_coeff,
                                                        const variable<FieldType> &var) {
                    return linear_combination<FieldType>(int_coeff) - var;
                }

                template<typename FieldType>
                linear_combination<FieldType> operator-(const typename FieldType::value_type &field_coeff,
                                                        const variable<FieldType> &var) {
                    return linear_combination<FieldType>(field_coeff) - var;
                }

                /****************************** Linear term **********************************/

                /**
                 * A linear term represents a formal expression of the form "coeff * x_{index}".
                 */
                template<typename FieldType>
                struct linear_term {
                    typedef FieldType field_type;
                    typedef typename field_type::value_type value_type;

                    var_index_t index;
                    value_type coeff;

                    linear_term() {};
                    linear_term(const variable<FieldType> &var) :
                        index(var.index), coeff(FieldType::value_type::zero()) {
                    }

                    linear_term(const variable<FieldType> &var, const integer_coeff_t int_coeff) :
                        index(var.index), coeff(value_type(int_coeff)) {
                    }

                    linear_term(const variable<FieldType> &var, const value_type &field_coeff) :
                        index(var.index), coeff(field_coeff) {
                    }

                    linear_term<FieldType> operator*(const integer_coeff_t int_coeff) const {
                        return (this->operator*(typename FieldType::value_type(int_coeff)));
                    }

                    linear_term<FieldType> operator*(const value_type &field_coeff) const {
                        return linear_term<FieldType>(this->index, field_coeff * this->coeff);
                    }

                    linear_combination<FieldType> operator+(const linear_combination<FieldType> &other) const {
                        return linear_combination<FieldType>(*this) + other;
                    }

                    linear_combination<FieldType> operator-(const linear_combination<FieldType> &other) const {
                        return (*this) + (-other);
                    }

                    linear_term<FieldType> operator-() const {
                        return linear_term<FieldType>(this->index, -this->coeff);
                    }

                    bool operator==(const linear_term<FieldType> &other) const {
                        return (this->index == other.index && this->coeff == other.coeff);
                    }
                };

                template<typename FieldType>
                linear_term<FieldType> operator*(integer_coeff_t int_coeff, const linear_term<FieldType> &lt) {
                    return typename FieldType::value_type(int_coeff) * lt;
                }

                template<typename FieldType>
                linear_term<FieldType> operator*(const typename FieldType::value_type &field_coeff,
                                                 const linear_term<FieldType> &lt) {
                    return linear_term<FieldType>(lt.index, field_coeff * lt.coeff);
                }

                template<typename FieldType>
                linear_combination<FieldType> operator+(const integer_coeff_t int_coeff,
                                                        const linear_term<FieldType> &lt) {
                    return linear_combination<FieldType>(int_coeff) + lt;
                }

                template<typename FieldType>
                linear_combination<FieldType> operator+(const typename FieldType::value_type &field_coeff,
                                                        const linear_term<FieldType> &lt) {
                    return linear_combination<FieldType>(field_coeff) + lt;
                }

                template<typename FieldType>
                linear_combination<FieldType> operator-(const integer_coeff_t int_coeff,
                                                        const linear_term<FieldType> &lt) {
                    return linear_combination<FieldType>(int_coeff) - lt;
                }

                template<typename FieldType>
                linear_combination<FieldType> operator-(const typename FieldType::value_type &field_coeff,
                                                        const linear_term<FieldType> &lt) {
                    return linear_combination<FieldType>(field_coeff) - lt;
                }

                /***************************** Linear combination ****************************/

                /**
                 * A linear combination represents a formal expression of the form "sum_i coeff_i * x_{index_i}".
                 */
                template<typename FieldType>
                struct linear_combination {

                    typedef FieldType field_type;
                    typedef typename field_type::value_type value_type;

                    std::vector<linear_term<FieldType>> terms;

                    linear_combination() {};
                    linear_combination(const integer_coeff_t int_coeff) {
                        this->add_term(linear_term<FieldType>(0, int_coeff));
                    }
                    linear_combination(const value_type &field_coeff) {
                        this->add_term(linear_term<FieldType>(0, field_coeff));
                    }
                    linear_combination(const variable<FieldType> &var) {
                        this->add_term(var);
                    }
                    linear_combination(const linear_term<FieldType> &lt) {
                        this->add_term(lt);
                    }
                    linear_combination(const std::vector<linear_term<FieldType>> &all_terms) {
                        if (all_terms.empty()) {
                            return;
                        }

                        terms = all_terms;
                        std::sort(terms.begin(), terms.end(),
                                  [](linear_term<FieldType> a, linear_term<FieldType> b) { return a.index < b.index; });

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
                    typename std::vector<linear_term<FieldType>>::const_iterator begin() const {
                        return terms.begin();
                    }

                    typename std::vector<linear_term<FieldType>>::const_iterator end() const {
                        return terms.end();
                    }

                    void add_term(const variable<FieldType> &var) {
                        this->terms.emplace_back(linear_term<FieldType>(var.index, value_type::zero()));
                    }
                    void add_term(const variable<FieldType> &var, integer_coeff_t int_coeff) {
                        this->terms.emplace_back(linear_term<FieldType>(var.index, int_coeff));
                    }
                    void add_term(const variable<FieldType> &var, const value_type &field_coeff) {
                        this->terms.emplace_back(linear_term<FieldType>(var.index, coeff));
                    }
                    void add_term(const linear_term<FieldType> &lt) {
                        this->terms.emplace_back(other);
                    }

                    value_type evaluate(const std::vector<value_type> &assignment) const {
                        value_type acc = value_type::zero();
                        for (auto &lt : terms) {
                            acc += (lt.index == 0 ? value_type::zero() : assignment[lt.index - 1]) * lt.coeff;
                        }
                        return acc;
                    }

                    linear_combination operator*(integer_coeff_t int_coeff) const {
                        return (*this) * value_type(int_coeff);
                    }
                    linear_combination operator*(const value_type &field_coeff) const {
                        linear_combination result;
                        result.terms.reserve(this->terms.size());
                        for (const linear_term<FieldType> &lt : this->terms) {
                            result.terms.emplace_back(lt * field_coeff);
                        }
                        return result;
                    }
                    linear_combination operator+(const linear_combination &other) const {
                        linear_combination result;

                        auto it1 = this->terms.begin();
                        auto it2 = other.terms.begin();

                        /* invariant: it1 and it2 always point to unprocessed items in the corresponding linear combinations
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
                                    linear_term<FieldType>(variable<FieldType>(it1->index), it1->coeff + it2->coeff));
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
                        return (*this) * (-value_type::zero());
                    }

                    bool operator==(const linear_combination &other) const {
                        return (this->terms == other.terms);
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

                template<typename FieldType>
                linear_combination<FieldType> operator*(integer_coeff_t int_coeff,
                                                        const linear_combination<FieldType> &lc) {
                    return lc * int_coeff;
                }

                template<typename FieldType>
                linear_combination<FieldType> operator*(const typename FieldType::value_type &field_coeff,
                                                        const linear_combination<FieldType> &lc) {
                    return lc * field_coeff;
                }

                template<typename FieldType>
                linear_combination<FieldType> operator+(integer_coeff_t int_coeff,
                                                        const linear_combination<FieldType> &lc) {
                    return linear_combination<FieldType>(int_coeff) + lc;
                }

                template<typename FieldType>
                linear_combination<FieldType> operator+(const typename FieldType::value_type &field_coeff,
                                                        const linear_combination<FieldType> &lc) {
                    return linear_combination<FieldType>(field_coeff) + lc;
                }

                template<typename FieldType>
                linear_combination<FieldType> operator-(integer_coeff_t int_coeff,
                                                        const linear_combination<FieldType> &lc) {
                    return linear_combination<FieldType>(int_coeff) - lc;
                }

                template<typename FieldType>
                linear_combination<FieldType> operator-(const typename FieldType::value_type &field_coeff,
                                                        const linear_combination<FieldType> &lc) {
                    return linear_combination<FieldType>(field_coeff) - lc;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_VARIABLE_HPP
