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

#ifndef CRYPTO3_ZK_VARIABLE_HPP_
#define CRYPTO3_ZK_VARIABLE_HPP_

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
                class linear_term;

                /**
                 * Forward declaration.
                 */
                template<typename FieldType>
                class linear_combination;

                /********************************* Variable **********************************/

                /**
                 * A variable represents a formal expression of the form "x_{index}".
                 */
                template<typename FieldType>
                class blueprint_variable {
                public:
                    var_index_t index;

                    blueprint_variable(const var_index_t index = 0) : index(index) {};

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

                    bool operator==(const blueprint_variable<FieldType> &other) const {
                        return (this->index == other.index);
                    }
                };

                template<typename FieldType>
                linear_term<FieldType> operator*(const integer_coeff_t int_coeff, const blueprint_variable<FieldType> &var) {
                    return linear_term<FieldType>(var, int_coeff);
                }

                template<typename FieldType>
                linear_term<FieldType> operator*(const typename FieldType::value_type &field_coeff,
                                                 const blueprint_variable<FieldType> &var) {
                    return linear_term<FieldType>(var, field_coeff);
                }

                template<typename FieldType>
                linear_combination<FieldType> operator+(const integer_coeff_t int_coeff,
                                                        const blueprint_variable<FieldType> &var) {
                    return linear_combination<FieldType>(int_coeff) + var;
                }

                template<typename FieldType>
                linear_combination<FieldType> operator+(const typename FieldType::value_type &field_coeff,
                                                        const blueprint_variable<FieldType> &var) {
                    return linear_combination<FieldType>(field_coeff) + var;
                }

                template<typename FieldType>
                linear_combination<FieldType> operator-(const integer_coeff_t int_coeff,
                                                        const blueprint_variable<FieldType> &var) {
                    return linear_combination<FieldType>(int_coeff) - var;
                }

                template<typename FieldType>
                linear_combination<FieldType> operator-(const typename FieldType::value_type &field_coeff,
                                                        const blueprint_variable<FieldType> &var) {
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
                    linear_term(const blueprint_variable<FieldType> &var) :
                        index(var.index), coeff(FieldType::value_type::zero()) {
                    }

                    linear_term(const blueprint_variable<FieldType> &var, const integer_coeff_t int_coeff) :
                        index(var.index), coeff(value_type(int_coeff)) {
                    }

                    linear_term(const blueprint_variable<FieldType> &var, const value_type &field_coeff) :
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
                linear_term<FieldType> operator*(integer_coeff_t int_coeff, const linear_term<FieldType> &lt);

                template<typename FieldType>
                linear_term<FieldType> operator*(const typename FieldType::value_type &field_coeff,
                                                 const linear_term<FieldType> &lt);

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
                class linear_combination {
                public:
                    typedef FieldType field_type;
                    typedef typename field_type::value_type value_type;

                    std::vector<linear_term<FieldType>> terms;

                    linear_combination() {};
                    linear_combination(const integer_coeff_t int_coeff);
                    linear_combination(const typename FieldType::value_type &field_coeff);
                    linear_combination(const blueprint_variable<FieldType> &var);
                    linear_combination(const linear_term<FieldType> &lt);
                    linear_combination(const std::vector<linear_term<FieldType>> &all_terms);

                    /* for supporting range-based for loops over linear_combination */
                    typename std::vector<linear_term<FieldType>>::const_iterator begin() const;
                    typename std::vector<linear_term<FieldType>>::const_iterator end() const;

                    void add_term(const blueprint_variable<FieldType> &var);
                    void add_term(const blueprint_variable<FieldType> &var, integer_coeff_t int_coeff);
                    void add_term(const blueprint_variable<FieldType> &var, const value_type &field_coeff);

                    void add_term(const linear_term<FieldType> &lt);

                    typename FieldType::value_type
                        evaluate(const std::vector<typename FieldType::value_type> &assignment) const;

                    linear_combination<FieldType> operator*(integer_coeff_t int_coeff) const;
                    linear_combination<FieldType> operator*(const value_type &field_coeff) const;

                    linear_combination<FieldType> operator+(const linear_combination<FieldType> &other) const;

                    linear_combination<FieldType> operator-(const linear_combination<FieldType> &other) const;
                    linear_combination<FieldType> operator-() const;

                    bool operator==(const linear_combination<FieldType> &other) const;

                    bool is_valid(size_t num_variables) const;

                    void print_with_assignment(const std::vector<typename FieldType::value_type> &full_assignment,
                                               const std::map<std::size_t, std::string> &variable_annotations =
                                                   std::map<std::size_t, std::string>()) const;
                };

                template<typename FieldType>
                linear_combination<FieldType> operator*(integer_coeff_t int_coeff,
                                                        const linear_combination<FieldType> &lc);

                template<typename FieldType>
                linear_combination<FieldType> operator*(const typename FieldType::value_type &field_coeff,
                                                        const linear_combination<FieldType> &lc);

                template<typename FieldType>
                linear_combination<FieldType> operator+(integer_coeff_t int_coeff,
                                                        const linear_combination<FieldType> &lc);

                template<typename FieldType>
                linear_combination<FieldType> operator+(const typename FieldType::value_type &field_coeff,
                                                        const linear_combination<FieldType> &lc);

                template<typename FieldType>
                linear_combination<FieldType> operator-(integer_coeff_t int_coeff,
                                                        const linear_combination<FieldType> &lc);

                template<typename FieldType>
                linear_combination<FieldType> operator-(const typename FieldType::value_type &field_coeff,
                                                        const linear_combination<FieldType> &lc);

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
                linear_combination<FieldType>::linear_combination(integer_coeff_t int_coeff) {
                    this->add_term(linear_term<FieldType>(0, int_coeff));
                }

                template<typename FieldType>
                linear_combination<FieldType>::linear_combination(const typename FieldType::value_type &field_coeff) {
                    this->add_term(linear_term<FieldType>(0, field_coeff));
                }

                template<typename FieldType>
                linear_combination<FieldType>::linear_combination(const blueprint_variable<FieldType> &var) {
                    this->add_term(var);
                }

                template<typename FieldType>
                linear_combination<FieldType>::linear_combination(const linear_term<FieldType> &lt) {
                    this->add_term(lt);
                }

                template<typename FieldType>
                typename std::vector<linear_term<FieldType>>::const_iterator
                    linear_combination<FieldType>::begin() const {
                    return terms.begin();
                }

                template<typename FieldType>
                typename std::vector<linear_term<FieldType>>::const_iterator
                    linear_combination<FieldType>::end() const {
                    return terms.end();
                }

                template<typename FieldType>
                void linear_combination<FieldType>::add_term(const blueprint_variable<FieldType> &var) {
                    this->terms.emplace_back(linear_term<FieldType>(var.index, FieldType::value_type::zero()));
                }

                template<typename FieldType>
                void linear_combination<FieldType>::add_term(const blueprint_variable<FieldType> &var,
                                                             integer_coeff_t int_coeff) {
                    this->terms.emplace_back(linear_term<FieldType>(var.index, int_coeff));
                }

                template<typename FieldType>
                void linear_combination<FieldType>::add_term(const blueprint_variable<FieldType> &var,
                                                             const typename FieldType::value_type &coeff) {
                    this->terms.emplace_back(linear_term<FieldType>(var.index, coeff));
                }

                template<typename FieldType>
                void linear_combination<FieldType>::add_term(const linear_term<FieldType> &other) {
                    this->terms.emplace_back(other);
                }

                template<typename FieldType>
                linear_combination<FieldType>
                    linear_combination<FieldType>::operator*(integer_coeff_t int_coeff) const {
                    return (*this) * typename FieldType::value_type(int_coeff);
                }

                template<typename FieldType>
                typename FieldType::value_type linear_combination<FieldType>::evaluate(
                    const std::vector<typename FieldType::value_type> &assignment) const {
                    typename FieldType::value_type acc = FieldType::value_type::zero();
                    for (auto &lt : terms) {
                        acc += (lt.index == 0 ? FieldType::value_type::zero() : assignment[lt.index - 1]) * lt.coeff;
                    }
                    return acc;
                }

                template<typename FieldType>
                linear_combination<FieldType>
                    linear_combination<FieldType>::operator*(const typename FieldType::value_type &field_coeff) const {
                    linear_combination<FieldType> result;
                    result.terms.reserve(this->terms.size());
                    for (const linear_term<FieldType> &lt : this->terms) {
                        result.terms.emplace_back(lt * field_coeff);
                    }
                    return result;
                }

                template<typename FieldType>
                linear_combination<FieldType>
                    linear_combination<FieldType>::operator+(const linear_combination<FieldType> &other) const {
                    linear_combination<FieldType> result;

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
                                linear_term<FieldType>(blueprint_variable<FieldType>(it1->index), it1->coeff + it2->coeff));
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

                template<typename FieldType>
                linear_combination<FieldType>
                    linear_combination<FieldType>::operator-(const linear_combination<FieldType> &other) const {
                    return (*this) + (-other);
                }

                template<typename FieldType>
                linear_combination<FieldType> linear_combination<FieldType>::operator-() const {
                    return (*this) * (-FieldType::value_type::zero());
                }

                template<typename FieldType>
                bool linear_combination<FieldType>::operator==(const linear_combination<FieldType> &other) const {
                    return (this->terms == other.terms);
                }

                template<typename FieldType>
                bool linear_combination<FieldType>::is_valid(size_t num_variables) const {
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

                template<typename FieldType>
                void linear_combination<FieldType>::print_with_assignment(
                    const std::vector<typename FieldType::value_type> &full_assignment,
                    const std::map<std::size_t, std::string> &variable_annotations) const {
                    for (auto &lt : terms) {
                        if (lt.index == 0) {
                            printf("    1 * ");
                            lt.coeff.print();
                        } else {
                            printf("    x_%zu * ", lt.index);
                            lt.coeff.print();

                            auto it = variable_annotations.find(lt.index);
                            printf("    where x_%zu (%s) was assigned value ", lt.index,
                                   (it == variable_annotations.end() ? "no annotation" : it->second.c_str()));
                            full_assignment[lt.index - 1].print();
                            printf("      i.e. negative of ");
                            (-full_assignment[lt.index - 1]).print();
                        }
                    }
                }

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

                template<typename FieldType>
                linear_combination<FieldType>::linear_combination(
                    const std::vector<linear_term<FieldType>> &all_terms) {
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
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // VARIABLE_HPP_
