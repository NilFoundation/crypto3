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

#ifndef CRYPTO3_ZK_NON_LINEAR_COMBINATION_HPP
#define CRYPTO3_ZK_NON_LINEAR_COMBINATION_HPP

#include <nil/crypto3/zk/snark/relations/variable.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Forward declaration.
                 */
                template<typename FieldType, bool RotationSupport>
                struct non_linear_combination;

                /****************************** Linear term **********************************/

                /**
                 * A linear term represents a formal expression of the form
                 * "coeff * w^{wire_index_1}_{rotation_1} * ... * w^{wire_index_k}_{rotation_k}".
                 */
                template<typename FieldType, bool RotationSupport = true>
                class non_linear_term;

                template<typename FieldType>
                class non_linear_term<FieldType, true> {
                    typedef FieldType field_type;
                    typedef typename field_type::value_type field_value_type;

                    constexpr static const bool RotationSupport = true;

                public:
                    std::vector<variable<FieldType, RotationSupport>> vars;
                    field_value_type coeff;

                    non_linear_term() {};

                    non_linear_term(const variable<field_type, RotationSupport> &var) : coeff(field_value_type::one()) {
                        vars.push_back(var);
                    }

                    non_linear_term(const field_value_type &field_val) : coeff(field_val) {
                    }

                    non_linear_term(std::vector<variable<FieldType, RotationSupport>> vars) :
                        vars(vars), coeff(field_value_type::one()) {
                    }

                    non_linear_term operator*(const field_value_type &field_coeff) const {
                        non_linear_term result(this->vars);
                        result.coeff = field_coeff * this->coeff;
                        return result;
                    }

                    non_linear_term operator*(const non_linear_term &other) const {
                        non_linear_term result(this->vars);

                        std::copy(other.vars.begin(), other.vars.end(), std::back_inserter(result.vars));
                        result.coeff = other.coeff * this->coeff;
                        return result;
                    }

                    // non_linear_combination<field_type> operator+(const non_linear_combination<field_type> &other)
                    // const {
                    //     return non_linear_combination<field_type>(*this) + other;
                    // }

                    // non_linear_combination<field_type> operator-(const non_linear_combination<field_type> &other)
                    // const {
                    //     return (*this) + (-other);
                    // }

                    non_linear_term operator-() const {
                        return non_linear_term(this->vars) * (-this->coeff);
                    }
                };

                template<typename FieldType, bool RotationSupport>
                non_linear_term<FieldType, RotationSupport>
                    operator*(const typename FieldType::value_type &field_coeff,
                              const non_linear_term<FieldType, RotationSupport> &nlt) {
                    return nlt * field_coeff;
                }

                template<typename FieldType, bool RotationSupport>
                non_linear_combination<FieldType, RotationSupport>
                    operator+(const typename FieldType::value_type &field_coeff,
                              const non_linear_term<FieldType, RotationSupport> &nlt) {
                    return non_linear_combination<FieldType, RotationSupport>(field_coeff) + nlt;
                }

                template<typename FieldType, bool RotationSupport>
                non_linear_combination<FieldType, RotationSupport>
                    operator-(const typename FieldType::value_type &field_coeff,
                              const non_linear_term<FieldType, RotationSupport> &nlt) {
                    return non_linear_combination<FieldType, RotationSupport>(field_coeff) - nlt;
                }

                template<typename FieldType, bool RotationSupport>
                non_linear_combination<FieldType, RotationSupport>
                    operator+(const non_linear_term<FieldType, RotationSupport> &A,
                              const non_linear_term<FieldType, RotationSupport> &B) {
                    return non_linear_combination<FieldType, RotationSupport>(A) +
                           non_linear_combination<FieldType, RotationSupport>(B);
                }

                template<typename FieldType, bool RotationSupport>
                non_linear_combination<FieldType, RotationSupport>
                    operator-(const non_linear_term<FieldType, RotationSupport> &A,
                              const non_linear_term<FieldType, RotationSupport> &B) {
                    return non_linear_combination<FieldType, RotationSupport>(A) -
                           non_linear_combination<FieldType, RotationSupport>(B);
                }

                /***************************** Linear combination ****************************/

                /**
                 * A linear combination represents a formal expression of the form "sum_i coeff_i * x_{index_i}".
                 */
                template<typename FieldType>
                class non_linear_combination<FieldType, true> {
                    typedef FieldType field_type;
                    typedef typename field_type::value_type field_value_type;

                    constexpr static const bool RotationSupport = true;

                public:
                    std::vector<non_linear_term<FieldType, RotationSupport>> terms;

                    non_linear_combination() {};
                    // non_linear_combination(const field_value_type &field_coeff) {
                    //     this->add_term(non_linear_term<FieldType, RotationSupport>(field_coeff));
                    // }
                    non_linear_combination(const variable<FieldType, RotationSupport> &var) {
                        this->add_term(var);
                    }
                    non_linear_combination(const non_linear_term<FieldType, RotationSupport> &nlt) {
                        this->add_term(nlt);
                    }
                    non_linear_combination(const std::vector<non_linear_term<FieldType, RotationSupport>> &terms) :
                        terms(terms) {
                    }

                    // non_linear_combination(const non_linear_combination &other):
                    //     terms(other.terms) {
                    // }

                    /* for supporting range-based for loops over non_linear_combination */
                    typename std::vector<non_linear_term<FieldType, RotationSupport>>::const_iterator begin() const {
                        return terms.begin();
                    }

                    typename std::vector<non_linear_term<FieldType, RotationSupport>>::const_iterator end() const {
                        return terms.end();
                    }

                    void add_term(const variable<FieldType, RotationSupport> &var) {
                        this->terms.emplace_back(non_linear_term<FieldType, RotationSupport>(var));
                    }
                    void add_term(const variable<FieldType, RotationSupport> &var,
                                  const field_value_type &field_coeff) {
                        this->terms.emplace_back(non_linear_term<FieldType, RotationSupport>(var) * field_coeff);
                    }
                    void add_term(const non_linear_term<FieldType, RotationSupport> &nlt) {
                        this->terms.emplace_back(nlt);
                    }

                    template<std::size_t WiresAmount>
                    field_value_type
                        evaluate(std::size_t row_index,
                                 const std::array<std::vector<field_value_type>, WiresAmount> &assignment) const {
                        field_value_type acc = field_value_type::zero();
                        for (non_linear_combination &nlt : terms) {
                            field_value_type term_value = nlt.coeff;

                            for (variable<FieldType, RotationSupport> &var : nlt.vars) {
                                term_value *= assignment[var.wire_index][row_index + var.rotation];
                            }
                            acc += assignment[nlt.vars] * nlt.coeff;
                        }
                        return acc;
                    }

                    template<std::size_t WiresAmount>
                    math::polynomial<field_value_type> evaluate(
                        std::size_t row_index,
                        const std::array<math::polynomial<field_value_type>, WiresAmount> &assignment) const {
                        math::polynomial<field_value_type> acc = {0};
                        for (non_linear_combination &nlt : terms) {
                            math::polynomial<field_value_type> term_value = {nlt.coeff};

                            for (variable<FieldType, RotationSupport> &var : nlt.vars) {
                                term_value *= assignment[var.wire_index];
                            }
                            acc += assignment[nlt.vars] * nlt.coeff;
                        }
                        return acc;
                    }

                    non_linear_combination operator*(const field_value_type &field_coeff) const {
                        non_linear_combination result;
                        result.terms.reserve(this->terms.size());
                        for (const non_linear_term<FieldType, RotationSupport> &nlt : this->terms) {
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
                        return (*this) * (-field_value_type::one());
                    }

                    void sort() {
                        std::sort(terms.begin(), terms.end());
                        std::vector<non_linear_term<FieldType, RotationSupport>> new_terms;

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
                };

                template<typename FieldType, bool RotationSupport>
                non_linear_combination<FieldType, RotationSupport>
                    operator*(const typename FieldType::value_type &field_coeff,
                              const non_linear_combination<FieldType, RotationSupport> &lc) {
                    return lc * field_coeff;
                }

                template<typename FieldType, bool RotationSupport>
                non_linear_combination<FieldType, RotationSupport>
                    operator*(const non_linear_combination<FieldType, RotationSupport> &A,
                              const non_linear_combination<FieldType, RotationSupport> &B) {
                    non_linear_combination<FieldType, RotationSupport> result;
                    result.terms.reserve(A.terms.size() * B.terms.size());

                    for (const non_linear_term<FieldType, RotationSupport> &this_nlt : A.terms) {
                        for (const non_linear_term<FieldType, RotationSupport> &other_nlt : B.terms) {
                            result.terms.emplace_back(this_nlt * other_nlt);
                        }
                    }
                    return result;
                }

                template<typename FieldType, bool RotationSupport>
                non_linear_combination<FieldType, RotationSupport>
                    operator*(const variable<FieldType, RotationSupport> &var,
                              const non_linear_combination<FieldType, RotationSupport> &A) {
                    non_linear_combination<FieldType, RotationSupport> result;
                    result.terms.reserve(A.terms.size());

                    for (const non_linear_term<FieldType, RotationSupport> &this_nlt : A.terms) {
                        result.terms.emplace_back(this_nlt * var);
                    }
                    return result;
                }

                template<typename FieldType, bool RotationSupport>
                non_linear_combination<FieldType, RotationSupport>
                    operator+(const typename FieldType::value_type &field_coeff,
                              const non_linear_combination<FieldType, RotationSupport> &lc) {
                    return non_linear_combination<FieldType, RotationSupport>(field_coeff) + lc;
                }

                template<typename FieldType, bool RotationSupport>
                non_linear_combination<FieldType, RotationSupport>
                    operator+(const non_linear_combination<FieldType, RotationSupport> &lc,
                              const typename FieldType::value_type &field_coeff) {

                    return field_coeff + lc;
                }

                template<typename FieldType, bool RotationSupport>
                non_linear_combination<FieldType, RotationSupport>
                    operator-(const typename FieldType::value_type &field_coeff,
                              const non_linear_combination<FieldType, RotationSupport> &lc) {
                    return non_linear_combination<FieldType, RotationSupport>(field_coeff) - lc;
                }

                template<typename FieldType, bool RotationSupport>
                non_linear_combination<FieldType, RotationSupport>
                    operator-(const non_linear_combination<FieldType, RotationSupport> &lc,
                              const typename FieldType::value_type &field_coeff) {

                    return -(field_coeff - lc);
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_NON_LINEAR_COMBINATION_HPP
