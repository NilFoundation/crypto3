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

#ifndef CRYPTO3_ZK_KNOWLEDGE_COMMITMENT_ELEMENT_HPP
#define CRYPTO3_ZK_KNOWLEDGE_COMMITMENT_ELEMENT_HPP

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/multiprecision/number.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename Type1, typename Type2>
                    struct knowledge_commitment;

                    /********************** Knowledge commitment *********************************/

                    /**
                     * A knowledge commitment element is a pair (g,h) where g is in Type1 and h in Type2,
                     * and Type1 and Type2 are groups (written additively).
                     *
                     * Such pairs form a group by defining:
                     * - "zero" = (0,0)
                     * - "one" = (1,1)
                     * - a * (g,h) + b * (g',h') := ( a * g + b * g', a * h + b * h').
                     */
                    template<typename Type1, typename Type2>
                    struct element_kc {

                        //using group_type = commitments<Type1, Type2>;

                        typename Type1::value_type g;
                        typename Type2::value_type h;

                        element_kc() = default;
                        element_kc(const element_kc &other) = default;
                        element_kc(element_kc &&other) = default;
                        element_kc(const typename Type1::value_type &g, const typename Type2::value_type &h) :
                            g(g), h(h) {
                        }

                        element_kc &operator=(const element_kc &other) = default;
                        element_kc &operator=(element_kc &&other) noexcept = default;
                        element_kc operator+(const element_kc &other) const {
                            return element_kc(this->g + other.g, this->h + other.h);
                        }
                        element_kc mixed_add(const element_kc &other) const {
                            return element_kc(this->g.mixed_add(other.g), this->h.mixed_add(other.h));
                        }
                        element_kc doubled() const {
                            return element_kc(this->g.doubled(), this->h.doubled());
                        }

                        element_kc to_projective() {
                            return element_kc(this->g.to_projective(), this->h.to_projective());
                        }
                        bool is_special() const {
                            return this->g->is_special() && this->h->is_special();
                        }

                        bool is_zero() const {
                            return (g.is_zero() && h.is_zero());
                        }
                        bool operator==(const element_kc &other) const {
                            return (this->g == other.g && this->h == other.h);
                        }
                        bool operator!=(const element_kc &other) const {
                            return !((*this) == other);
                        }

                        static element_kc zero() {
                            return element_kc(Type1::value_type::zero(), Type2::value_type::zero());
                        }
                        static element_kc one() {
                            return element_kc(Type1::value_type::one(), Type2::value_type::one());
                        }

                        static void batch_to_special_all_non_zeros(std::vector<element_kc> &vec) {
                            // it is guaranteed that every vec[i] is non-zero,
                            // but, for any i, *one* of vec[i].g and vec[i].h might still be zero,
                            // so we still have to handle zeros separately

                            // we separately process g's first, then h's
                            // to lower memory consumption
                            std::vector<typename Type1::value_type> g_vec;
                            g_vec.reserve(vec.size());

                            for (std::size_t i = 0; i < vec.size(); ++i) {
                                if (!vec[i].g.is_zero()) {
                                    g_vec.emplace_back(vec[i].g);
                                }
                            }

                            Type1::value_type::batch_to_special_all_non_zeros(g_vec);
                            auto g_it = g_vec.begin();
                            typename Type1::value_type Type1_zero_special = Type1::value_type::zero().to_projective();

                            for (std::size_t i = 0; i < vec.size(); ++i) {
                                if (!vec[i].g.is_zero()) {
                                    vec[i].g = *g_it;
                                    ++g_it;
                                } else {
                                    vec[i].g = Type1_zero_special;
                                }
                            }

                            g_vec.clear();

                            // exactly the same thing, but for h:
                            std::vector<typename Type2::value_type> h_vec;
                            h_vec.reserve(vec.size());

                            for (std::size_t i = 0; i < vec.size(); ++i) {
                                if (!vec[i].h.is_zero()) {
                                    h_vec.emplace_back(vec[i].h);
                                }
                            }

                            Type2::value_type::batch_to_special_all_non_zeros(h_vec);
                            auto h_it = h_vec.begin();
                            typename Type2::value_type Type2_zero_special = Type2::value_type::zero().to_projective();

                            for (std::size_t i = 0; i < vec.size(); ++i) {
                                if (!vec[i].h.is_zero()) {
                                    vec[i].h = *h_it;
                                    ++h_it;
                                } else {
                                    vec[i].h = Type2_zero_special;
                                }
                            }

                            h_vec.clear();
                        }
                    };

                    template<typename Type1,
                             typename Type2,
                             typename Backend,
                             multiprecision::expression_template_option ExpressionTemplates>
                    element_kc<Type1, Type2> operator*(const multiprecision::number<Backend, ExpressionTemplates> &lhs,
                                                       const element_kc<Type1, Type2> &rhs) {
                        return element_kc<Type1, Type2>(lhs * rhs.g, lhs * rhs.h);
                    }

                    template<typename Type1,
                             typename Type2,
                             typename Backend,
                             multiprecision::expression_template_option ExpressionTemplates>
                    element_kc<Type1, Type2>
                        operator*(const element_kc<Type1, Type2> &lhs,
                                  const multiprecision::number<Backend, ExpressionTemplates> &rhs) {
                        return element_kc<Type1, Type2>(rhs * lhs.g, rhs * lhs.h);
                    }

                    template<
                        typename Type1,
                        typename Type2,
                        typename FieldValueType,
                        typename = typename std::enable_if<
                            algebra::is_field<typename FieldValueType::field_type>::value &&
                                !algebra::is_extended_field<typename FieldValueType::field_type>::value,
                            FieldValueType>::type>
                    element_kc<Type1, Type2> operator*(const FieldValueType &lhs, const element_kc<Type1, Type2> &rhs) {

                        return lhs.data * rhs;
                    }

                    template<
                        typename Type1,
                        typename Type2,
                        typename FieldValueType,
                        typename = typename std::enable_if<
                            algebra::is_field<typename FieldValueType::field_type>::value &&
                                !algebra::is_extended_field<typename FieldValueType::field_type>::value,
                            FieldValueType>::type>
                    element_kc<Type1, Type2> operator*(const element_kc<Type1, Type2> &lhs, const FieldValueType &rhs) {

                        return lhs * rhs.data;
                    }
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_KNOWLEDGE_COMMITMENT_ELEMENT_HPP
