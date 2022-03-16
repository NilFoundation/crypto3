//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_ZK_MATH_NON_LINEAR_COMBINATION_HPP
#define CRYPTO3_MARSHALLING_ZK_MATH_NON_LINEAR_COMBINATION_HPP

#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/marshalling/zk/types/math/non_linear_term.hpp>

#include <nil/crypto3/zk/math/non_linear_combination.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase, typename NonLinearCombination, typename = void>
                struct non_linear_combination;

                template<typename TTypeBase, typename VariableType>
                struct non_linear_combination<TTypeBase, nil::crypto3::math::non_linear_combination<VariableType>,
                                              typename std::enable_if<std::is_same<
                                                  VariableType, nil::crypto3::zk::snark::plonk_variable<
                                                                    typename VariableType::field_type>>::value>::type> {
                    using type = nil::marshalling::types::array_list<
                        TTypeBase,
                        typename non_linear_term<TTypeBase, typename nil::crypto3::math::non_linear_combination<
                                                                VariableType>::term_type>::type,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<TTypeBase, std::size_t>>>;
                };

                template<typename NonLinearCombination, typename Endianness>
                typename non_linear_combination<nil::marshalling::field_type<Endianness>, NonLinearCombination>::type
                    fill_non_linear_combination(const NonLinearCombination &comb) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using size_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;
                    using term_marshalling_type =
                        typename non_linear_term<TTypeBase, typename NonLinearCombination::term_type>::type;
                    using term_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, term_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;

                    term_vector_marshalling_type filled_terms;
                    for (const auto &term : comb.terms) {
                        filled_terms.value().push_back(
                            fill_non_linear_term<typename NonLinearCombination::term_type, Endianness>(term));
                    }

                    return filled_terms;
                }

                template<typename NonLinearCombination, typename Endianness>
                NonLinearCombination make_non_linear_combination(
                    const typename non_linear_combination<nil::marshalling::field_type<Endianness>,
                                                          NonLinearCombination>::type &filled_comb) {
                    NonLinearCombination comb;
                    for (auto i = 0; i < filled_comb.value().size(); i++) {
                        comb.terms.emplace_back(
                            make_non_linear_term<typename NonLinearCombination::term_type, Endianness>(
                                filled_comb.value().at(i)));
                    }
                    return comb;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_ZK_MATH_NON_LINEAR_COMBINATION_HPP
