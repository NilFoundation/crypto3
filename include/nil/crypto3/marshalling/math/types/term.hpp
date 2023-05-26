//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_ZK_MATH_TERM_HPP
#define CRYPTO3_MARSHALLING_ZK_MATH_TERM_HPP

#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase, typename NonLinearTerm, typename = void>
                struct term;

                template<typename TTypeBase, typename VariableType>
                struct term<TTypeBase, nil::crypto3::math::term<VariableType>, void> {
                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // assignment_type coeff
                            field_element<TTypeBase,
                                          typename nil::crypto3::math::term<VariableType>::assignment_type>,
                            // std::vector<VariableType> vars
                            nil::marshalling::types::array_list<
                                TTypeBase, typename variable<TTypeBase, VariableType>::type,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::size_t>>
                                >
                            >
                        >;
                };

                template<typename NonLinearTerm, typename Endianness>
                typename std::enable_if<
                    std::is_same<nil::crypto3::math::term<typename NonLinearTerm::variable_type>,
                                 NonLinearTerm>::value,
                    typename term<nil::marshalling::field_type<Endianness>, NonLinearTerm>::type>::type
                    fill_term(const NonLinearTerm &t) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using result_type = typename term<TTypeBase, NonLinearTerm>::type;
                    using size_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;
                    using field_element_marhsalling_type =
                        field_element<TTypeBase, typename NonLinearTerm::assignment_type>;
                    using variable_marshalling_type =
                        typename variable<TTypeBase, typename NonLinearTerm::variable_type>::type;
                    using variable_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, variable_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;

                    variable_vector_marshalling_type filled_vars;
                    for (const auto &var : t.vars) {
                        filled_vars.value().push_back(
                            fill_variable<typename NonLinearTerm::variable_type, Endianness>(var));
                    }

                    return result_type(std::make_tuple(field_element_marhsalling_type(t.coeff), filled_vars));
                }

                template<typename NonLinearTerm, typename Endianness>
                typename std::enable_if<
                    std::is_same<nil::crypto3::math::term<typename NonLinearTerm::variable_type>,
                                 NonLinearTerm>::value,
                    NonLinearTerm>::type
                    make_term(const typename term<nil::marshalling::field_type<Endianness>,
                                                                        NonLinearTerm>::type &filled_term) {
                    NonLinearTerm t;
                    t.coeff = std::get<0>(filled_term.value()).value();
                    t.vars.reserve(std::get<1>(filled_term.value()).value().size());
                    for (auto i = 0; i < std::get<1>(filled_term.value()).value().size(); i++) {
                        t.vars.emplace_back(make_variable<typename NonLinearTerm::variable_type, Endianness>(
                            std::get<1>(filled_term.value()).value().at(i)));
                    }
                    return t;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_ZK_MATH_TERM_HPP
