//---------------------------------------------------------------------------//
// Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_ZK_MATH_EXPRESSION_HPP
#define CRYPTO3_MARSHALLING_ZK_MATH_EXPRESSION_HPP

#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/variant.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/marshalling/math/types/term.hpp>
#include <nil/crypto3/marshalling/math/types/flat_expression.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                // Marshalling struct for flat_pow_operation.
                template<typename TTypeBase>
                struct flat_pow_operation {
                    using type =
                        nil::marshalling::types::bundle<
                            TTypeBase,
                            std::tuple<
                                // power
                                nil::marshalling::types::integral<TTypeBase, std::int64_t>,
                                // type
                                nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                                // child_index
                                nil::marshalling::types::integral<TTypeBase, std::uint32_t>
                            >
                        >;
                };

                // Marshalling struct for flat_binary_arithmetic_operation.
                template<typename TTypeBase>
                struct flat_binary_arithmetic_operation {
                    using type =
                        nil::marshalling::types::bundle<
                            TTypeBase,
                            std::tuple<
                                // op
                                nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                                // left_type
                                nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                                // left_index
                                nil::marshalling::types::integral<TTypeBase, std::uint32_t>,
                                // right_type
                                nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                                // right_index
                                nil::marshalling::types::integral<TTypeBase, std::uint32_t>
                            >
                        >;
                };


                template<typename TTypeBase, typename ExpressionType>
                struct expression
                {
                    using type =
                        nil::marshalling::types::bundle<
                            TTypeBase,
                            std::tuple<
                                // std::vector<math::term<VariableType>> terms
                                nil::marshalling::types::array_list<
                                    TTypeBase,
                                    typename term<TTypeBase, typename ExpressionType::term_type>::type,
                                    nil::marshalling::option::sequence_size_field_prefix<
                                        nil::marshalling::types::integral<TTypeBase, std::size_t>>
                                >,
                                // std::vector<flat_pow_operation> pow_operations
                                nil::marshalling::types::array_list<
                                    TTypeBase,
                                    typename flat_pow_operation<TTypeBase>::type,
                                    nil::marshalling::option::sequence_size_field_prefix<
                                        nil::marshalling::types::integral<TTypeBase, std::size_t>>
                                >,
                                // std::vector<flat_binary_arithmetic_operation> binary_operations
                                nil::marshalling::types::array_list<
                                    TTypeBase,
                                    typename flat_binary_arithmetic_operation<TTypeBase>::type,
                                    nil::marshalling::option::sequence_size_field_prefix<
                                        nil::marshalling::types::integral<TTypeBase, std::size_t>>
                                >,
                                // flat_node_type root_type;
                                nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                                // size_t root_index;
                                nil::marshalling::types::integral<TTypeBase, std::uint32_t>
                            >
                        >;
                };

                template<typename Endianness>
                typename flat_pow_operation<nil::marshalling::field_type<Endianness>>::type
                    fill_power_operation(const math::flat_pow_operation& power_op) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    return typename flat_pow_operation<nil::marshalling::field_type<Endianness>>::type(
                        std::make_tuple(
                            nil::marshalling::types::integral<TTypeBase, std::int64_t>(power_op.power),
                            nil::marshalling::types::integral<TTypeBase, std::uint8_t>((std::uint8_t)power_op.type),
                            nil::marshalling::types::integral<TTypeBase, std::uint32_t>(power_op.child_index)));
                }

                template<typename Endianness, typename ArithmeticOperatorType>
                typename flat_binary_arithmetic_operation<nil::marshalling::field_type<Endianness>>::type
                    fill_binary_operation(const math::flat_binary_arithmetic_operation<ArithmeticOperatorType>& bin_op) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    return typename flat_binary_arithmetic_operation<nil::marshalling::field_type<Endianness>>::type(
                        std::make_tuple(
                            nil::marshalling::types::integral<TTypeBase, std::uint8_t>((std::uint8_t)bin_op.op),
                            nil::marshalling::types::integral<TTypeBase, std::uint8_t>((std::uint8_t)bin_op.left_type),
                            nil::marshalling::types::integral<TTypeBase, std::uint32_t>(bin_op.left_index),
                            nil::marshalling::types::integral<TTypeBase, std::uint8_t>((std::uint8_t)bin_op.right_type),
                            nil::marshalling::types::integral<TTypeBase, std::uint32_t>(bin_op.right_index)));
                }


                template<typename ExpressionType, typename Endianness>
                typename expression<nil::marshalling::field_type<Endianness>, ExpressionType>::type
                    fill_expression(const ExpressionType &expr) {

                    math::expression_flattener<ExpressionType> flattener(expr);
                    const auto& flat_expr = flattener.get_result();

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using size_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;
                    // Fill the terms.
                    using term_marshalling_type =
                        typename term<TTypeBase, typename ExpressionType::term_type>::type;
                    using term_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, term_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    term_vector_marshalling_type filled_terms;
                    for (const auto &term : flat_expr.terms) {
                        filled_terms.value().push_back(
                            fill_term<Endianness, typename ExpressionType::term_type>(term));
                    }

                    // Fill the power operations.
                    using pow_operation_type = typename flat_pow_operation<TTypeBase>::type;
                    using pow_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, pow_operation_type, nil::marshalling::option::sequence_size_field_prefix<
                                        size_t_marshalling_type>>;
                    pow_vector_marshalling_type filled_powers;
                    for (const auto &power : flat_expr.pow_operations) {
                        filled_powers.value().push_back(fill_power_operation<Endianness>(power));
                    }

                    // Fill the binary operations.
                    using binary_operation_type = typename flat_binary_arithmetic_operation<TTypeBase>::type;
                    using binary_operation_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, binary_operation_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    binary_operation_vector_marshalling_type filled_binary_opeations;
                    for (const auto &bin_op : flat_expr.binary_operations) {
                        filled_binary_opeations.value().push_back(
                            fill_binary_operation<Endianness>(bin_op));
                    }

                    return typename expression<nil::marshalling::field_type<Endianness>, ExpressionType>::type(
                        std::make_tuple(
                            filled_terms,
                            filled_powers,
                            filled_binary_opeations,
                            nil::marshalling::types::integral<TTypeBase, std::uint8_t>((std::uint8_t)flat_expr.root_type),
                            nil::marshalling::types::integral<TTypeBase, std::uint32_t>(flat_expr.root_index)));

                }

                template<typename Endianness>
                math::flat_pow_operation
                    make_power_operation(const typename flat_pow_operation<nil::marshalling::field_type<Endianness>>::type& filled_power_op) {
                    math::flat_pow_operation power_op;
                    power_op.power = std::get<0>(filled_power_op.value()).value();
                    power_op.type = static_cast<math::flat_node_type>(std::get<1>(filled_power_op.value()).value());
                    power_op.child_index = std::get<2>(filled_power_op.value()).value();
                    return power_op;
                }

                template<typename Endianness, typename ArithmeticOperatorType>
                math::flat_binary_arithmetic_operation<ArithmeticOperatorType>
                    make_binary_operation(const typename flat_binary_arithmetic_operation<nil::marshalling::field_type<Endianness>>::type& filled_power_op) {
                    math::flat_binary_arithmetic_operation<ArithmeticOperatorType> bin_op;
                    bin_op.op = static_cast<ArithmeticOperatorType>(std::get<0>(filled_power_op.value()).value());
                    bin_op.left_type = static_cast<math::flat_node_type>(std::get<1>(filled_power_op.value()).value());
                    bin_op.left_index = std::get<2>(filled_power_op.value()).value();
                    bin_op.right_type = static_cast<math::flat_node_type>(std::get<3>(filled_power_op.value()).value());
                    bin_op.right_index = std::get<4>(filled_power_op.value()).value();
                    return bin_op;
                }

                template<typename ExpressionType, typename Endianness>
                ExpressionType make_expression(
                    const typename expression<nil::marshalling::field_type<Endianness>,
                                                          ExpressionType>::type &filled_expr) {

                    using ArithmeticOperatorType = typename ExpressionType::binary_arithmetic_operation_type::ArithmeticOperatorType;
                    math::flat_expression<ExpressionType> flat_expr;

                    // Get the terms.
                    const auto& terms = std::get<0>(filled_expr.value()).value();
                    for (std::size_t i = 0; i < terms.size(); i++) {
                        flat_expr.terms.emplace_back(
                            make_term<Endianness, typename ExpressionType::term_type>(terms.at(i)));
                    }

                    // Get the power operations.
                    const auto& powers = std::get<1>(filled_expr.value()).value();
                    for (std::size_t i = 0; i < powers.size(); i++) {
                        flat_expr.pow_operations.emplace_back(
                            make_power_operation<Endianness>(powers.at(i)));
                    }

                    // Get the binary arithmetic operations.
                    const auto& bin_ops = std::get<2>(filled_expr.value()).value();
                    for (std::size_t i = 0; i < bin_ops.size(); i++) {
                        flat_expr.binary_operations.emplace_back(
                            make_binary_operation<Endianness, ArithmeticOperatorType>(bin_ops.at(i)));
                    }

                    flat_expr.root_type = static_cast<math::flat_node_type>(std::get<3>(filled_expr.value()).value());
                    flat_expr.root_index = std::get<4>(filled_expr.value()).value();

                    return flat_expr.to_expression();
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_ZK_MATH_EXPRESSION_HPP
