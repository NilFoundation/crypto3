//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MATH_EXPRESSION_EVALUATOR_HPP
#define CRYPTO3_MATH_EXPRESSION_EVALUATOR_HPP

#ifndef CRYPTO3_MATH_EXPRESSION_HPP
#error "evaluator.hpp must not be included directly!"
#endif

#include <map>
#include <string>

#include <boost/fusion/include/adapt_struct.hpp>
#include <nil/crypto3/math/expressions/ast.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            namespace expressions {
                namespace detail {
                    namespace ast {

                        // Optimizer

                        template <typename T>
                        struct holds_alternative_impl {
                            using result_type = bool;

                            template <typename U>
                            bool operator()(U const &) const {
                                return std::is_same<U, T>::value;
                            }
                        };

                        template <typename T, typename... Ts>
                        bool holds_alternative(x3::variant<Ts...> const &v) {
                            return boost::apply_visitor(holds_alternative_impl<T>(), v);
                        }

                        struct ConstantFolder {
                            using result_type = operand;

                            result_type operator()(nil) const {
                                return result_type{0};
                            }

                            result_type operator()(double n) const {
                                return result_type{n};
                            }

                            result_type operator()(std::string const &c) const {
                                return result_type{c};
                            }

                            result_type operator()(operation const &x, operand const &lhs) const {
                                auto rhs = boost::apply_visitor(*this, x.rhs);

                                if (holds_alternative<double>(lhs) && holds_alternative<double>(rhs)) {
                                    return result_type{
                                        x.op(boost::get<double>(lhs), boost::get<double>(rhs))};
                                }
                                return result_type{binary_op{x.op, lhs, rhs}};
                            }

                            result_type operator()(unary_op const &x) const {
                                auto rhs = boost::apply_visitor(*this, x.rhs);

                                /// If the operand is known, we can directly evaluate the function.
                                if (holds_alternative<double>(rhs)) {
                                    return result_type{x.op(boost::get<double>(rhs))};
                                }
                                return result_type{unary_op{x.op, rhs}};
                            }

                            result_type operator()(binary_op const &x) const {
                                auto lhs = boost::apply_visitor(*this, x.lhs);
                                auto rhs = boost::apply_visitor(*this, x.rhs);

                                /// If both operands are known, we can directly evaluate the function,
                                /// else we just update the children with the new expressions.
                                if (holds_alternative<double>(lhs) && holds_alternative<double>(rhs)) {
                                    return result_type{
                                        x.op(boost::get<double>(lhs), boost::get<double>(rhs))};
                                }
                                return result_type{binary_op{x.op, lhs, rhs}};
                            }

                            result_type operator()(expression const &x) const {
                                auto state = boost::apply_visitor(*this, x.lhs);
                                for (operation const &oper : x.rhs) {
                                    state = (*this)(oper, state);
                                }
                                return result_type{state};
                            }
                        };

                        struct eval {
                            using result_type = double;

                            explicit eval(std::map<std::string, double> sym) : st(std::move(sym)) {}

                            double operator()(nil) const {
                                BOOST_ASSERT(0);
                                return 0;
                            }

                            double operator()(double n) const { return n; }

                            double operator()(std::string const &c) const {
                                auto it = st.find(c);
                                if (it == st.end()) {
                                    throw std::invalid_argument("Unknown variable " + c); // NOLINT
                                }
                                return it->second;
                            }

                            double operator()(operation const &x, double lhs) const {
                                double rhs = boost::apply_visitor(*this, x.rhs);
                                return x.op(lhs, rhs);
                            }

                            double operator()(unary_op const &x) const {
                                double rhs = boost::apply_visitor(*this, x.rhs);
                                return x.op(rhs);
                            }

                            double operator()(binary_op const &x) const {
                                double lhs = boost::apply_visitor(*this, x.lhs);
                                double rhs = boost::apply_visitor(*this, x.rhs);
                                return x.op(lhs, rhs);
                            }

                            double operator()(expression const &x) const {
                                double state = boost::apply_visitor(*this, x.lhs);
                                for (operation const &oper : x.rhs) {
                                    state = (*this)(oper, state);
                                }
                                return state;
                            }

                        private:
                            std::map<std::string, double> st;
                        };

                    } // namespace ast
                }    // namespace detail    
            }    // namespace expressions
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_EXPRESSION_EVALUATOR_HPP