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

#ifndef CRYPTO3_MATH_EXPRESSION_AST_HPP
#define CRYPTO3_MATH_EXPRESSION_AST_HPP

#ifndef CRYPTO3_MATH_EXPRESSION_HPP
#error "ast.hpp must not be included directly!"
#endif

#include <boost/spirit/home/x3.hpp>
#include <boost/spirit/home/x3/support/ast/variant.hpp>

#include <list>
#include <string>

namespace nil {
    namespace crypto3 {
        namespace math {
            namespace expressions {
                namespace detail {

                    namespace x3 = boost::spirit::x3;

                    namespace ast {

                        struct nil {};
                        struct unary_op;
                        struct binary_op;
                        struct expression;

                        // clang-format off
                        struct operand : x3::variant<
                                         nil
                                         , double
                                         , std::string
                                         , x3::forward_ast<unary_op>
                                         , x3::forward_ast<binary_op>
                                         , x3::forward_ast<expression>
                                         > {
                            using base_type::base_type;
                            using base_type::operator=;
                        };
                        // clang-format on

                        struct unary_op {
                            double (*op)(double);
                            operand rhs;
                        };

                        struct binary_op {
                            double (*op)(double, double);
                            operand lhs;
                            operand rhs;
                        };

                        struct operation {
                            double (*op)(double, double);
                            operand rhs;
                        };

                        struct expression {
                            operand lhs;
                            std::list<operation> rhs;
                        };

                    } // namespace ast
                }    // namespace detail    
            }    // namespace expressions
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_EXPRESSION_AST_HPP