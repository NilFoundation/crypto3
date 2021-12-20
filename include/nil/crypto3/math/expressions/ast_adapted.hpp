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

#ifndef CRYPTO3_MATH_EXPRESSION_AST_ADAPTED_HPP
#define CRYPTO3_MATH_EXPRESSION_AST_ADAPTED_HPP

#ifndef CRYPTO3_MATH_EXPRESSION_HPP
#error "ast_adapted.hpp must not be included directly!"
#endif

#include <nil/crypto3/math/expressions/ast.hpp>

#include <boost/fusion/include/adapt_struct.hpp>

using namespace nil::crypto3::math::expressions::detail::ast;

BOOST_FUSION_ADAPT_STRUCT(unary_op, op, rhs)

BOOST_FUSION_ADAPT_STRUCT(binary_op, op, lhs, rhs)

BOOST_FUSION_ADAPT_STRUCT(operation, op, rhs)

BOOST_FUSION_ADAPT_STRUCT(expression, lhs, rhs)

#endif    // CRYPTO3_MATH_EXPRESSION_AST_ADAPTED_HPP