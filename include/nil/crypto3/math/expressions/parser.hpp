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

#ifndef CRYPTO3_MATH_EXPRESSION_PARSER_HPP
#define CRYPTO3_MATH_EXPRESSION_PARSER_HPP

#ifndef CRYPTO3_MATH_EXPRESSION_HPP
#error "parser.hpp must not be included directly!"
#endif

#include <list>
#include <string>

#include <boost/spirit/home/x3.hpp>
#include <boost/spirit/home/x3/support/ast/variant.hpp>

#include <nil/crypto3/math/expressions/ast.hpp>
#include <nil/crypto3/math/expressions/parser_def.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            namespace expressions {
                namespace detail {

                    namespace x3 = boost::spirit::x3;

                    namespace parser {

                        using iterator_type = std::string::const_iterator;
                        using context_type = x3::phrase_parse_context<x3::ascii::space_type>::type;
                        BOOST_SPIRIT_INSTANTIATE(expression_type, iterator_type, context_type)

                    } // namespace parser
                }    // namespace detail    
            }    // namespace expressions
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_EXPRESSION_PARSER_HPP