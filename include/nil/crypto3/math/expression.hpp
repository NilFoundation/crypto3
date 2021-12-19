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

#ifndef CRYPTO3_MATH_EXPRESSION_HPP
#define CRYPTO3_MATH_EXPRESSION_HPP

#include <boost/proto/proto.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            namespace expression {
                namespace detail {
                    template<std::size_t I>
                    struct placeholder
                    {};

                    template<typename ValueType, std::size_t VariablesAmount>
                    struct expression_context
                      : boost::proto::callable_context< expression_context<ValueType, VariablesAmount> const >
                    {
                        // Values to replace the placeholders
                        std::array<ValueType, VariablesAmount> args;

                        ValueType& operator [](std::size_t Index){
                            return this->args[Index];
                        }

                        // Define the result type of the calculator.
                        // (This makes the expression_context "callable".)
                        typedef ValueType result_type;

                        // Handle the placeholders:
                        template<std::size_t I>
                        ValueType operator()(boost::proto::tag::terminal, placeholder<I>) const
                        {
                            return this->args[I];
                        }
                    };
                }    // namespace detail

                template <std::size_t Index>
                using variable_type = typename boost::proto::terminal<detail::placeholder<Index>>::type;

                template <typename ValueType, std::size_t VariablesAmount>
                using assignment_type = detail::expression_context<ValueType, VariablesAmount>;

                template <typename Expr, typename ValueType, std::size_t VariablesAmount>
                ValueType eval(Expr expr, detail::expression_context<ValueType, VariablesAmount> ctx){
                    return boost::proto::eval( expr, ctx );
                }
            }    // namespace expression
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_EXPRESSION_HPP
