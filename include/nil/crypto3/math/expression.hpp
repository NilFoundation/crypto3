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
            namespace expressions {
                namespace detail {
                    template<typename Expr>
                    struct lazy_expression_expr;

                    // This grammar describes which lazy vector lazy_expressions
                    // are allowed; namely, vector terminals and addition
                    // and subtraction of lazy vector lazy_expressions.
                    struct lazy_expression_grammar
                      : boost::proto::or_<
                            boost::proto::terminal< boost::proto::_ >
                          , boost::proto::plus< lazy_expression_grammar, lazy_expression_grammar >
                          , boost::proto::minus< lazy_expression_grammar, lazy_expression_grammar >
                          , boost::proto::multiplies< lazy_expression_grammar, lazy_expression_grammar >
                        >
                    {};

                    // Tell proto that in the lazy_expression_domain, all
                    // lazy_expressions should be wrapped in laxy_vector_expr<>
                    // and must conform to the lazy vector grammar.
                    struct lazy_expression_domain
                      : boost::proto::domain<boost::proto::generator<lazy_expression_expr>, lazy_expression_grammar>
                    {};

                    // Here is an evaluation context that indexes into a lazy vector
                    // expression, and combines the result.
                    struct lazy_expression_subscript_context {
                        lazy_expression_subscript_context(){}

                        // Use default_eval for all the operations ...
                        template<typename Expr, typename Tag = typename Expr::proto_tag>
                        struct eval
                          : boost::proto::default_eval<Expr, lazy_expression_subscript_context>
                        {};

                    };

                    // Here is the domain-specific lazy_expression wrapper, which overrides
                    // operator [] to evaluate the lazy_expression using the lazy_expression_subscript_context.
                    template<typename Expr>
                    struct lazy_expression_expr
                      : boost::proto::extends<Expr, lazy_expression_expr<Expr>, lazy_expression_domain>
                    {
                      // typedef boost::proto::default_context lazy_expression_subscript_context;
                        lazy_expression_expr( Expr const & expr = Expr() )
                          : lazy_expression_expr::proto_extends( expr )
                        {}

                        // Use the lazy_expression_subscript_context<> to implement subscripting
                        // of a lazy vector lazy_expression tree.
                        typename boost::proto::result_of::eval< Expr, lazy_expression_subscript_context >::type
                        evaluate()  {
                            lazy_expression_subscript_context ctx;
                            return boost::proto::eval(*this, ctx);
                        }

                        typename boost::proto::result_of::eval< Expr, lazy_expression_subscript_context >::type
                        evaluate() const {
                            lazy_expression_subscript_context ctx;
                            return boost::proto::eval(*this, ctx);
                        }
                    };

                }    // namespace detail

                // Here is our lazy_expression terminal, implemented in terms of detail::lazy_expression_expr
                template< typename T >
                struct lazy_expression
                  : detail::lazy_expression_expr< typename boost::proto::terminal< T>::type >
                {
                    typedef typename boost::proto::terminal< T >::type expr_type;

                    lazy_expression( T const & value = T() )
                      : detail::lazy_expression_expr<expr_type>( expr_type::make( T( value ) ) )
                    {}

                    // Here we define a += operator for lazy vector terminals that
                    // takes a lazy vector lazy_expression and indexes it. expr.evaluate(i) here
                    // uses lazy_expression_subscript_context<> under the covers.
                    template< typename Expr >
                    lazy_expression &operator = (Expr const & expr)
                    {
                        boost::proto::value(*this) = expr.evaluate();
                        return *this;
                    }

                    void assign(T const & value){
                        boost::proto::value(*this) = value;
                    }
                };
            }    // namespace expressions
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_EXPRESSION_HPP
