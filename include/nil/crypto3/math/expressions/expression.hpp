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

#include <nil/crypto3/math/expressions/ast.hpp>
#include <nil/crypto3/math/expressions/evaluator.hpp>
#include <nil/crypto3/math/expressions/parser.hpp>

#include <memory>
#include <stdexcept>
#include <string>

namespace nil {
    namespace crypto3 {
        namespace math {
            namespace expressions {

                /// @brief Parse a mathematical expression
                ///
                /// This can parse and evaluate a mathematical expression for a given
                /// symbol table using Boost.Spirit X3.  The templates of Boost.Spirit
                /// are very expensive to parse and instantiate, which is why we hide
                /// it behind an opaque pointer.
                ///
                /// The drawback of this approach is that calls can no longer be
                /// inlined and because the pointer crosses translation unit
                /// boundaries, dereferencing it can also not be optimized out at
                /// compile time.  We have to rely entirely on link-time optimization
                /// which might be not as good.
                ///
                /// The pointer to the implementation is a std::unique_ptr which makes
                /// the class not copyable but only moveable.  Copying shouldn't be
                /// required but is easy to implement.
                class Parser {
                    class impl {
                        typename detail::ast::operand ast;

                    public:
                        void parse(std::string const &expr) {
                            auto ast_ = detail::ast::expression{};

                            auto first = expr.begin();
                            auto last = expr.end();

                            boost::spirit::x3::ascii::space_type space;
                            bool r = phrase_parse(first, last, detail::grammar(), space, ast_);

                            if (!r || first != last) {
                                std::string rest(first, last);
                                throw std::runtime_error("Parsing failed at " + rest); // NOLINT
                            }

                            ast = ast_;
                        }

                        void optimize() { ast = boost::apply_visitor(detail::ast::ConstantFolder{}, ast); }

                        double evaluate(std::map<std::string, double> const &st) {
                            return boost::apply_visitor(detail::ast::eval{st}, ast);
                        }
                    };
                    std::unique_ptr<impl> pimpl;

                public:
                    /// @brief Constructor
                    Parser() : pimpl{std::make_unique<impl>()} {};

                    /// @brief Destructor
                    ~Parser() {};

                    /// @brief Parse the mathematical expression into an abstract syntax tree
                    ///
                    /// @param[in] expr The expression given as a std::string
                    void parse(std::string const &expr) { pimpl->parse(expr); }

                    /// @brief Perform constant folding onto the abstract syntax tree
                    void optimize() { pimpl->optimize(); }

                    /// @brief Evaluate the abstract syntax tree for a given symbol table
                    ///
                    /// @param[in] st The symbol table
                    double evaluate(std::map<std::string, double> const &st = {}) {
                        return pimpl->evaluate(st);
                    }
                };

                /// @brief Convenience function
                ///
                /// This function builds the grammar, parses the iterator to an AST,
                /// evaluates it, and returns the result.
                ///
                /// @param[in] expr  mathematical expression
                /// @param[in] st    the symbol table for variables
                inline double parse(std::string const &expr,
                                    std::map<std::string, double> const &st = {}) {
                    Parser parser;
                    parser.parse(expr);
                    return parser.evaluate(st);
                }
            }    // namespace expressions
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_EXPRESSION_HPP
