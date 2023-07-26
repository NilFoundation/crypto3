//---------------------------------------------------------------------------//
// Copyright (c) 2022-2023 Martun Karapetyan <martun@nil.foundation>
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
// @file Classes for mathematical expressions:
// - a term (i.e.,  a * x_i1 * x_i2 * ... * x_in)
// - an expression - stores any mathematical expression with -+* operatos and 'pow' in a form of a tree.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_MATH_EXPRESSION_HPP
#define CRYPTO3_ZK_MATH_EXPRESSION_HPP

#include <ostream>
#include <vector>
#include <functional>
#include <unordered_map>
#include <boost/functional/hash.hpp>
#include <boost/variant.hpp>
#include <boost/variant/recursive_wrapper.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            enum class ArithmeticOperator : std::uint8_t 
            {
                ADD = 0,
                SUB = 1,
                MULT = 2
            };


            /******************* Forward declarations of all the classes ******************/
            template<typename VariableType>
            class expression;

            template<typename VariableType>
            class term;

            template<typename VariableType>
            class pow_operation;

            template<typename VariableType>
            class binary_arithmetic_operation;

            /************** Definitions of all the classes **********************************/

            template<typename VariableType>
            class expression {
            public:
                typedef term<VariableType> term_type;
                typedef VariableType variable_type;
                typedef typename VariableType::assignment_type assignment_type;

                // We intentionally don't add variable_type and assignment_type here,
                // They must be converted to term<VariableType> before being used.
                typedef boost::variant<
                    boost::recursive_wrapper<term<VariableType>>,
                    boost::recursive_wrapper<pow_operation<VariableType>>,
                    boost::recursive_wrapper<binary_arithmetic_operation<VariableType>>
                    > expression_type;

                expression(const term<VariableType> &expr)
                  : expr(expr) {
                }
                expression(const pow_operation<VariableType> &expr)
                  : expr(expr) {
                }
                expression(const binary_arithmetic_operation<VariableType> &expr)
                  : expr(expr) {
                }
                expression(const VariableType &var)
                  : expr(term<VariableType>(var)) {
                }

                // Every number type will be accepted here, 
                // if it can be converted to 'assignment_type'.
                // This will include integral types and number<cpp_int_backend<...>>
                template<class NumberType>
                expression(const NumberType &coeff)
                  : expr(term<VariableType>((assignment_type)coeff)) {
                }

                expression(const expression<VariableType>& other) = default;
                expression(expression<VariableType>&& other) = default;
                expression<VariableType>& operator=(const expression<VariableType>& other) = default;
                expression<VariableType>& operator=(expression<VariableType>&& other) = default;

                expression<VariableType> pow(const std::size_t power) const;
                expression<VariableType> operator-() const;

                // Operations between 2 expressions. Everything else is implicitly converted
                // to expression class.
                expression<VariableType>& operator+=(const expression<VariableType>& other);
                expression<VariableType>& operator-=(const expression<VariableType>& other);
                expression<VariableType>& operator*=(const expression<VariableType>& other);

                expression<VariableType> operator+(const expression<VariableType>& other) const;
                expression<VariableType> operator-(const expression<VariableType>& other) const;
                expression<VariableType> operator*(const expression<VariableType>& other) const;

                // Used for testing purposes. Checks for EXACT EQUALITY ONLY, no isomorphism!!!
                bool operator==(const expression<VariableType>& other) const;
                bool operator!=(const expression<VariableType>& other) const;

                expression_type expr;
            };


            /**
             * A Non-Linear term represents a formal expression of the form
             * "coeff * w^{wire_index_1}_{rotation_1} * ... * w^{wire_index_k}_{rotation_k}", where 
             * the values of w^{wire_index_1}_{rotation_1} can repeat.
             */
            template<typename VariableType>
            class term  {
            public:
                typedef VariableType variable_type;
                typedef typename VariableType::assignment_type assignment_type;

                term() : coeff(assignment_type::zero()) {};

                term(const VariableType &var) : coeff(assignment_type::one()) {
                    vars.push_back(var);
                }

                // Every number type will be accepted here, 
                // if it can be converted to 'assignment_type'.
                // This will include integral types and number<cpp_int_backend<...>>
                template<class NumberType>
                term(const NumberType &field_val) : coeff(field_val) {
                }

                term(const std::vector<VariableType> &vars,
                     const assignment_type &coeff) 
                    : vars(vars)
                    , coeff(coeff) 
                {
                }

                term(const std::vector<VariableType> &vars) 
                    : vars(vars)
                    , coeff(assignment_type::one()) 
                {
                }

                term(const term<VariableType>& other) = default;
                term(term<VariableType>&& other) = default;
                term<VariableType>& operator=(const term<VariableType>& other) = default;
                term<VariableType>& operator=(term<VariableType>&& other) = default;

                // This operator will also allow multiplication with VariableType and assignment_type
                // via an implicit conversion to term.
                term<VariableType> operator*(const term<VariableType> &other) const;
                expression<VariableType> operator+(const term<VariableType> &other) const;
                expression<VariableType> operator-(const term<VariableType> &other) const;

                expression<VariableType> pow(const std::size_t power) const;
                term operator-() const;

                bool operator==(const term<VariableType>& other) const;
                bool operator!=(const term<VariableType>& other) const;

                // Used for debugging, to be able to see what's inside the term.
                std::string to_string() const;
                
                // If variables repeat, in some cases we 
                // want to be able to represent it as Product(var_i^power_i).
                std::unordered_map<variable_type, int> to_unordered_map() const;

                std::vector<variable_type> vars;
                assignment_type coeff;
            };

            template<typename VariableType>
            class pow_operation
            {
            public:
                typedef VariableType variable_type;
                
                pow_operation(const expression<VariableType>& expr, int power) 
                    : expr(expr)
                    , power(power) {
                }
                pow_operation(const pow_operation<VariableType>& other) = default;
                pow_operation(pow_operation<VariableType>&& other) = default;
                pow_operation<VariableType>& operator=(const pow_operation<VariableType>& other) = default;
                pow_operation<VariableType>& operator=(pow_operation<VariableType>&& other) = default;

                // Used for testing purposes. Checks for EXACT EQUALITY ONLY, no isomorphism!!!
                bool operator==(const pow_operation<VariableType>& other) const;
                bool operator!=(const pow_operation<VariableType>& other) const;

                const expression<VariableType> expr;
                const int power;

            }; 
 
            // One of +, -, *, / operations. We build an expression tree using this class.
            template<typename VariableType>
            class binary_arithmetic_operation
            {
            public:
                binary_arithmetic_operation(
                        const expression<VariableType>& expr_left,
                        const expression<VariableType>& expr_right,
                        ArithmeticOperator op) 
                    : expr_left(expr_left)
                    , expr_right(expr_right)
                    , op(op) {
                }

                binary_arithmetic_operation(
                    const binary_arithmetic_operation<VariableType>& other) = default;
                binary_arithmetic_operation(
                    binary_arithmetic_operation<VariableType>&& other) = default;
                binary_arithmetic_operation<VariableType>& operator=(
                    const binary_arithmetic_operation<VariableType>& other) = default;
                binary_arithmetic_operation<VariableType>& operator=(
                    binary_arithmetic_operation<VariableType>&& other) = default;

                // Used for testing purposes. Checks for EXACT EQUALITY ONLY, no isomorphism!!!
                bool operator==(const binary_arithmetic_operation<VariableType>& other) const;
                bool operator!=(const binary_arithmetic_operation<VariableType>& other) const;

                // Use for testing.
                std::string get_operator_string() const {
                    switch (op) {
                        case ArithmeticOperator::ADD:
                            return "+";
                        case ArithmeticOperator::SUB:
                            return "-";
                        case ArithmeticOperator::MULT:
                            return "*";
                    }
                }

                expression<VariableType> expr_left;
                expression<VariableType> expr_right;
                ArithmeticOperator op;
            };

            /*********** Member function bodies for class 'term' *******************************/
            template<typename VariableType>
            term<VariableType> term<VariableType>::operator*(const term<VariableType> &other) const {
                term<VariableType> result(this->vars);
                std::copy(other.vars.begin(), other.vars.end(), std::back_inserter(result.vars));
                result.coeff = other.coeff * this->coeff;
                return result; 
            }

            template<typename VariableType>
            expression<VariableType> term<VariableType>::operator+(const term<VariableType> &other) const {
                return expression<VariableType>(*this) + other;
            }

            template<typename VariableType>
            expression<VariableType> term<VariableType>::operator-(const term<VariableType> &other) const {
                return expression<VariableType>(*this) - other;
            }

            template<typename VariableType>
            expression<VariableType> term<VariableType>::pow(const std::size_t power) const {
                return pow_operation<VariableType>(*this, power); 
            }
            
            template<typename VariableType>
            term<VariableType> term<VariableType>::operator-() const {
                return term<VariableType>(this->vars, -this->coeff);
            }

            /*********** Member function bodies for class 'expression' *******************************/

            template<typename VariableType>
            expression<VariableType> expression<VariableType>::pow(const std::size_t power) const {
                return pow_operation<VariableType>(*this, power); 
            }

            template<typename VariableType>
            expression<VariableType> expression<VariableType>::operator-() const {
                return (*this) * term<VariableType>(-assignment_type::one());
            }

            template<typename VariableType>
            expression<VariableType>& expression<VariableType>::operator+=(
                    const expression<VariableType>& other) {
                expr = binary_arithmetic_operation<VariableType>(*this, other, ArithmeticOperator::ADD);
                return *this;
            }

            template<typename VariableType>
            expression<VariableType>& expression<VariableType>::operator-=(
                    const expression<VariableType>& other) {
                expr = binary_arithmetic_operation<VariableType>(*this, other, ArithmeticOperator::SUB);
                return *this;
            }

            template<typename VariableType>
            expression<VariableType>& expression<VariableType>::operator*=(
                    const expression<VariableType>& other) {
                expr = binary_arithmetic_operation<VariableType>(*this, other, ArithmeticOperator::MULT);
                return *this;
            }

            template<typename VariableType>
            expression<VariableType> expression<VariableType>::operator+(
                    const expression<VariableType>& other) const {
                return binary_arithmetic_operation<VariableType>(*this, other, ArithmeticOperator::ADD);
            }
    
            template<typename VariableType>
            expression<VariableType> expression<VariableType>::operator-(
                    const expression<VariableType>& other) const {
                return binary_arithmetic_operation<VariableType>(*this, other, ArithmeticOperator::SUB);
            }

            template<typename VariableType>
            expression<VariableType> expression<VariableType>::operator*(
                    const expression<VariableType>& other) const {
                return binary_arithmetic_operation<VariableType>(*this, other, ArithmeticOperator::MULT);
            }

            /***** Operators for [VariableType or assignment_type or int] +-* term. **********************/
            template<typename VariableType, typename LeftType, 
                     typename = std::enable_if_t<std::is_same<LeftType, VariableType>::value || std::is_same<LeftType, typename VariableType::assignment_type>::value || std::is_integral<LeftType>::value>>
            term<VariableType> operator*(
                    const LeftType &left,
                    const term<VariableType> &t) {
                return term<VariableType>(left) * t;
            }

            template<typename VariableType, typename LeftType, 
                     typename = std::enable_if_t<std::is_same<LeftType, VariableType>::value || std::is_same<LeftType, typename VariableType::assignment_type>::value || std::is_integral<LeftType>::value>>
            expression<VariableType> operator+(
                    const LeftType &left,
                    const term<VariableType> &t) {
                return term<VariableType>(left) + t;
            }

            template<typename VariableType, typename LeftType, 
                     typename = std::enable_if_t<std::is_same<LeftType, VariableType>::value || std::is_same<LeftType, typename VariableType::assignment_type>::value || std::is_integral<LeftType>::value>>
            expression<VariableType> operator-(
                    const LeftType &left,
                    const term<VariableType> &t) {
                return term<VariableType>(left) - t;
            }

            // Operators for [VariableType or assignment_type or int] +-* expression.
            template<typename VariableType, typename LeftType, 
                     typename = std::enable_if_t<std::is_same<LeftType, VariableType>::value || std::is_same<LeftType, typename VariableType::assignment_type>::value || std::is_same<LeftType, term<VariableType>>::value || std::is_integral<LeftType>::value>>
            expression<VariableType> operator*(
                    const LeftType &left,
                    const expression<VariableType> &exp) {
                return expression<VariableType>(left) * exp;
            }

            template<typename VariableType, typename LeftType, 
                     typename = std::enable_if_t<std::is_same<LeftType, VariableType>::value || std::is_same<LeftType, typename VariableType::assignment_type>::value || std::is_same<LeftType, term<VariableType>>::value || std::is_integral<LeftType>::value>>
            expression<VariableType> operator+(
                    const LeftType &left,
                    const expression<VariableType> &exp) {
                return expression<VariableType>(left) + exp;
            }

            template<typename VariableType, typename LeftType, 
                     typename = std::enable_if_t<std::is_same<LeftType, VariableType>::value || std::is_same<LeftType, typename VariableType::assignment_type>::value || std::is_same<LeftType, term<VariableType>>::value || std::is_integral<LeftType>::value>>
            expression<VariableType> operator-(
                    const LeftType &left,
                    const expression<VariableType> &exp) {
                return expression<VariableType>(left) - exp;
            }

            template<typename VariableType>
            std::unordered_map<VariableType, int> term<VariableType>::to_unordered_map() const {
                std::unordered_map<VariableType, int> vars_map;
                for (const auto& var: vars) {
                    auto iter = vars_map.find(var);
                    if (iter != vars_map.end()) {
                        iter->second++;
                    } else {
                        vars_map[var] = 1;
                    }
                }
                return vars_map;
            }

            template<typename VariableType>
            bool term<VariableType>::operator==(const term<VariableType>& other) const {
                if (this->coeff != other.coeff) {
                    return false;
                }
                if (this->vars.size() != other.vars.size()) {
                    return false;
                }
                // Put both vars and other->vars into a hashmap, and check if
                // everything is equal.
                auto vars_map = this->to_unordered_map();
                for (const auto& var: other.vars) {
                    auto iter = vars_map.find(var);
                    if (iter != vars_map.end()) {
                        iter->second--;
                    } else {
                        return false;
                    }
                }
                for (const auto& entry: vars_map) {
                    if (entry.second != 0)
                        return false;
                }
                return true;
            }

            // Used for testing purposes.
            template<typename VariableType>
            bool term<VariableType>::operator!=(const term<VariableType>& other) const {
                return !(*this == other);
            }

            // Used in the unit tests, so we can use BOOST_CHECK_EQUALS, and see
            // the values of terms, when the check fails.
            template<typename VariableType>
            std::ostream& operator<<(std::ostream& os, const term<VariableType>& term) {
                if (term.coeff != VariableType::assignment_type::one()) {
                    if (term.vars.size() != 0) {
                        os << term.coeff << " * ";
                    } else {
                        os << term.coeff;
                    }
                } else if (term.vars.size() == 0) {
                    os << term.coeff;
                }
                bool first = true;
                for (const auto& var : term.vars) {
                    if (!first)
                        os << " * ";
                    os << var;
                    first = false;
                }
                return os;
            }

            // Used in the unit tests, so we can use BOOST_CHECK_EQUALS, and see
            // the values of terms, when the check fails.
            template<typename VariableType>
            std::ostream& operator<<(std::ostream& os, const pow_operation<VariableType>& power) {
                os << "(" << power.expr << " ^ " << power.power << ")";
                return os;
            }

            // Used in the unit tests, so we can use BOOST_CHECK_EQUALS, and see
            // the values of terms, when the check fails.
            template<typename VariableType>
            std::ostream& operator<<(std::ostream& os, const binary_arithmetic_operation<VariableType>& bin_op) {
                os << "(" << bin_op.expr_left << " " << bin_op.get_operator_string() << " "
                    << bin_op.expr_right << ")";
                return os;
            }

            // Used in the unit tests, so we can use BOOST_CHECK_EQUALS, and see
            // the values of terms, when the check fails.
            template<typename VariableType>
            std::ostream& operator<<(std::ostream& os, const expression<VariableType>& expr) {
                os << expr.expr;
                return os;
            }

            // Used for testing purposes. Checks for EXACT EQUALITY ONLY, no isomorphism!!!
            template<typename VariableType>
            bool pow_operation<VariableType>::operator==(
                    const pow_operation<VariableType>& other) const {
                return this->power == other.power && this->expr == other.expr;
            }

            // Used for testing purposes.
            template<typename VariableType>
            bool pow_operation<VariableType>::operator!=(
                    const pow_operation<VariableType>& other) const {
                return !(*this == other);
            }

            // Used for testing purposes. Checks for EXACT EQUALITY ONLY, no isomorphism!!!
            template<typename VariableType>
            bool binary_arithmetic_operation<VariableType>::operator==(
                    const binary_arithmetic_operation<VariableType>& other) const {
                return this->op == other.op &&
                       this->expr_left == other.expr_left &&
                       this->expr_right == other.expr_right;
            }

            // Used for testing purposes. Checks for EXACT EQUALITY ONLY, no isomorphism!!!
            template<typename VariableType>
            bool binary_arithmetic_operation<VariableType>::operator!=(
                    const binary_arithmetic_operation<VariableType>& other) const {
                return !(*this == other);
            }
 
            // Used for testing purposes. Checks for EXACT EQUALITY ONLY, no isomorphism!!!
            template<typename VariableType>
            bool expression<VariableType>::operator==(const expression<VariableType>& other) const {
                return this->expr == other.expr;
            }

            // Used for testing purposes. Checks for EXACT EQUALITY ONLY, no isomorphism!!!
            template<typename VariableType>
            bool expression<VariableType>::operator!=(const expression<VariableType>& other) const {
                return this->expr != other.expr;
            }
            
        }    // namespace math
    }            // namespace crypto3
}    // namespace nil

template <typename VariableType>
struct std::hash<nil::crypto3::math::term<VariableType>>
{
    std::hash<VariableType> vars_hasher;
    std::hash<typename VariableType::assignment_type> coeff_hasher;

    std::size_t operator()(const nil::crypto3::math::term<VariableType>& term) const
    {
        std::size_t result = coeff_hasher(term.coeff);
        auto vars = term.vars;
        sort(vars.begin(), vars.end());
        for (const auto& var: vars) {
            boost::hash_combine(result, vars_hasher(var));
        }
        return result;
    }
};

#endif    // CRYPTO3_ZK_MATH_EXPRESSION_HPP
