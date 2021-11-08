//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_JACOBI_HPP
#define BOOST_MULTIPRECISION_JACOBI_HPP

#include <nil/crypto3/multiprecision/detail/default_ops.hpp>


namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            /**
             * Compute the Jacobi symbol. If n is prime, this is equivalent
             * to the Legendre symbol.
             * @see http://mathworld.wolfram.com/JacobiSymbol.html
             *
             * @param a is a non-negative integer
             * @param n is an odd integer > 1
             * @return (n / m)
             */
            template<typename Backend, expression_template_option ExpressionTemplates>
            constexpr typename boost::enable_if_c<number_category<Backend>::value == number_kind_integer, int>::type
                jacobi(const number<Backend, ExpressionTemplates>& a, const number<Backend, ExpressionTemplates>& n) {
                return backends::eval_jacobi(a.backend(), n.backend());
            }
        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

#endif    // BOOST_MULTIPRECISION_JACOBI_HPP
