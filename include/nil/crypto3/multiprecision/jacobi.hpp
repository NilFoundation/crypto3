//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MULTIPRECISION_JACOBI_HPP
#define CRYPTO3_MULTIPRECISION_JACOBI_HPP

#include <boost/multiprecision/detail/default_ops.hpp>


namespace boost {
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
        BOOST_MP_CXX14_CONSTEXPR typename boost::enable_if_c<number_category<Backend>::value == number_kind_integer, int>::type
            jacobi(const number<Backend, ExpressionTemplates>& a, const number<Backend, ExpressionTemplates>& n) {
            return backends::eval_jacobi(a.backend(), n.backend());
        }
    }    // namespace multiprecision
} // namespace boost

#endif    // CRYPTO3_MULTIPRECISION_JACOBI_HPP
