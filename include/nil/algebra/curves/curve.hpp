//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_GFP_HPP
#define ALGEBRA_CURVES_GFP_HPP

#include <boost/mpl/arithmetic.hpp>

#include <nil/algebra/fields/element.hpp>

namespace nil {
    namespace algebra {
        /*!
         * @brief Element type traits for elliptic curve E: y^2 = x^3 + ax + b over GF(p)
         * @tparam Element1
         * @tparam A
         * @tparam B
         */
        template<typename Element1, typename A, typename B>
        struct elliptic {
            typedef
                typename boost::mpl::multiplies<typename Element1::x, typename Element1::x, typename Element1::x>::type
                    xpow3;
            typedef typename boost::mpl::multiplies<typename Element1::y, typename Element1::y>::type ypow2;
            typedef typename boost::mpl::multiplies<typename Element1::x, A>::type ax;

            typedef typename std::enable_if<
                std::is_same<ypow2, typename boost::mpl::plus<xpow3, ax, typename B::x>::type>::value>::type type;
        };

        /**
         * @brief This class represents an elliptic curve over GF(p)
         *
         * Construct the elliptic curve E: y^2 = x^3 + ax + b over GF(p)
         *
         * @tparam Number Satisfies Number concept requirements.
         *
         */

        template<typename FieldType, typename Expression>
        struct curve {
            typedef FieldType field_type;
            typedef typename field_type::modulus_type number_type;
        };

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_GFP_HPP
