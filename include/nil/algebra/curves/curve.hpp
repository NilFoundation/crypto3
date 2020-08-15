//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_CURVE_HPP
#define ALGEBRA_CURVES_CURVE_HPP

#include <boost/mpl/arithmetic.hpp>

namespace nil {
    namespace algebra {
        namespace curves {

            /**
             * @brief This class represents an elliptic curve over GF(p)
             *
             * Construct the elliptic curve E: y^2 = x^3 + ax + b over GF(p)
             *
             * @tparam Number Satisfies Number concept requirements.
             *
             */

            template<typename FieldTypeype>
            struct curve{
                typedef FieldTypeype field_type;
                typedef typename field_type::modulus_type number_type;
            };

        }    // namespace curves
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_CURVE_HPP
