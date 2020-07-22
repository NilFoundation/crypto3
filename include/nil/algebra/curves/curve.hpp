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

#include <nil/algebra/fields/detail/point.hpp>

namespace nil {
    namespace algebra {

        /**
         * @brief This class represents an elliptic curve over GF(p)
         *
         * Construct the elliptic curve E: y^2 = x^3 + ax + b over GF(p)
         *
         * @tparam Number Satisfies Number concept requirements.
         *
         * @note There should not be any reason for applications to use this
         * type. If you need EC primitives use the interfaces ec_group and
         * point_gfp
         */

        template<typename FieldType>
        struct curve {
            using number_type = NumberType;

            constexpr curve_gfp(number_type p, number_type a, number_type b, number_type x, number_type y,
                                number_type order) :
                p(p),
                a(a), b(b), x(x), y(y) {
            }

            constexpr static const number_type p;
            constexpr static const number_type a;
            constexpr static const number_type b;

            // generator coordinates:
            constexpr static const number_type x;
            constexpr static const number_type y;
            constexpr static const number_type order;
        };

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_GFP_HPP
