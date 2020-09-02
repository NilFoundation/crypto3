//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_SCALAR_MATH_HPP
#define ALGEBRA_SCALAR_MATH_HPP

namespace nil {
    namespace algebra {

        /** \addtogroup scalar
         *  @{
         */

        /** @brief computes the absolute value
         *  @param x argument
         *  @return \f$ \lvert x \rvert \f$
         *
         *  Computes the absolute value.
         */
        template <typename T>
        constexpr T abs(T x) {
            return x > 0 ? x : -x;
        }

        /** @}*/

    }    // namespace algebra
}    // namespace nil

#endif // ALGEBRA_SCALAR_MATH_HPP
