//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_NIST_P384_HPP
#define ALGEBRA_CURVES_NIST_P384_HPP

#include <nil/crypto3/pubkey/ec_group/curve_nist.hpp>

namespace nil {
    namespace algebra {
        namespace curves {

            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(384)

            /**
             * The NIST P-384 curve
             */
            template<std::size_t WordBits = limb_bits>
            struct p384 : public curve_nist<384, WordBits> {
                typedef typename curve_nist<384>::number_type number_type;

                constexpr static const number_type p =
                    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF_cppui384;
            };
        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_NIST_P384_HPP
