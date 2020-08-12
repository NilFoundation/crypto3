//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_CURVE_NIST_P384_HPP
#define CRYPTO3_PUBKEY_CURVE_NIST_P384_HPP

#include <memory>

#include <boost/multiprecision/mask_bits.hpp>
#include <boost/multiprecision/reduce_below.hpp>

#include <nil/crypto3/pubkey/ec_group/curve_nist.hpp>

#include <nil/crypto3/utilities/assert.hpp>

namespace nil {
    namespace algebra {

        BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(384)

        /**
         * The NIST P-384 curve
         */
        template<std::size_t WordBits = limb_bits>
        struct p384 : public curve_nist_policy<384, WordBits> {
            typedef typename curve_nist_policy<384>::number_type number_type;

            constexpr static const number_type p =
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF_cppui384;
        };
    }        // namespace algebra
}    // namespace nil

#endif    // CRYPTO3_CURVE_NIST_P384_HPP
