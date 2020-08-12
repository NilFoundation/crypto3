//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_FF_CURVE_NIST_P256_HPP
#define CRYPTO3_PUBKEY_CURVE_NIST_P256_HPP

#include <memory>

#include <boost/multiprecision/mask_bits.hpp>
#include <boost/multiprecision/reduce_below.hpp>

#include <nil/crypto3/pubkey/ec_group/curve_nist.hpp>

#include <nil/crypto3/utilities/assert.hpp>

namespace nil {
    namespace algebra {
        namespace curves {

            /**
             * The NIST P-256 curve
             */
            template<std::size_t WordBits = limb_bits>
            struct p256 : public curve_nist_policy<256, WordBits> {
                typedef typename curve_nist_policy<256>::number_type number_type;

                constexpr static const number_type p =
                    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF_cppui256;
            };
        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // CRYPTO3_CURVE_NIST_P256_HPP
