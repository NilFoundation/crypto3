//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_FF_CURVE_NIST_P224_HPP
#define CRYPTO3_FF_CURVE_NIST_P224_HPP

#include <memory>

#include <boost/multiprecision/mask_bits.hpp>
#include <boost/multiprecision/reduce_below.hpp>

#include <nil/crypto3/algebra/curves/curve_gfp.hpp>

namespace nil {
    namespace algebra {

        BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(224)

        /**
         * The NIST P-224 curve
         */
        template<std::size_t WordBits = limb_bits>
        struct p224 : public curve_nist_policy<224, WordBits> {
            typedef typename curve_nist_policy<224>::number_type number_type;

            constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001_cppui224;

        };
    }        // namespace algebra
}    // namespace nil

#endif    // CRYPTO3_FF_CURVE_NIST_P224_HPP