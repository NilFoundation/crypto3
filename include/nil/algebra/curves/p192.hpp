//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_FF_CURVE_NIST_P192_HPP
#define CRYPTO3_FF_CURVE_GOST_A_HPP

#include <memory>

#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/multiprecision/mask_bits.hpp>
#include <boost/multiprecision/reduce_below.hpp>

#include <nil/crypto3/pubkey/ec_group/curve_nist.hpp>

namespace nil {
    namespace algebra {

        BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(192)

        /**
         * The NIST P-192 curve
         */
        template<std::size_t WordBits = limb_bits>
        struct p192 : public curve_nist_policy<192, WordBits> {
            typedef typename curve_nist_policy<192>::number_type number_type;

            typedef number<backends::cpp_int_backend<p_bits, p_bits, unsigned_magnitude, unchecked, void>> p_type;

            constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF_cppui192;
        };
    }        // namespace algebra
}    // namespace nil

#endif    // CRYPTO3_FF_CURVE_GOST_A_HPP
