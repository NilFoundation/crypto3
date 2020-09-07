//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_NIST_P192_HPP
#define ALGEBRA_CURVES_NIST_P192_HPP

#include <memory>

#include <nil/crypto3/pubkey/ec_group/curve_nist.hpp>
#include <nil/crypto3/algebra/curves/detail/element/p192.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace curves {

            /**
             * The NIST P-192 curve
             */
            template<std::size_t WordBits = limb_bits>
            struct p192 : public curve_nist<192, WordBits> {
                typedef typename curve_nist<192>::number_type number_type;

                constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF_cppui192;
            };
        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_NIST_P192_HPP
