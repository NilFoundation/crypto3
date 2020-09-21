//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_CURVES_NIST_P224_HPP
#define CRYPTO3_ALGEBRA_CURVES_NIST_P224_HPP

#include <nil/crypto3/algebra/curves/curve_nist.hpp>
#include <nil/crypto3/algebra/curves/detail/element/p224.hpp>

#include <nil/crypto3/algebra/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                /**
                 * The NIST P-224 curve
                 */
                template<std::size_t WordBits = limb_bits>
                struct p224 : public curve_nist<224, WordBits> {
                    typedef typename curve_nist<224>::number_type number_type;

                    constexpr static const number_type p =
                        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001_cppui224;
                };
            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_CURVES_NIST_P224_HPP
