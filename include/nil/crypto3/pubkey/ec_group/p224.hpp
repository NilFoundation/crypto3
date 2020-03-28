//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_CURVE_NIST_P224_HPP
#define CRYPTO3_PUBKEY_CURVE_NIST_P224_HPP

#include <memory>

#include <boost/multiprecision/mask_bits.hpp>
#include <boost/multiprecision/reduce_below.hpp>

#include <nil/crypto3/pubkey/ec_group/curve_nist.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(224)

            /**
             * The NIST P-224 curve
             */
            template<std::size_t WordBits = limb_bits>
            class p224 : public curve_nist_policy<224, WordBits> {
            public:
                constexpr static const std::size_t word_bits = curve_nist_policy<224, WordBits>::word_bits;
                constexpr static const std::size_t p_bits = curve_nist_policy<224, WordBits>::p_bits;
                constexpr static const std::size_t p_words = curve_nist_policy<224, WordBits>::p_words;

                typedef number<backends::cpp_int_backend<p_bits, p_bits, unsigned_magnitude, unchecked, void>> p_type;

                constexpr static const p_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001_cppui224;

                template<typename Backend, expression_template_option ExpressionTemplates>
                static void redc_mod_p(number<Backend, ExpressionTemplates> &x) {
                    const uint32_t X7 = detail::get_uint32_t(x, 7);
                    const uint32_t X8 = detail::get_uint32_t(x, 8);
                    const uint32_t X9 = detail::get_uint32_t(x, 9);
                    const uint32_t X10 = detail::get_uint32_t(x, 10);
                    const uint32_t X11 = detail::get_uint32_t(x, 11);
                    const uint32_t X12 = detail::get_uint32_t(x, 12);
                    const uint32_t X13 = detail::get_uint32_t(x, 13);

                    mask_bits(x, p_bits);

                    // One full copy of P224 is added, so the result is always positive

                    int64_t S = 0;

                    S += detail::get_uint32_t(x, 0);
                    S += 1;
                    S -= X7;
                    S -= X11;
                    detail::set_uint32_t(x, 0, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 1);
                    S -= X8;
                    S -= X12;
                    detail::set_uint32_t(x, 1, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 2);
                    S -= X9;
                    S -= X13;
                    detail::set_uint32_t(x, 2, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 3);
                    S += 0xFFFFFFFF;
                    S += X7;
                    S += X11;
                    S -= X10;
                    detail::set_uint32_t(x, 3, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 4);
                    S += 0xFFFFFFFF;
                    S += X8;
                    S += X12;
                    S -= X11;
                    detail::set_uint32_t(x, 4, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 5);
                    S += 0xFFFFFFFF;
                    S += X9;
                    S += X13;
                    S -= X12;
                    detail::set_uint32_t(x, 5, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 6);
                    S += 0xFFFFFFFF;
                    S += X10;
                    S -= X13;
                    detail::set_uint32_t(x, 6, S);
                    S >>= 32;
                    detail::set_uint32_t(x, 7, S);

                    CRYPTO3_ASSERT_EQUAL(S >> 32, 0, "No underflow");

                    reduce_below(x, p);
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CURVE_NIST_P224_HPP