//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_CURVE_NIST_P521_HPP
#define CRYPTO3_PUBKEY_CURVE_NIST_P521_HPP

#include <memory>

#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/multiprecision/mask_bits.hpp>
#include <boost/multiprecision/reduce_below.hpp>

#include <nil/crypto3/pubkey/ec_group/curve_nist.hpp>

#include <nil/crypto3/utilities/assert.hpp>

namespace nil {
    namespace crypto3 {

        BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(521)

        /**
         * The NIST P-521 curve
         */
        template<std::size_t WordBits = limb_bits>
        class p521 : public curve_nist_policy<521, WordBits> {
        public:
            constexpr static const std::size_t word_bits = curve_nist_policy<521, WordBits>::word_bits;
            constexpr static const std::size_t p_bits = curve_nist_policy<521, WordBits>::p_bits;
            constexpr static const std::size_t p_words = curve_nist_policy<521, WordBits>::p_words;

            typedef number<backends::cpp_int_backend<p_bits, p_bits, unsigned_magnitude, unchecked, void>> p_type;

            constexpr static const p_type p =
                0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_cppui521;

            template<typename Backend, expression_template_option ExpressionTemplates>
            static void redc_mod_p(number<Backend, ExpressionTemplates> &x, secure_vector<uint32_t> &ws) {
                const size_t p_full_words = p_bits / word_bits;
                const size_t p_top_bits = p_bits % word_bits;
                const size_t p_words = p_full_words + 1;

                const size_t x_sw = x.size();

                if (x_sw < p_words) {
                    return;
                }    // already smaller

                if (ws.size() < p_words + 1) {
                    ws.resize(p_words + 1);
                }

                clear_mem(ws.data(), ws.size());
                bigint_shr2(ws.data(), x.backend().limbs(), x_sw, p_full_words, p_top_bits);

                mask_bits(x, p_bits);

                // Word-level carry will be zero
                word carry = bigint_add3_nc(x.backend().limbs(), x.backend().limbs(), p_words, ws.data(), p_words);
                CRYPTO3_ASSERT_EQUAL(carry, 0, "Final carry in P-521 reduction");

                // Now find the actual carry in bit 522
                const uint8_t bit_522_set = x.word_at(p_full_words) >> (p_top_bits);

#if (BOOST_ARCH_CURRENT_WORD_BITS == 64)
                static const word p521_words[9] = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                                   0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                                   0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x1FF};
#endif

                /*
                 * If bit 522 is set then we overflowed and must reduce. Otherwise, if the
                 * top bit is set, it is possible we have x == 2**521 - 1 so check for that.
                 */
                if (bit_522_set) {
#if (BOOST_ARCH_CURRENT_WORD_BITS == 64)
                    bigint_sub2(x.mutable_data(), x.size(), p521_words, 9);
#else
                    x -= p;
#endif
                } else if (x.word_at(p_full_words) >> (p_top_bits - 1)) {
                    /*
                     * Otherwise we must reduce if p is exactly 2^512-1
                     */

                    word possibly_521 = MP_WORD_MAX;
                    for (size_t i = 0; i != p_full_words; ++i) {
                        possibly_521 &= x.word_at(i);
                    }

                    if (possibly_521 == MP_WORD_MAX) {
                        x.reduce_below(p, ws);
                    }
                }
            }

            template<typename Backend, expression_template_option ExpressionTemplates>
            number<Backend, ExpressionTemplates> invert_element(const number<Backend, ExpressionTemplates> &x,
                                                                secure_vector<uint32_t> &ws) const override {
                number<Backend, ExpressionTemplates> r;
                number<Backend, ExpressionTemplates> rl;
                number<Backend, ExpressionTemplates> a7;
                number<Backend, ExpressionTemplates> tmp;

                curve_sqr(r, x, ws);
                curve_mul_tmp(r, x, tmp, ws);

                curve_sqr_tmp(r, tmp, ws);
                curve_mul_tmp(r, x, tmp, ws);

                rl = r;

                for (size_t i = 0; i != 3; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, rl, tmp, ws);

                curve_sqr_tmp(r, tmp, ws);
                curve_mul_tmp(r, x, tmp, ws);
                a7 = r;    // need this value later

                curve_sqr_tmp(r, tmp, ws);
                curve_mul_tmp(r, x, tmp, ws);

                rl = r;
                for (size_t i = 0; i != 8; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, rl, tmp, ws);

                rl = r;
                for (size_t i = 0; i != 16; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, rl, tmp, ws);

                rl = r;
                for (size_t i = 0; i != 32; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, rl, tmp, ws);

                rl = r;
                for (size_t i = 0; i != 64; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, rl, tmp, ws);

                rl = r;
                for (size_t i = 0; i != 128; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, rl, tmp, ws);

                rl = r;
                for (size_t i = 0; i != 256; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, rl, tmp, ws);

                for (size_t i = 0; i != 7; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, a7, tmp, ws);

                for (size_t i = 0; i != 2; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, x, tmp, ws);

                return r;
            }
        };
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CURVE_NIST_P521_HPP
