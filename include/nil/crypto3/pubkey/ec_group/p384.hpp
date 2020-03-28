//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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
    namespace crypto3 {
        namespace pubkey {

            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(384)

            /**
             * The NIST P-384 curve
             */
            template<std::size_t WordBits = limb_bits>
            class p384 : public curve_nist_policy<384, WordBits> {
            public:
                constexpr static const std::size_t word_bits = curve_nist_policy<384, WordBits>::word_bits;
                constexpr static const std::size_t p_bits = curve_nist_policy<384, WordBits>::p_bits;
                constexpr static const std::size_t p_words = curve_nist_policy<384, WordBits>::p_words;

                typedef number<backends::cpp_int_backend<p_bits, p_bits, unsigned_magnitude, unchecked, void>> p_type;

                constexpr static const p_type p =
                    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF_cppui384;

                template<typename Backend, expression_template_option ExpressionTemplates>
                static void redc_mod_p(number<Backend, ExpressionTemplates> &x) {
                    static const size_t p384_limbs = (word_bits == 32) ? 12 : 6;

                    const uint32_t X12 = detail::get_uint32_t(x, 12);
                    const uint32_t X13 = detail::get_uint32_t(x, 13);
                    const uint32_t X14 = detail::get_uint32_t(x, 14);
                    const uint32_t X15 = detail::get_uint32_t(x, 15);
                    const uint32_t X16 = detail::get_uint32_t(x, 16);
                    const uint32_t X17 = detail::get_uint32_t(x, 17);
                    const uint32_t X18 = detail::get_uint32_t(x, 18);
                    const uint32_t X19 = detail::get_uint32_t(x, 19);
                    const uint32_t X20 = detail::get_uint32_t(x, 20);
                    const uint32_t X21 = detail::get_uint32_t(x, 21);
                    const uint32_t X22 = detail::get_uint32_t(x, 22);
                    const uint32_t X23 = detail::get_uint32_t(x, 23);

                    mask_bits(x, p_bits);
                    x.shrink_to_fit(p384_limbs + 1);

                    int64_t S = 0;

                    // One copy of P-384 is added to prevent underflow
                    S = detail::get_uint32_t(x, 0);
                    S += 0xFFFFFFFF;
                    S += X12;
                    S += X21;
                    S += X20;
                    S -= X23;
                    detail::set_uint32_t(x, 0, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 1);
                    S += X13;
                    S += X22;
                    S += X23;
                    S -= X12;
                    S -= X20;
                    detail::set_uint32_t(x, 1, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 2);
                    S += X14;
                    S += X23;
                    S -= X13;
                    S -= X21;
                    detail::set_uint32_t(x, 2, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 3);
                    S += 0xFFFFFFFF;
                    S += X15;
                    S += X12;
                    S += X20;
                    S += X21;
                    S -= X14;
                    S -= X22;
                    S -= X23;
                    detail::set_uint32_t(x, 3, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 4);
                    S += 0xFFFFFFFE;
                    S += X21;
                    S += X21;
                    S += X16;
                    S += X13;
                    S += X12;
                    S += X20;
                    S += X22;
                    S -= X15;
                    S -= X23;
                    S -= X23;
                    detail::set_uint32_t(x, 4, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 5);
                    S += 0xFFFFFFFF;
                    S += X22;
                    S += X22;
                    S += X17;
                    S += X14;
                    S += X13;
                    S += X21;
                    S += X23;
                    S -= X16;
                    detail::set_uint32_t(x, 5, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 6);
                    S += 0xFFFFFFFF;
                    S += X23;
                    S += X23;
                    S += X18;
                    S += X15;
                    S += X14;
                    S += X22;
                    S -= X17;
                    detail::set_uint32_t(x, 6, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 7);
                    S += 0xFFFFFFFF;
                    S += X19;
                    S += X16;
                    S += X15;
                    S += X23;
                    S -= X18;
                    detail::set_uint32_t(x, 7, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 8);
                    S += 0xFFFFFFFF;
                    S += X20;
                    S += X17;
                    S += X16;
                    S -= X19;
                    detail::set_uint32_t(x, 8, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 9);
                    S += 0xFFFFFFFF;
                    S += X21;
                    S += X18;
                    S += X17;
                    S -= X20;
                    detail::set_uint32_t(x, 9, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 10);
                    S += 0xFFFFFFFF;
                    S += X22;
                    S += X19;
                    S += X18;
                    S -= X21;
                    detail::set_uint32_t(x, 10, S);
                    S >>= 32;

                    S += detail::get_uint32_t(x, 11);
                    S += 0xFFFFFFFF;
                    S += X23;
                    S += X20;
                    S += X19;
                    S -= X22;
                    detail::set_uint32_t(x, 11, S);
                    S >>= 32;

                    BOOST_ASSERT_MSG(S >= 0 && S <= 4, "Expected overflow in P-384 reduction");

                    /*
                    This is a table of (i*P-384) % 2**384 for i in 1...4
                    */
                    static const uint32_t p384_mults[5][p384_limbs] = {
#if (CRYPTO3_MP_WORD_BITS == 64)
                        {0x00000000FFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF,
                         0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
                        {0x00000001FFFFFFFE, 0xFFFFFFFE00000000, 0xFFFFFFFFFFFFFFFD, 0xFFFFFFFFFFFFFFFF,
                         0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
                        {0x00000002FFFFFFFD, 0xFFFFFFFD00000000, 0xFFFFFFFFFFFFFFFC, 0xFFFFFFFFFFFFFFFF,
                         0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
                        {0x00000003FFFFFFFC, 0xFFFFFFFC00000000, 0xFFFFFFFFFFFFFFFB, 0xFFFFFFFFFFFFFFFF,
                         0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
                        {0x00000004FFFFFFFB, 0xFFFFFFFB00000000, 0xFFFFFFFFFFFFFFFA, 0xFFFFFFFFFFFFFFFF,
                         0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},

#else
                        {0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                         0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
                        {0xFFFFFFFE, 0x00000001, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                         0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
                        {0xFFFFFFFD, 0x00000002, 0x00000000, 0xFFFFFFFD, 0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                         0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
                        {0xFFFFFFFC, 0x00000003, 0x00000000, 0xFFFFFFFC, 0xFFFFFFFB, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                         0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
                        {0xFFFFFFFB, 0x00000004, 0x00000000, 0xFFFFFFFB, 0xFFFFFFFA, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                         0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
#endif
                    };

                    word borrow = bigint_sub2(x.backend().limbs(), x.size(), p384_mults[S], p384_limbs);

                    BOOST_ASSERT_MSG(borrow == 0 || borrow == 1, "Expected borrow during P-384 reduction");

                    if (borrow) {
                        bigint_add2(x.backend().limbs(), x.size() - 1, p384_mults[0], p384_limbs);
                    }
                }

                template<typename Backend, expression_template_option ExpressionTemplates>
                number<Backend, ExpressionTemplates> invert_element(const number<Backend, ExpressionTemplates> &x,
                                                                    secure_vector<uint32_t> &ws) const override {
                    number<Backend, ExpressionTemplates> r, x2, x3, x15, x30, tmp, rl;

                    r = x;
                    curve_sqr_tmp(r, tmp, ws);
                    curve_mul_tmp(r, x, tmp, ws);
                    x2 = r;

                    curve_sqr_tmp(r, tmp, ws);
                    curve_mul_tmp(r, x, tmp, ws);

                    x3 = r;

                    for (size_t i = 0; i != 3; ++i) {
                        curve_sqr_tmp(r, tmp, ws);
                    }
                    curve_mul_tmp(r, x3, tmp, ws);

                    rl = r;
                    for (size_t i = 0; i != 6; ++i) {
                        curve_sqr_tmp(r, tmp, ws);
                    }
                    curve_mul_tmp(r, rl, tmp, ws);

                    for (size_t i = 0; i != 3; ++i) {
                        curve_sqr_tmp(r, tmp, ws);
                    }
                    curve_mul_tmp(r, x3, tmp, ws);

                    x15 = r;
                    for (size_t i = 0; i != 15; ++i) {
                        curve_sqr_tmp(r, tmp, ws);
                    }
                    curve_mul_tmp(r, x15, tmp, ws);

                    x30 = r;
                    for (size_t i = 0; i != 30; ++i) {
                        curve_sqr_tmp(r, tmp, ws);
                    }
                    curve_mul_tmp(r, x30, tmp, ws);

                    rl = r;
                    for (size_t i = 0; i != 60; ++i) {
                        curve_sqr_tmp(r, tmp, ws);
                    }
                    curve_mul_tmp(r, rl, tmp, ws);

                    rl = r;
                    for (size_t i = 0; i != 120; ++i) {
                        curve_sqr_tmp(r, tmp, ws);
                    }
                    curve_mul_tmp(r, rl, tmp, ws);

                    for (size_t i = 0; i != 15; ++i) {
                        curve_sqr_tmp(r, tmp, ws);
                    }
                    curve_mul_tmp(r, x15, tmp, ws);

                    for (size_t i = 0; i != 31; ++i) {
                        curve_sqr_tmp(r, tmp, ws);
                    }
                    curve_mul_tmp(r, x30, tmp, ws);

                    for (size_t i = 0; i != 2; ++i) {
                        curve_sqr_tmp(r, tmp, ws);
                    }
                    curve_mul_tmp(r, x2, tmp, ws);

                    for (size_t i = 0; i != 94; ++i) {
                        curve_sqr_tmp(r, tmp, ws);
                    }
                    curve_mul_tmp(r, x30, tmp, ws);

                    for (size_t i = 0; i != 2; ++i) {
                        curve_sqr_tmp(r, tmp, ws);
                    }

                    curve_mul_tmp(r, x, tmp, ws);

                    return r;
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CURVE_NIST_P384_HPP
