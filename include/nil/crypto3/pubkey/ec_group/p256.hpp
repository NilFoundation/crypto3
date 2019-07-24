#ifndef CRYPTO3_CURVE_NIST_P256_HPP
#define CRYPTO3_CURVE_NIST_P256_HPP

#include <memory>

#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/multiprecision/mask_bits.hpp>
#include <boost/multiprecision/reduce_below.hpp>

#include <nil/crypto3/pubkey/ec_group/curve_nist.hpp>

#include <nil/crypto3/utilities/assert.hpp>

namespace nil {
    namespace crypto3 {

        /**
         * The NIST P-256 curve
         */
        template<std::size_t WordBits = limb_bits>
        class p256 : public curve_nist_policy<256, WordBits> {
        public:
            constexpr static const std::size_t word_bits = curve_nist_policy<256, WordBits>::word_bits;
            constexpr static const std::size_t p_bits = curve_nist_policy<256, WordBits>::p_bits;
            constexpr static const std::size_t p_words = curve_nist_policy<256, WordBits>::p_words;

            typedef number<backends::cpp_int_backend<p_bits, p_bits, unsigned_magnitude, unchecked, void>> p_type;

            constexpr static const p_type p
                = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF_cppui256;

            template<typename Backend, expression_template_option ExpressionTemplates>
            static void redc_mod_p(number<Backend, ExpressionTemplates> &x) {
                static const size_t p256_limbs = (word_bits == 32) ? 8 : 4;

                const uint32_t X8 = detail::get_uint32_t(x, 8);
                const uint32_t X9 = detail::get_uint32_t(x, 9);
                const uint32_t X10 = detail::get_uint32_t(x, 10);
                const uint32_t X11 = detail::get_uint32_t(x, 11);
                const uint32_t X12 = detail::get_uint32_t(x, 12);
                const uint32_t X13 = detail::get_uint32_t(x, 13);
                const uint32_t X14 = detail::get_uint32_t(x, 14);
                const uint32_t X15 = detail::get_uint32_t(x, 15);

                mask_bits(x, p_bits);
                x.shrink_to_fit(p256_limbs + 1);

                int64_t S = 0;

                // Adds 6 * P-256 to prevent underflow

                S = detail::get_uint32_t(x, 0);
                S += 0xFFFFFFFA;
                S += X8;
                S += X9;
                S -= X11;
                S -= X12;
                S -= X13;
                S -= X14;
                detail::set_uint32_t(x, 0, S);
                S >>= 32;

                S += detail::get_uint32_t(x, 1);
                S += 0xFFFFFFFF;
                S += X9;
                S += X10;
                S -= X12;
                S -= X13;
                S -= X14;
                S -= X15;
                detail::set_uint32_t(x, 1, S);
                S >>= 32;

                S += detail::get_uint32_t(x, 2);
                S += 0xFFFFFFFF;
                S += X10;
                S += X11;
                S -= X13;
                S -= X14;
                S -= X15;
                detail::set_uint32_t(x, 2, S);
                S >>= 32;

                S += detail::get_uint32_t(x, 3);
                S += 5;
                S += X11;
                S += X11;
                S += X12;
                S += X12;
                S += X13;
                S -= X15;
                S -= X8;
                S -= X9;
                detail::set_uint32_t(x, 3, S);
                S >>= 32;

                S += detail::get_uint32_t(x, 4);
                S += X12;
                S += X12;
                S += X13;
                S += X13;
                S += X14;
                S -= X9;
                S -= X10;
                detail::set_uint32_t(x, 4, S);
                S >>= 32;

                S += detail::get_uint32_t(x, 5);
                S += X13;
                S += X13;
                S += X14;
                S += X14;
                S += X15;
                S -= X10;
                S -= X11;
                detail::set_uint32_t(x, 5, S);
                S >>= 32;

                S += detail::get_uint32_t(x, 6);
                S += 6;
                S += X14;
                S += X14;
                S += X15;
                S += X15;
                S += X14;
                S += X13;
                S -= X8;
                S -= X9;
                detail::set_uint32_t(x, 6, S);
                S >>= 32;

                S += detail::get_uint32_t(x, 7);
                S += 0xFFFFFFFA;
                S += X15;
                S += X15;
                S += X15;
                S += X8;
                S -= X10;
                S -= X11;
                S -= X12;
                S -= X13;
                detail::set_uint32_t(x, 7, S);
                S >>= 32;

                S += 5;    // final carry of 6*P-256

                BOOST_ASSERT_MSG(S >= 0 && S <= 10, "Expected overflow");

                /*
                This is a table of (i*P-256) % 2**256 for i in 1...10
                */
                static const uint32_t p256_mults[11][p256_limbs] = {
#if (CRYPTO3_MP_WORD_BITS == 64)
                    {0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF, 0x0000000000000000, 0xFFFFFFFF00000001},
                    {0xFFFFFFFFFFFFFFFE, 0x00000001FFFFFFFF, 0x0000000000000000, 0xFFFFFFFE00000002},
                    {0xFFFFFFFFFFFFFFFD, 0x00000002FFFFFFFF, 0x0000000000000000, 0xFFFFFFFD00000003},
                    {0xFFFFFFFFFFFFFFFC, 0x00000003FFFFFFFF, 0x0000000000000000, 0xFFFFFFFC00000004},
                    {0xFFFFFFFFFFFFFFFB, 0x00000004FFFFFFFF, 0x0000000000000000, 0xFFFFFFFB00000005},
                    {0xFFFFFFFFFFFFFFFA, 0x00000005FFFFFFFF, 0x0000000000000000, 0xFFFFFFFA00000006},
                    {0xFFFFFFFFFFFFFFF9, 0x00000006FFFFFFFF, 0x0000000000000000, 0xFFFFFFF900000007},
                    {0xFFFFFFFFFFFFFFF8, 0x00000007FFFFFFFF, 0x0000000000000000, 0xFFFFFFF800000008},
                    {0xFFFFFFFFFFFFFFF7, 0x00000008FFFFFFFF, 0x0000000000000000, 0xFFFFFFF700000009},
                    {0xFFFFFFFFFFFFFFF6, 0x00000009FFFFFFFF, 0x0000000000000000, 0xFFFFFFF60000000A},
                    {0xFFFFFFFFFFFFFFF5, 0x0000000AFFFFFFFF, 0x0000000000000000, 0xFFFFFFF50000000B},
#else
                    {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF},
                    {0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001, 0x00000000, 0x00000000, 0x00000002, 0xFFFFFFFE},
                    {0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000002, 0x00000000, 0x00000000, 0x00000003, 0xFFFFFFFD},
                    {0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000003, 0x00000000, 0x00000000, 0x00000004, 0xFFFFFFFC},
                    {0xFFFFFFFB, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000004, 0x00000000, 0x00000000, 0x00000005, 0xFFFFFFFB},
                    {0xFFFFFFFA, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000005, 0x00000000, 0x00000000, 0x00000006, 0xFFFFFFFA},
                    {0xFFFFFFF9, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000006, 0x00000000, 0x00000000, 0x00000007, 0xFFFFFFF9},
                    {0xFFFFFFF8, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000007, 0x00000000, 0x00000000, 0x00000008, 0xFFFFFFF8},
                    {0xFFFFFFF7, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000008, 0x00000000, 0x00000000, 0x00000009, 0xFFFFFFF7},
                    {0xFFFFFFF6, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000009, 0x00000000, 0x00000000, 0x0000000A, 0xFFFFFFF6},
                    {0xFFFFFFF5, 0xFFFFFFFF, 0xFFFFFFFF, 0x0000000A, 0x00000000, 0x00000000, 0x0000000B, 0xFFFFFFF5},
#endif
                };

                word borrow = bigint_sub2(x.backend().limbs(), x.size(), p256_mults[S], p256_limbs);

                BOOST_ASSERT_MSG(borrow == 0 || borrow == 1, "Expected borrow during P-256 reduction");

                if (borrow) {
                    bigint_add2(x.backend().limbs(), x.size() - 1, p256_mults[0], p256_limbs);
                }
            }

            template<typename Backend, expression_template_option ExpressionTemplates>
            number<Backend, ExpressionTemplates> invert_element(const number<Backend, ExpressionTemplates> &x,
                                                                secure_vector<uint32_t> &ws) const override {
                boost::multiprecision::cpp_int r, p2, p4, p8, p16, p32, tmp;

                curve_sqr(r, x, ws);

                curve_mul(p2, r, x, ws);
                curve_sqr(r, p2, ws);
                curve_sqr_tmp(r, tmp, ws);

                curve_mul(p4, r, p2, ws);

                curve_sqr(r, p4, ws);
                for (size_t i = 0; i != 3; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul(p8, r, p4, ws);

                curve_sqr(r, p8, ws);
                for (size_t i = 0; i != 7; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul(p16, r, p8, ws);

                curve_sqr(r, p16, ws);
                for (size_t i = 0; i != 15; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul(p32, r, p16, ws);

                curve_sqr(r, p32, ws);
                for (size_t i = 0; i != 31; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, x, tmp, ws);

                for (size_t i = 0; i != 32 * 4; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, p32, tmp, ws);

                for (size_t i = 0; i != 32; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, p32, tmp, ws);

                for (size_t i = 0; i != 16; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, p16, tmp, ws);
                for (size_t i = 0; i != 8; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, p8, tmp, ws);

                for (size_t i = 0; i != 4; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, p4, tmp, ws);

                for (size_t i = 0; i != 2; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, p2, tmp, ws);

                for (size_t i = 0; i != 2; ++i) {
                    curve_sqr_tmp(r, tmp, ws);
                }
                curve_mul_tmp(r, x, tmp, ws);

                return r;
            }
        };
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CURVE_NIST_P256_HPP
