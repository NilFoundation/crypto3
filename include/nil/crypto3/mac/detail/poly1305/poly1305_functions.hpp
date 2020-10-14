//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MAC_POLY1305_FUNCTIONS_HPP
#define CRYPTO3_MAC_POLY1305_FUNCTIONS_HPP

#include <boost/endian/arithmetic.hpp>
#include <boost/endian/conversion.hpp>

#include <nil/crypto3/detail/make_uint_t.hpp>

#include <nil/crypto3/mac/detail/poly1305/poly1305_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            namespace detail {
                struct poly1305_functions : public poly1305_policy {
                    typedef poly1305_policy policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t key_words = policy_type::key_words;
                    constexpr static const std::size_t key_bits = policy_type::key_bits;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t key_schedule_bits = policy_type::key_schedule_bits;
                    constexpr static const std::size_t key_schedule_words = policy_type::key_schedule_words;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    static void poly1305_init(key_schedule_type &X, const key_type &key) {
                        using namespace nil::crypto3::detail;
                        /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
                        const word_type t0 = boost::endian::native_to_little(
                            make_uint_t<word_bits>(key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]));
                        const word_type t1 = boost::endian::native_to_little(make_uint_t<word_bits>(
                            key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15]));

                        X[0] = (t0)&0xffc0fffffff;
                        X[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
                        X[2] = ((t1 >> 24)) & 0x00ffffffc0f;

                        /* h = 0 */
                        X[3] = 0;
                        X[4] = 0;
                        X[5] = 0;

                        /* save pad for later */
                        X[6] = boost::endian::native_to_little(make_uint_t<word_bits>(
                            key[16], key[17], key[18], key[19], key[20], key[21], key[22], key[23]));
                        X[7] = boost::endian::native_to_little(make_uint_t<word_bits>(
                            key[24], key[25], key[26], key[27], key[28], key[29], key[30], key[31]));
                    }

                    static void poly1305_blocks(key_schedule_type &X, const uint8_t *m, size_t blocks,
                                                bool is_final = false) {
                        const word_type hibit = is_final ? 0 : (static_cast<word_type>(1) << 40); /* 1 << 128 */

                        const word_type r0 = X[0];
                        const word_type r1 = X[1];
                        const word_type r2 = X[2];

                        word_type h0 = X[3 + 0];
                        word_type h1 = X[3 + 1];
                        word_type h2 = X[3 + 2];

                        const word_type s1 = r1 * (5 << 2);
                        const word_type s2 = r2 * (5 << 2);

                        while (blocks--) {
                            /* h += m[i] */
                            const word_type t0 = load_le<word_type>(m, 0);
                            const word_type t1 = load_le<word_type>(m, 1);

                            h0 += ((t0)&0xfffffffffff);
                            h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff);
                            h2 += (((t1 >> 24)) & 0x3ffffffffff) | hibit;

                            /* h *= r */
                            uint128_t d0 = uint128_t(h0) * r0 + uint128_t(h1) * s2 + uint128_t(h2) * s1;
                            uint128_t d1 = uint128_t(h0) * r1 + uint128_t(h1) * r0 + uint128_t(h2) * s2;
                            uint128_t d2 = uint128_t(h0) * r2 + uint128_t(h1) * r1 + uint128_t(h2) * r0;

                            /* (partial) h %= p */
                            word_type c = carry_shift(d0, 44);
                            h0 = d0 & 0xfffffffffff;
                            d1 += c;
                            c = carry_shift(d1, 44);
                            h1 = d1 & 0xfffffffffff;
                            d2 += c;
                            c = carry_shift(d2, 42);
                            h2 = d2 & 0x3ffffffffff;
                            h0 += c * 5;
                            c = carry_shift(h0, 44);
                            h0 = h0 & 0xfffffffffff;
                            h1 += c;

                            m += 16;
                        }

                        X[3 + 0] = h0;
                        X[3 + 1] = h1;
                        X[3 + 2] = h2;
                    }

                    static void poly1305_finish(key_schedule_type &X, uint8_t mac[16]) {
                        /* fully carry h */
                        word_type h0 = X[3 + 0];
                        word_type h1 = X[3 + 1];
                        word_type h2 = X[3 + 2];

                        word_type c;
                        c = (h1 >> 44);
                        h1 &= 0xfffffffffff;
                        h2 += c;
                        c = (h2 >> 42);
                        h2 &= 0x3ffffffffff;
                        h0 += c * 5;
                        c = (h0 >> 44);
                        h0 &= 0xfffffffffff;
                        h1 += c;
                        c = (h1 >> 44);
                        h1 &= 0xfffffffffff;
                        h2 += c;
                        c = (h2 >> 42);
                        h2 &= 0x3ffffffffff;
                        h0 += c * 5;
                        c = (h0 >> 44);
                        h0 &= 0xfffffffffff;
                        h1 += c;

                        /* compute h + -p */
                        word_type g0 = h0 + 5;
                        c = (g0 >> 44);
                        g0 &= 0xfffffffffff;
                        word_type g1 = h1 + c;
                        c = (g1 >> 44);
                        g1 &= 0xfffffffffff;
                        word_type g2 = h2 + c - (static_cast<word_type>(1) << 42);

                        /* select h if h < p, or h + -p if h >= p */
                        c = (g2 >> ((sizeof(word_type) * 8) - 1)) - 1;
                        g0 &= c;
                        g1 &= c;
                        g2 &= c;
                        c = ~c;
                        h0 = (h0 & c) | g0;
                        h1 = (h1 & c) | g1;
                        h2 = (h2 & c) | g2;

                        /* h = (h + pad) */
                        const word_type t0 = X[6];
                        const word_type t1 = X[7];

                        h0 += ((t0)&0xfffffffffff);
                        c = (h0 >> 44);
                        h0 &= 0xfffffffffff;
                        h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c;
                        c = (h1 >> 44);
                        h1 &= 0xfffffffffff;
                        h2 += (((t1 >> 24)) & 0x3ffffffffff) + c;
                        h2 &= 0x3ffffffffff;

                        /* mac = h % (2^128) */
                        h0 = ((h0) | (h1 << 44));
                        h1 = ((h1 >> 20) | (h2 << 24));

                        store_le(mac, h0, h1);

                        /* zero out the state */
                        clear_mem(X.data(), X.size());
                    }
                };
            }    // namespace detail
        }        // namespace mac
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_POLY1305_FUNCTIONS_HPP
