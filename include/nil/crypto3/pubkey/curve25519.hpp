//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_CURVE_25519_HPP
#define CRYPTO3_PUBKEY_CURVE_25519_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
#if !defined(CRYPTO3_TARGET_HAS_NATIVE_UINT128)
                typedef donna128 uint128_t;
#endif

                /* Sum two numbers: output += in */
                inline void fsum(uint64_t out[5], const uint64_t in[5]) {
                    out[0] += in[0];
                    out[1] += in[1];
                    out[2] += in[2];
                    out[3] += in[3];
                    out[4] += in[4];
                }

                /* Find the difference of two numbers: out = in - out
                 * (note the order of the arguments!)
                 *
                 * Assumes that out[i] < 2**52
                 * On return, out[i] < 2**55
                 */
                inline void fdifference_backwards(uint64_t out[5], const uint64_t in[5]) {
                    /* 152 is 19 << 3 */
                    const uint64_t two54m152 = (static_cast<uint64_t>(1) << 54) - 152;
                    const uint64_t two54m8 = (static_cast<uint64_t>(1) << 54) - 8;

                    out[0] = in[0] + two54m152 - out[0];
                    out[1] = in[1] + two54m8 - out[1];
                    out[2] = in[2] + two54m8 - out[2];
                    out[3] = in[3] + two54m8 - out[3];
                    out[4] = in[4] + two54m8 - out[4];
                }

                inline void fadd_sub(uint64_t x[5], uint64_t y[5]) {
                    // TODO merge these and avoid the tmp array
                    uint64_t tmp[5];
                    copy_mem(tmp, y, 5);
                    fsum(y, x);
                    fdifference_backwards(x, tmp);    // does x - z
                }

                /* Multiply a number by a scalar: out = in * scalar */
                inline void fscalar_product(uint64_t out[5], const uint64_t in[5], const uint64_t scalar) {
                    uint128_t a = uint128_t(in[0]) * scalar;
                    out[0] = a & 0x7ffffffffffff;

                    a = uint128_t(in[1]) * scalar + carry_shift(a, 51);
                    out[1] = a & 0x7ffffffffffff;

                    a = uint128_t(in[2]) * scalar + carry_shift(a, 51);
                    out[2] = a & 0x7ffffffffffff;

                    a = uint128_t(in[3]) * scalar + carry_shift(a, 51);
                    out[3] = a & 0x7ffffffffffff;

                    a = uint128_t(in[4]) * scalar + carry_shift(a, 51);
                    out[4] = a & 0x7ffffffffffff;

                    out[0] += carry_shift(a, 51) * 19;
                }

                /* Multiply two numbers: out = in2 * in
                 *
                 * out must be distinct to both inputs. The inputs are reduced coefficient
                 * form, the output is not.
                 *
                 * Assumes that in[i] < 2**55 and likewise for in2.
                 * On return, out[i] < 2**52
                 */
                inline void fmul(uint64_t out[5], const uint64_t in[5], const uint64_t in2[5]) {
                    const uint128_t s0 = in2[0];
                    const uint128_t s1 = in2[1];
                    const uint128_t s2 = in2[2];
                    const uint128_t s3 = in2[3];
                    const uint128_t s4 = in2[4];

                    uint64_t r0 = in[0];
                    uint64_t r1 = in[1];
                    uint64_t r2 = in[2];
                    uint64_t r3 = in[3];
                    uint64_t r4 = in[4];

                    uint128_t t0 = r0 * s0;
                    uint128_t t1 = r0 * s1 + r1 * s0;
                    uint128_t t2 = r0 * s2 + r2 * s0 + r1 * s1;
                    uint128_t t3 = r0 * s3 + r3 * s0 + r1 * s2 + r2 * s1;
                    uint128_t t4 = r0 * s4 + r4 * s0 + r3 * s1 + r1 * s3 + r2 * s2;

                    r4 *= 19;
                    r1 *= 19;
                    r2 *= 19;
                    r3 *= 19;

                    t0 += r4 * s1 + r1 * s4 + r2 * s3 + r3 * s2;
                    t1 += r4 * s2 + r2 * s4 + r3 * s3;
                    t2 += r4 * s3 + r3 * s4;
                    t3 += r4 * s4;

                    r0 = t0 & 0x7ffffffffffff;
                    t1 += carry_shift(t0, 51);
                    r1 = t1 & 0x7ffffffffffff;
                    t2 += carry_shift(t1, 51);
                    r2 = t2 & 0x7ffffffffffff;
                    t3 += carry_shift(t2, 51);
                    r3 = t3 & 0x7ffffffffffff;
                    t4 += carry_shift(t3, 51);
                    r4 = t4 & 0x7ffffffffffff;
                    uint64_t c = carry_shift(t4, 51);

                    r0 += c * 19;
                    c = r0 >> 51;
                    r0 = r0 & 0x7ffffffffffff;
                    r1 += c;
                    c = r1 >> 51;
                    r1 = r1 & 0x7ffffffffffff;
                    r2 += c;

                    out[0] = r0;
                    out[1] = r1;
                    out[2] = r2;
                    out[3] = r3;
                    out[4] = r4;
                }

                inline void fsquare_times(uint64_t out[5], const uint64_t in[5], size_t count) {
                    uint64_t r0 = in[0];
                    uint64_t r1 = in[1];
                    uint64_t r2 = in[2];
                    uint64_t r3 = in[3];
                    uint64_t r4 = in[4];

                    for (size_t i = 0; i != count; ++i) {
                        const uint64_t d0 = r0 * 2;
                        const uint64_t d1 = r1 * 2;
                        const uint64_t d2 = r2 * 2 * 19;
                        const uint64_t d419 = r4 * 19;
                        const uint64_t d4 = d419 * 2;

                        uint128_t t0 = uint128_t(r0) * r0 + uint128_t(d4) * r1 + uint128_t(d2) * (r3);
                        uint128_t t1 = uint128_t(d0) * r1 + uint128_t(d4) * r2 + uint128_t(r3) * (r3 * 19);
                        uint128_t t2 = uint128_t(d0) * r2 + uint128_t(r1) * r1 + uint128_t(d4) * (r3);
                        uint128_t t3 = uint128_t(d0) * r3 + uint128_t(d1) * r2 + uint128_t(r4) * (d419);
                        uint128_t t4 = uint128_t(d0) * r4 + uint128_t(d1) * r3 + uint128_t(r2) * (r2);

                        r0 = t0 & 0x7ffffffffffff;
                        t1 += carry_shift(t0, 51);
                        r1 = t1 & 0x7ffffffffffff;
                        t2 += carry_shift(t1, 51);
                        r2 = t2 & 0x7ffffffffffff;
                        t3 += carry_shift(t2, 51);
                        r3 = t3 & 0x7ffffffffffff;
                        t4 += carry_shift(t3, 51);
                        r4 = t4 & 0x7ffffffffffff;
                        uint64_t c = carry_shift(t4, 51);

                        r0 += c * 19;
                        c = r0 >> 51;
                        r0 = r0 & 0x7ffffffffffff;
                        r1 += c;
                        c = r1 >> 51;
                        r1 = r1 & 0x7ffffffffffff;
                        r2 += c;
                    }

                    out[0] = r0;
                    out[1] = r1;
                    out[2] = r2;
                    out[3] = r3;
                    out[4] = r4;
                }

                inline void fsquare(uint64_t out[5], const uint64_t in[5]) {
                    return fsquare_times(out, in, 1);
                }

                /* Take a little-endian, 32-byte number and expand it into polynomial form */
                inline void fexpand(uint64_t *out, const uint8_t *in) {
                    out[0] = load_le<uint64_t>(in, 0) & 0x7ffffffffffff;
                    out[1] = (load_le<uint64_t>(in + 6, 0) >> 3) & 0x7ffffffffffff;
                    out[2] = (load_le<uint64_t>(in + 12, 0) >> 6) & 0x7ffffffffffff;
                    out[3] = (load_le<uint64_t>(in + 19, 0) >> 1) & 0x7ffffffffffff;
                    out[4] = (load_le<uint64_t>(in + 24, 0) >> 12) & 0x7ffffffffffff;
                }

                /* Take a fully reduced polynomial form number and contract it into a
                 * little-endian, 32-byte array
                 */
                inline void fcontract(uint8_t *out, const uint64_t input[5]) {
                    uint128_t t0 = input[0];
                    uint128_t t1 = input[1];
                    uint128_t t2 = input[2];
                    uint128_t t3 = input[3];
                    uint128_t t4 = input[4];

                    for (size_t i = 0; i != 2; ++i) {
                        t1 += t0 >> 51;
                        t0 &= 0x7ffffffffffff;
                        t2 += t1 >> 51;
                        t1 &= 0x7ffffffffffff;
                        t3 += t2 >> 51;
                        t2 &= 0x7ffffffffffff;
                        t4 += t3 >> 51;
                        t3 &= 0x7ffffffffffff;
                        t0 += (t4 >> 51) * 19;
                        t4 &= 0x7ffffffffffff;
                    }

                    /* now t is between 0 and 2^255-1, properly carried. */
                    /* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */

                    t0 += 19;

                    t1 += t0 >> 51;
                    t0 &= 0x7ffffffffffff;
                    t2 += t1 >> 51;
                    t1 &= 0x7ffffffffffff;
                    t3 += t2 >> 51;
                    t2 &= 0x7ffffffffffff;
                    t4 += t3 >> 51;
                    t3 &= 0x7ffffffffffff;
                    t0 += (t4 >> 51) * 19;
                    t4 &= 0x7ffffffffffff;

                    /* now between 19 and 2^255-1 in both cases, and offset by 19. */

                    t0 += 0x8000000000000 - 19;
                    t1 += 0x8000000000000 - 1;
                    t2 += 0x8000000000000 - 1;
                    t3 += 0x8000000000000 - 1;
                    t4 += 0x8000000000000 - 1;

                    /* now between 2^255 and 2^256-20, and offset by 2^255. */

                    t1 += t0 >> 51;
                    t0 &= 0x7ffffffffffff;
                    t2 += t1 >> 51;
                    t1 &= 0x7ffffffffffff;
                    t3 += t2 >> 51;
                    t2 &= 0x7ffffffffffff;
                    t4 += t3 >> 51;
                    t3 &= 0x7ffffffffffff;
                    t4 &= 0x7ffffffffffff;

                    store_le(out, combine_lower(t0, 0, t1, 51), combine_lower(t1, 13, t2, 38),
                             combine_lower(t2, 26, t3, 25), combine_lower(t3, 39, t4, 12));
                }

                /* Input: Q, Q', Q-Q'
                 * Out: 2Q, Q+Q'
                 *
                 *   result.two_q (2*Q): long form
                 *   result.q_plus_q_dash (Q + Q): long form
                 *   in_q: short form, destroyed
                 *   in_q_dash: short form, destroyed
                 *   in_q_minus_q_dash: short form, preserved
                 */

                void fmonty(uint64_t result_two_q_x[5], uint64_t result_two_q_z[5], uint64_t result_q_plus_q_dash_x[5],
                            uint64_t result_q_plus_q_dash_z[5], uint64_t in_q_x[5], uint64_t in_q_z[5],
                            uint64_t in_q_dash_x[5], uint64_t in_q_dash_z[5], const uint64_t q_minus_q_dash[5]) {
                    uint64_t zzz[5];
                    uint64_t xx[5];
                    uint64_t zz[5];
                    uint64_t xxprime[5];
                    uint64_t zzprime[5];
                    uint64_t zzzprime[5];

                    fadd_sub(in_q_z, in_q_x);
                    fadd_sub(in_q_dash_z, in_q_dash_x);

                    fmul(xxprime, in_q_dash_x, in_q_z);
                    fmul(zzprime, in_q_dash_z, in_q_x);

                    fadd_sub(zzprime, xxprime);

                    fsquare(result_q_plus_q_dash_x, xxprime);
                    fsquare(zzzprime, zzprime);
                    fmul(result_q_plus_q_dash_z, zzzprime, q_minus_q_dash);

                    fsquare(xx, in_q_x);
                    fsquare(zz, in_q_z);
                    fmul(result_two_q_x, xx, zz);

                    fdifference_backwards(zz, xx);    // does zz = xx - zz
                    fscalar_product(zzz, zz, 121665);
                    fsum(zzz, xx);

                    fmul(result_two_q_z, zz, zzz);
                }

                /*
                 * Maybe swap the contents of two uint64_t arrays (@a and @b),
                 * Param @iswap is assumed to be either 0 or 1
                 *
                 * This function performs the swap without leaking any side-channel
                 * information.
                 */
                void swap_conditional(uint64_t a[5], uint64_t b[5], uint64_t iswap) {
                    const uint64_t swap = static_cast<uint64_t>(-static_cast<int64_t>(iswap));

                    for (size_t i = 0; i < 5; ++i) {
                        const uint64_t x = swap & (a[i] ^ b[i]);
                        a[i] ^= x;
                        b[i] ^= x;
                    }
                }

                /* Calculates nQ where Q is the x-coordinate of a point on the curve
                 *
                 *   resultx/resultz: the x/z coordinate of the resulting curve point (short form)
                 *   n: a little endian, 32-byte number
                 *   q: a point of the curve (short form)
                 */
                void cmult(uint64_t resultx[5], uint64_t resultz[5], const uint8_t n[32], const uint64_t q[5]) {
                    uint64_t a[5] = {0};    // nqpqx
                    uint64_t b[5] = {1};    // npqpz
                    uint64_t c[5] = {1};    // nqx
                    uint64_t d[5] = {0};    // nqz
                    uint64_t e[5] = {0};    // npqqx2
                    uint64_t f[5] = {1};    // npqqz2
                    uint64_t g[5] = {0};    // nqx2
                    uint64_t h[5] = {1};    // nqz2

                    copy_mem(a, q, 5);

                    for (size_t i = 0; i < 32; ++i) {
                        const uint64_t bit0 = (n[31 - i] >> 7) & 1;
                        const uint64_t bit1 = (n[31 - i] >> 6) & 1;
                        const uint64_t bit2 = (n[31 - i] >> 5) & 1;
                        const uint64_t bit3 = (n[31 - i] >> 4) & 1;
                        const uint64_t bit4 = (n[31 - i] >> 3) & 1;
                        const uint64_t bit5 = (n[31 - i] >> 2) & 1;
                        const uint64_t bit6 = (n[31 - i] >> 1) & 1;
                        const uint64_t bit7 = (n[31 - i] >> 0) & 1;

                        swap_conditional(c, a, bit0);
                        swap_conditional(d, b, bit0);
                        fmonty(g, h, e, f, c, d, a, b, q);

                        swap_conditional(g, e, bit0 ^ bit1);
                        swap_conditional(h, f, bit0 ^ bit1);
                        fmonty(c, d, a, b, g, h, e, f, q);

                        swap_conditional(c, a, bit1 ^ bit2);
                        swap_conditional(d, b, bit1 ^ bit2);
                        fmonty(g, h, e, f, c, d, a, b, q);

                        swap_conditional(g, e, bit2 ^ bit3);
                        swap_conditional(h, f, bit2 ^ bit3);
                        fmonty(c, d, a, b, g, h, e, f, q);

                        swap_conditional(c, a, bit3 ^ bit4);
                        swap_conditional(d, b, bit3 ^ bit4);
                        fmonty(g, h, e, f, c, d, a, b, q);

                        swap_conditional(g, e, bit4 ^ bit5);
                        swap_conditional(h, f, bit4 ^ bit5);
                        fmonty(c, d, a, b, g, h, e, f, q);

                        swap_conditional(c, a, bit5 ^ bit6);
                        swap_conditional(d, b, bit5 ^ bit6);
                        fmonty(g, h, e, f, c, d, a, b, q);

                        swap_conditional(g, e, bit6 ^ bit7);
                        swap_conditional(h, f, bit6 ^ bit7);
                        fmonty(c, d, a, b, g, h, e, f, q);

                        swap_conditional(c, a, bit7);
                        swap_conditional(d, b, bit7);
                    }

                    copy_mem(resultx, c, 5);
                    copy_mem(resultz, d, 5);
                }

                // -----------------------------------------------------------------------------
                // Shamelessly copied from djb's code, tightened a little
                // -----------------------------------------------------------------------------
                void crecip(uint64_t out[5], const uint64_t z[5]) {
                    uint64_t a[5];
                    uint64_t b[5];
                    uint64_t c[5];
                    uint64_t t0[5];

                    /* 2 */ fsquare(a, z);    // a = 2
                    /* 8 */ fsquare_times(t0, a, 2);
                    /* 9 */ fmul(b, t0, z);    // b = 9
                    /* 11 */ fmul(a, b, a);    // a = 11
                    /* 22 */ fsquare(t0, a);
                    /* 2^5 - 2^0 = 31 */ fmul(b, t0, b);
                    /* 2^10 - 2^5 */ fsquare_times(t0, b, 5);
                    /* 2^10 - 2^0 */ fmul(b, t0, b);
                    /* 2^20 - 2^10 */ fsquare_times(t0, b, 10);
                    /* 2^20 - 2^0 */ fmul(c, t0, b);
                    /* 2^40 - 2^20 */ fsquare_times(t0, c, 20);
                    /* 2^40 - 2^0 */ fmul(t0, t0, c);
                    /* 2^50 - 2^10 */ fsquare_times(t0, t0, 10);
                    /* 2^50 - 2^0 */ fmul(b, t0, b);
                    /* 2^100 - 2^50 */ fsquare_times(t0, b, 50);
                    /* 2^100 - 2^0 */ fmul(c, t0, b);
                    /* 2^200 - 2^100 */ fsquare_times(t0, c, 100);
                    /* 2^200 - 2^0 */ fmul(t0, t0, c);
                    /* 2^250 - 2^50 */ fsquare_times(t0, t0, 50);
                    /* 2^250 - 2^0 */ fmul(t0, t0, b);
                    /* 2^255 - 2^5 */ fsquare_times(t0, t0, 5);
                    /* 2^255 - 21 */ fmul(out, t0, a);
                }

                /*
                 * The types above are just wrappers for curve25519_donna, plus defining
                 * encodings for public and private keys.
                 */
                void curve25519_donna(uint8_t mypublic[32], const uint8_t secret[32], const uint8_t basepoint[32]) {
                    ct::poison(secret, 32);
                    ct::poison(basepoint, 32);

                    uint64_t bp[5], x[5], z[5], zmone[5];
                    uint8_t e[32];

                    copy_mem(e, secret, 32);
                    e[0] &= 248;
                    e[31] &= 127;
                    e[31] |= 64;

                    fexpand(bp, basepoint);
                    cmult(x, z, e, bp);
                    crecip(zmone, z);
                    fmul(z, x, zmone);
                    fcontract(mypublic, z);

                    ct::unpoison(secret, 32);
                    ct::unpoison(basepoint, 32);
                    ct::unpoison(mypublic, 32);
                }

                /**
                 * Exponentiate by the x25519 base point
                 * @param mypublic output value
                 * @param secret random scalar
                 */
                void curve25519_basepoint(uint8_t mypublic[32], const uint8_t secret[32]) {
                    const uint8_t basepoint[32] = {9};
                    curve25519_donna(mypublic, secret, basepoint);
                }

                void size_check(size_t size, const char *thing) {
                    if (size != 32) {
                        throw decoding_error("Invalid size " + std::to_string(size) + " for Curve25519 " + thing);
                    }
                }

                secure_vector<uint8_t> curve25519(const secure_vector<uint8_t> &secret, const uint8_t pubval[32]) {
                    secure_vector<uint8_t> out(32);
                    curve25519_donna(out.data(), secret.data(), pubval);
                    return out;
                }

            }    // namespace detail

            template<typename CurveType>
            struct curve25519_public_key {
                typedef CurveType curve_type;

                typedef typename curve_type::value_type value_type;
                typedef typename curve_type::number_type number_type;

                constexpr static const std::size_t key_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_type;

                constexpr static const std::size_t key_schedule_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;
            };

            template<typename CurveType>
            struct curve25519_private_key {
                typedef CurveType curve_type;

                typedef typename curve_type::value_type value_type;
                typedef typename curve_type::number_type number_type;

                constexpr static const std::size_t key_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_type;

                constexpr static const std::size_t key_schedule_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;
            };

            template<typename CurveType>
            struct curve25519 {
                typedef CurveType curve_type;

                typedef curve25519_public_key<CurveType> public_key_type;
                typedef curve25519_private_key<CurveType> private_key_type;
            };

            class curve25519_public_key : public virtual public_key_policy {
            public:
                /**
                 * Get the OID of the underlying public key scheme.
                 * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 3, 101, 110});
                }

                std::string algo_name() const override {
                    return "Curve25519";
                }

                std::size_t estimated_strength() const override {
                    return 128;
                }

                std::size_t key_length() const override {
                    return 255;
                }

                bool check_key(random_number_generator &rng, bool strong) const override {
                    return true;    // no tests possible?
                }

                algorithm_identifier get_algorithm_identifier() const override {
                    // get_algorithm_identifier::USE_NULL_PARAM puts 0x05 0x00 in parameters
                    // We want nothing
                    std::vector<uint8_t> empty;
                    return algorithm_identifier(oid(), empty);
                }

                std::vector<uint8_t> public_key_bits() const override {
                    return m_public;
                }

                std::vector<uint8_t> public_value() const {
                    return m_public;
                }

                /**
                 * Create a Curve25519 Public Key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded public key bits
                 */
                curve25519_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits) {
                    m_public = key_bits;

                    size_check(m_public.size(), "public key");
                }

                /**
                 * Create a Curve25519 Public Key.
                 * @param pub 32-byte raw public key
                 */
                explicit curve25519_public_key(const std::vector<uint8_t> &pub) : m_public(pub) {
                }

                /**
                 * Create a Curve25519 Public Key.
                 * @param pub 32-byte raw public key
                 */
                explicit curve25519_public_key(const secure_vector<uint8_t> &pub) : m_public(pub.begin(), pub.end()) {
                }

            protected:
                curve25519_public_key() = default;

                std::vector<uint8_t> m_public;
            };

            class curve25519_private_key final : public curve25519_public_key,
                                                 public virtual private_key_policy,
                                                 public virtual pk_key_agreement_key {
            public:
                /**
                 * Construct a private key from the specified parameters.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits PKCS #8 structure
                 */
                curve25519_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits) {
                    ber_decoder(key_bits).decode(m_private, OCTET_STRING).discard_remaining();

                    size_check(m_private.size(), "private key");
                    m_public.resize(32);
                    curve25519_basepoint(m_public.data(), m_private.data());
                }

                /**
                 * Generate a private key.
                 * @param rng the RNG to use
                 */
                template<typename UniformRandomGenerator>
                explicit curve25519_private_key(UniformRandomGenerator &rng) {
                    m_private = rng.random_vec(32);
                    m_public.resize(32);
                    curve25519_basepoint(m_public.data(), m_private.data());
                }

                /**
                 * Construct a private key from the specified parameters.
                 * @param secret_key the private key
                 */
                explicit curve25519_private_key(const secure_vector<uint8_t> &secret_key) {
                    if (secret_key.size() != 32) {
                        throw decoding_error("Invalid size for Curve25519 private key");
                    }

                    m_public.resize(32);
                    m_private = secret_key;
                    curve25519_basepoint(m_public.data(), m_private.data());
                }

                std::vector<uint8_t> public_value() const override {
                    return curve25519_public_key::public_value();
                }

                secure_vector<uint8_t> agree(const uint8_t w[], size_t w_len) const {
                    size_check(w_len, "public value");
                    return curve25519(m_private, w);
                }

                const secure_vector<uint8_t> &get_x() const {
                    return m_private;
                }

                secure_vector<uint8_t> private_key_bits() const override {
                    return der_encoder().encode(m_private, OCTET_STRING).get_contents();
                }

                bool check_key(random_number_generator &rng, bool strong) const override {
                    std::vector<uint8_t> public_point(32);
                    curve25519_basepoint(public_point.data(), m_private.data());
                    return public_point == m_public;
                }

                std::unique_ptr<pk_operations::key_agreement>
                    create_key_agreement_op(random_number_generator &rng, const std::string &params,
                                            const std::string &provider) const override;

            private:
                secure_vector<uint8_t> m_private;
            };

            class curve25519_ka_operation final : public pk_operations::key_agreement_with_kdf {
            public:
                curve25519_ka_operation(const curve25519_private_key &key, const std::string &kdf) :
                    pk_operations::key_agreement_with_kdf(kdf), m_key(key) {
                }

                secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override {
                    return m_key.agree(w, w_len);
                }

            private:
                const curve25519_private_key &m_key;
            };

            std::unique_ptr<pk_operations::key_agreement> curve25519_private_key::create_key_agreement_op(
                random_number_generator & /*random*/, const std::string &params, const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::key_agreement>(new curve25519_ka_operation(*this, params));
                }
                throw Provider_Not_Found(algo_name(), provider);
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil
#endif
