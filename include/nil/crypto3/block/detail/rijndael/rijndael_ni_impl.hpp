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

#ifndef CRYPTO3_RIJNDAEL_NI_IMPL_HPP
#define CRYPTO3_RIJNDAEL_NI_IMPL_HPP

#include <cstddef>

#include <wmmintrin.h>

#include <nil/crypto3/detail/make_uint_t.hpp>
#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/config.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @cond DETAIL_IMPL
             */
            namespace detail {
                BOOST_ATTRIBUTE_TARGET("ssse3,aes")
                __m128i aes_128_key_expansion(__m128i key, __m128i key_with_rcon) {
                    key_with_rcon = _mm_shuffle_epi32(key_with_rcon, _MM_SHUFFLE(3, 3, 3, 3));
                    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
                    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
                    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
                    return _mm_xor_si128(key, key_with_rcon);
                }

                BOOST_ATTRIBUTE_TARGET("ssse3,aes")
                void aes_192_key_expansion(__m128i *K1, __m128i *K2, __m128i key2_with_rcon, uint32_t out[],
                                           bool last) {
                    __m128i key1 = *K1;
                    __m128i key2 = *K2;

                    key2_with_rcon = _mm_shuffle_epi32(key2_with_rcon, _MM_SHUFFLE(1, 1, 1, 1));
                    key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
                    key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
                    key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
                    key1 = _mm_xor_si128(key1, key2_with_rcon);

                    *K1 = key1;
                    _mm_storeu_si128(reinterpret_cast<__m128i *>(out), key1);

                    if (last) {
                        return;
                    }

                    key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
                    key2 = _mm_xor_si128(key2, _mm_shuffle_epi32(key1, _MM_SHUFFLE(3, 3, 3, 3)));

                    *K2 = key2;
                    out[4] = _mm_cvtsi128_si32(key2);
                    out[5] = _mm_cvtsi128_si32(_mm_srli_si128(key2, 4));
                }

                /*
                 * The second half of the AES-256 key expansion (other half same as AES-128)
                 */
                BOOST_ATTRIBUTE_TARGET("ssse3,aes")
                __m128i aes_256_key_expansion(__m128i key, __m128i key2) {
                    __m128i key_with_rcon = _mm_aeskeygenassist_si128(key2, 0x00);
                    key_with_rcon = _mm_shuffle_epi32(key_with_rcon, _MM_SHUFFLE(2, 2, 2, 2));

                    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
                    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
                    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
                    return _mm_xor_si128(key, key_with_rcon);
                }

                template<std::size_t KeyBitsImpl, std::size_t BlockBitsImpl, typename PolicyType>
                class rijndael_ni_impl {
                    BOOST_STATIC_ASSERT(PolicyType::block_bits == 128 && BlockBitsImpl == 128);
                };

                template<typename PolicyType>
                class rijndael_ni_impl<128, 128, PolicyType> {
                    typedef PolicyType policy_type;
                    typedef typename policy_type::block_type block_type;
                    typedef typename policy_type::key_type key_type;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    BOOST_STATIC_ASSERT(PolicyType::key_bits == 128);

                public:
                    BOOST_ATTRIBUTE_TARGET("ssse3,aes")
                    static block_type encrypt_block(const block_type &plaintext,
                                                    const key_schedule_type &encryption_key) {
                        block_type out = {0};
                        const __m128i *in_mm = reinterpret_cast<const __m128i *>(plaintext.data());
                        __m128i *out_mm = reinterpret_cast<__m128i *>(out.data());

                        const __m128i *key_mm = reinterpret_cast<const __m128i *>(encryption_key.data());

                        const __m128i K0 = _mm_loadu_si128(key_mm);
                        const __m128i K1 = _mm_loadu_si128(key_mm + 1);
                        const __m128i K2 = _mm_loadu_si128(key_mm + 2);
                        const __m128i K3 = _mm_loadu_si128(key_mm + 3);
                        const __m128i K4 = _mm_loadu_si128(key_mm + 4);
                        const __m128i K5 = _mm_loadu_si128(key_mm + 5);
                        const __m128i K6 = _mm_loadu_si128(key_mm + 6);
                        const __m128i K7 = _mm_loadu_si128(key_mm + 7);
                        const __m128i K8 = _mm_loadu_si128(key_mm + 8);
                        const __m128i K9 = _mm_loadu_si128(key_mm + 9);
                        const __m128i K10 = _mm_loadu_si128(key_mm + 10);

                        __m128i B = _mm_loadu_si128(in_mm);

                        B = _mm_xor_si128(B, K0);

                        B = _mm_aesenc_si128(B, K1);
                        B = _mm_aesenc_si128(B, K2);
                        B = _mm_aesenc_si128(B, K3);
                        B = _mm_aesenc_si128(B, K4);
                        B = _mm_aesenc_si128(B, K5);
                        B = _mm_aesenc_si128(B, K6);
                        B = _mm_aesenc_si128(B, K7);
                        B = _mm_aesenc_si128(B, K8);
                        B = _mm_aesenc_si128(B, K9);
                        B = _mm_aesenclast_si128(B, K10);

                        _mm_storeu_si128(out_mm, B);

                        return out;
                    }

                    BOOST_ATTRIBUTE_TARGET("ssse3,aes")
                    static block_type decrypt_block(const block_type &plaintext,
                                                    const key_schedule_type &decryption_key) {
                        block_type out = {0};
                        const __m128i *in_mm = reinterpret_cast<const __m128i *>(plaintext.data());
                        __m128i *out_mm = reinterpret_cast<__m128i *>(out.data());

                        const __m128i *key_mm = reinterpret_cast<const __m128i *>(decryption_key.data());

                        const __m128i K0 = _mm_loadu_si128(key_mm);
                        const __m128i K1 = _mm_loadu_si128(key_mm + 1);
                        const __m128i K2 = _mm_loadu_si128(key_mm + 2);
                        const __m128i K3 = _mm_loadu_si128(key_mm + 3);
                        const __m128i K4 = _mm_loadu_si128(key_mm + 4);
                        const __m128i K5 = _mm_loadu_si128(key_mm + 5);
                        const __m128i K6 = _mm_loadu_si128(key_mm + 6);
                        const __m128i K7 = _mm_loadu_si128(key_mm + 7);
                        const __m128i K8 = _mm_loadu_si128(key_mm + 8);
                        const __m128i K9 = _mm_loadu_si128(key_mm + 9);
                        const __m128i K10 = _mm_loadu_si128(key_mm + 10);

                        __m128i B = _mm_loadu_si128(in_mm);

                        B = _mm_xor_si128(B, K0);

                        B = _mm_aesdec_si128(B, K1);
                        B = _mm_aesdec_si128(B, K2);
                        B = _mm_aesdec_si128(B, K3);
                        B = _mm_aesdec_si128(B, K4);
                        B = _mm_aesdec_si128(B, K5);
                        B = _mm_aesdec_si128(B, K6);
                        B = _mm_aesdec_si128(B, K7);
                        B = _mm_aesdec_si128(B, K8);
                        B = _mm_aesdec_si128(B, K9);
                        B = _mm_aesdeclast_si128(B, K10);

                        _mm_storeu_si128(out_mm, B);

                        return out;
                    }

                    BOOST_ATTRIBUTE_TARGET("ssse3,aes")
                    static void schedule_key(const key_type &input_key,
                                             key_schedule_type &encryption_key,
                                             key_schedule_type &decryption_key) {
#define AES_128_KEY_EXPANSION(K, RCON) detail::aes_128_key_expansion(K, _mm_aeskeygenassist_si128(K, RCON))

                        const __m128i K0 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(input_key.data()));
                        const __m128i K1 = AES_128_KEY_EXPANSION(K0, 0x01);
                        const __m128i K2 = AES_128_KEY_EXPANSION(K1, 0x02);
                        const __m128i K3 = AES_128_KEY_EXPANSION(K2, 0x04);
                        const __m128i K4 = AES_128_KEY_EXPANSION(K3, 0x08);
                        const __m128i K5 = AES_128_KEY_EXPANSION(K4, 0x10);
                        const __m128i K6 = AES_128_KEY_EXPANSION(K5, 0x20);
                        const __m128i K7 = AES_128_KEY_EXPANSION(K6, 0x40);
                        const __m128i K8 = AES_128_KEY_EXPANSION(K7, 0x80);
                        const __m128i K9 = AES_128_KEY_EXPANSION(K8, 0x1B);
                        const __m128i K10 = AES_128_KEY_EXPANSION(K9, 0x36);

#undef AES_128_KEY_EXPANSION

                        __m128i *EK_mm = reinterpret_cast<__m128i *>(encryption_key.data());
                        _mm_storeu_si128(EK_mm, K0);
                        _mm_storeu_si128(EK_mm + 1, K1);
                        _mm_storeu_si128(EK_mm + 2, K2);
                        _mm_storeu_si128(EK_mm + 3, K3);
                        _mm_storeu_si128(EK_mm + 4, K4);
                        _mm_storeu_si128(EK_mm + 5, K5);
                        _mm_storeu_si128(EK_mm + 6, K6);
                        _mm_storeu_si128(EK_mm + 7, K7);
                        _mm_storeu_si128(EK_mm + 8, K8);
                        _mm_storeu_si128(EK_mm + 9, K9);
                        _mm_storeu_si128(EK_mm + 10, K10);

                        // Now generate decryption keys

                        __m128i *DK_mm = reinterpret_cast<__m128i *>(decryption_key.data());
                        _mm_storeu_si128(DK_mm, K10);
                        _mm_storeu_si128(DK_mm + 1, _mm_aesimc_si128(K9));
                        _mm_storeu_si128(DK_mm + 2, _mm_aesimc_si128(K8));
                        _mm_storeu_si128(DK_mm + 3, _mm_aesimc_si128(K7));
                        _mm_storeu_si128(DK_mm + 4, _mm_aesimc_si128(K6));
                        _mm_storeu_si128(DK_mm + 5, _mm_aesimc_si128(K5));
                        _mm_storeu_si128(DK_mm + 6, _mm_aesimc_si128(K4));
                        _mm_storeu_si128(DK_mm + 7, _mm_aesimc_si128(K3));
                        _mm_storeu_si128(DK_mm + 8, _mm_aesimc_si128(K2));
                        _mm_storeu_si128(DK_mm + 9, _mm_aesimc_si128(K1));
                        _mm_storeu_si128(DK_mm + 10, K0);
                    }
                };

                template<typename PolicyType>
                class rijndael_ni_impl<192, 128, PolicyType> {
                protected:
                    typedef PolicyType policy_type;
                    typedef typename policy_type::block_type block_type;
                    typedef typename policy_type::key_type key_type;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    BOOST_STATIC_ASSERT(PolicyType::key_bits == 192);

                public:
                    BOOST_ATTRIBUTE_TARGET("ssse3,aes")
                    static block_type encrypt_block(const block_type &plaintext,
                                                    const key_schedule_type &encryption_key) {
                        block_type out = {0};
                        const __m128i *in_mm = reinterpret_cast<const __m128i *>(plaintext.data());
                        __m128i *out_mm = reinterpret_cast<__m128i *>(out.data());

                        const __m128i *key_mm = reinterpret_cast<const __m128i *>(encryption_key.data());

                        const __m128i K0 = _mm_loadu_si128(key_mm);
                        const __m128i K1 = _mm_loadu_si128(key_mm + 1);
                        const __m128i K2 = _mm_loadu_si128(key_mm + 2);
                        const __m128i K3 = _mm_loadu_si128(key_mm + 3);
                        const __m128i K4 = _mm_loadu_si128(key_mm + 4);
                        const __m128i K5 = _mm_loadu_si128(key_mm + 5);
                        const __m128i K6 = _mm_loadu_si128(key_mm + 6);
                        const __m128i K7 = _mm_loadu_si128(key_mm + 7);
                        const __m128i K8 = _mm_loadu_si128(key_mm + 8);
                        const __m128i K9 = _mm_loadu_si128(key_mm + 9);
                        const __m128i K10 = _mm_loadu_si128(key_mm + 10);
                        const __m128i K11 = _mm_loadu_si128(key_mm + 11);
                        const __m128i K12 = _mm_loadu_si128(key_mm + 12);

                        __m128i B = _mm_loadu_si128(in_mm);

                        B = _mm_xor_si128(B, K0);

                        B = _mm_aesenc_si128(B, K1);
                        B = _mm_aesenc_si128(B, K2);
                        B = _mm_aesenc_si128(B, K3);
                        B = _mm_aesenc_si128(B, K4);
                        B = _mm_aesenc_si128(B, K5);
                        B = _mm_aesenc_si128(B, K6);
                        B = _mm_aesenc_si128(B, K7);
                        B = _mm_aesenc_si128(B, K8);
                        B = _mm_aesenc_si128(B, K9);
                        B = _mm_aesenc_si128(B, K10);
                        B = _mm_aesenc_si128(B, K11);
                        B = _mm_aesenclast_si128(B, K12);

                        _mm_storeu_si128(out_mm, B);

                        return out;
                    }

                    BOOST_ATTRIBUTE_TARGET("ssse3,aes")
                    static block_type decrypt_block(const block_type &plaintext,
                                                    const key_schedule_type &decryption_key) {
                        block_type out = {0};
                        const __m128i *in_mm = reinterpret_cast<const __m128i *>(plaintext.data());
                        __m128i *out_mm = reinterpret_cast<__m128i *>(out.data());

                        const __m128i *key_mm = reinterpret_cast<const __m128i *>(decryption_key.data());

                        const __m128i K0 = _mm_loadu_si128(key_mm);
                        const __m128i K1 = _mm_loadu_si128(key_mm + 1);
                        const __m128i K2 = _mm_loadu_si128(key_mm + 2);
                        const __m128i K3 = _mm_loadu_si128(key_mm + 3);
                        const __m128i K4 = _mm_loadu_si128(key_mm + 4);
                        const __m128i K5 = _mm_loadu_si128(key_mm + 5);
                        const __m128i K6 = _mm_loadu_si128(key_mm + 6);
                        const __m128i K7 = _mm_loadu_si128(key_mm + 7);
                        const __m128i K8 = _mm_loadu_si128(key_mm + 8);
                        const __m128i K9 = _mm_loadu_si128(key_mm + 9);
                        const __m128i K10 = _mm_loadu_si128(key_mm + 10);
                        const __m128i K11 = _mm_loadu_si128(key_mm + 11);
                        const __m128i K12 = _mm_loadu_si128(key_mm + 12);

                        __m128i B = _mm_loadu_si128(in_mm);

                        B = _mm_xor_si128(B, K0);

                        B = _mm_aesdec_si128(B, K1);
                        B = _mm_aesdec_si128(B, K2);
                        B = _mm_aesdec_si128(B, K3);
                        B = _mm_aesdec_si128(B, K4);
                        B = _mm_aesdec_si128(B, K5);
                        B = _mm_aesdec_si128(B, K6);
                        B = _mm_aesdec_si128(B, K7);
                        B = _mm_aesdec_si128(B, K8);
                        B = _mm_aesdec_si128(B, K9);
                        B = _mm_aesdec_si128(B, K10);
                        B = _mm_aesdec_si128(B, K11);
                        B = _mm_aesdeclast_si128(B, K12);

                        _mm_storeu_si128(out_mm, B);

                        return out;
                    }

                    /**
                     * Load a variable number of little-endian words
                     * @param out the output array of words
                     * @param in the input array of bytes
                     * @param count how many words are in in
                     */
                    template<typename T>
                    static inline void load_le(T out[], const uint8_t in[], size_t count) {
                        if (count > 0) {
#if defined(BOOST_ENDIAN_LITTLE_BYTE_AVAILABLE)
                            std::memcpy(out, in, sizeof(T) * count);
#elif defined(BOOST_ENDIAN_BIG_BYTE_AVAILABLE)
                            std::memcpy(out, in, sizeof(T) * count);
                            const size_t blocks = count - (count % 4);
                            const size_t left = count - blocks;

                            for (size_t i = 0; i != blocks; i += 4)
                                bswap_4(out + i);

                            for (size_t i = 0; i != left; ++i)
                                out[blocks + i] = boost::endian::endian_reverse(out[blocks + i]);
#else
                            for (size_t i = 0; i != count; ++i) {
                                out[i] = load_le<T>(in, i);
                            }
#endif
                        }
                    }

                    BOOST_ATTRIBUTE_TARGET("ssse3,aes")
                    static void schedule_key(const key_type &input_key,
                                             key_schedule_type &encryption_key,
                                             key_schedule_type &decryption_key) {
                        __m128i K0 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(input_key.data()));
                        __m128i K1 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(input_key.data() + 8));
                        K1 = _mm_srli_si128(K1, 8);

                        load_le(encryption_key.data(), input_key.data(), 6);

#define AES_192_KEY_EXPANSION(RCON, EK_OFF) \
    detail::aes_192_key_expansion(&K0, &K1, _mm_aeskeygenassist_si128(K1, RCON), &encryption_key[EK_OFF], EK_OFF == 48)

                        AES_192_KEY_EXPANSION(0x01, 6);
                        AES_192_KEY_EXPANSION(0x02, 12);
                        AES_192_KEY_EXPANSION(0x04, 18);
                        AES_192_KEY_EXPANSION(0x08, 24);
                        AES_192_KEY_EXPANSION(0x10, 30);
                        AES_192_KEY_EXPANSION(0x20, 36);
                        AES_192_KEY_EXPANSION(0x40, 42);
                        AES_192_KEY_EXPANSION(0x80, 48);

#undef AES_192_KEY_EXPANSION

                        // Now generate decryption keys
                        const __m128i *EK_mm = reinterpret_cast<const __m128i *>(encryption_key.data());

                        __m128i *DK_mm = reinterpret_cast<__m128i *>(decryption_key.data());
                        _mm_storeu_si128(DK_mm, _mm_loadu_si128(EK_mm + 12));
                        _mm_storeu_si128(DK_mm + 1, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 11)));
                        _mm_storeu_si128(DK_mm + 2, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 10)));
                        _mm_storeu_si128(DK_mm + 3, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 9)));
                        _mm_storeu_si128(DK_mm + 4, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 8)));
                        _mm_storeu_si128(DK_mm + 5, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 7)));
                        _mm_storeu_si128(DK_mm + 6, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 6)));
                        _mm_storeu_si128(DK_mm + 7, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 5)));
                        _mm_storeu_si128(DK_mm + 8, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 4)));
                        _mm_storeu_si128(DK_mm + 9, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 3)));
                        _mm_storeu_si128(DK_mm + 10, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 2)));
                        _mm_storeu_si128(DK_mm + 11, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 1)));
                        _mm_storeu_si128(DK_mm + 12, _mm_loadu_si128(EK_mm + 0));
                    }
                };

                template<typename PolicyType>
                class rijndael_ni_impl<256, 128, PolicyType> {
                protected:
                    typedef PolicyType policy_type;
                    typedef typename policy_type::block_type block_type;
                    typedef typename policy_type::key_type key_type;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    BOOST_STATIC_ASSERT(PolicyType::key_bits == 256);

                public:
                    BOOST_ATTRIBUTE_TARGET("ssse3,aes")
                    static block_type encrypt_block(const block_type &plaintext,
                                                    const key_schedule_type &encryption_key) {
                        block_type out = {0};
                        const __m128i *in_mm = reinterpret_cast<const __m128i *>(plaintext.data());
                        __m128i *out_mm = reinterpret_cast<__m128i *>(out.data());

                        const __m128i *key_mm = reinterpret_cast<const __m128i *>(encryption_key.data());

                        const __m128i K0 = _mm_loadu_si128(key_mm);
                        const __m128i K1 = _mm_loadu_si128(key_mm + 1);
                        const __m128i K2 = _mm_loadu_si128(key_mm + 2);
                        const __m128i K3 = _mm_loadu_si128(key_mm + 3);
                        const __m128i K4 = _mm_loadu_si128(key_mm + 4);
                        const __m128i K5 = _mm_loadu_si128(key_mm + 5);
                        const __m128i K6 = _mm_loadu_si128(key_mm + 6);
                        const __m128i K7 = _mm_loadu_si128(key_mm + 7);
                        const __m128i K8 = _mm_loadu_si128(key_mm + 8);
                        const __m128i K9 = _mm_loadu_si128(key_mm + 9);
                        const __m128i K10 = _mm_loadu_si128(key_mm + 10);
                        const __m128i K11 = _mm_loadu_si128(key_mm + 11);
                        const __m128i K12 = _mm_loadu_si128(key_mm + 12);
                        const __m128i K13 = _mm_loadu_si128(key_mm + 13);
                        const __m128i K14 = _mm_loadu_si128(key_mm + 14);

                        __m128i B = _mm_loadu_si128(in_mm);

                        B = _mm_xor_si128(B, K0);

                        B = _mm_aesenc_si128(B, K1);
                        B = _mm_aesenc_si128(B, K2);
                        B = _mm_aesenc_si128(B, K3);
                        B = _mm_aesenc_si128(B, K4);
                        B = _mm_aesenc_si128(B, K5);
                        B = _mm_aesenc_si128(B, K6);
                        B = _mm_aesenc_si128(B, K7);
                        B = _mm_aesenc_si128(B, K8);
                        B = _mm_aesenc_si128(B, K9);
                        B = _mm_aesenc_si128(B, K10);
                        B = _mm_aesenc_si128(B, K11);
                        B = _mm_aesenc_si128(B, K12);
                        B = _mm_aesenc_si128(B, K13);
                        B = _mm_aesenclast_si128(B, K14);

                        _mm_storeu_si128(out_mm, B);

                        return out;
                    }

                    BOOST_ATTRIBUTE_TARGET("ssse3,aes")
                    static block_type decrypt_block(const block_type &plaintext,
                                                    const key_schedule_type &decryption_key) {
                        block_type out = {0};
                        const __m128i *in_mm = reinterpret_cast<const __m128i *>(plaintext.data());
                        __m128i *out_mm = reinterpret_cast<__m128i *>(out.data());

                        const __m128i *key_mm = reinterpret_cast<const __m128i *>(decryption_key.data());

                        const __m128i K0 = _mm_loadu_si128(key_mm);
                        const __m128i K1 = _mm_loadu_si128(key_mm + 1);
                        const __m128i K2 = _mm_loadu_si128(key_mm + 2);
                        const __m128i K3 = _mm_loadu_si128(key_mm + 3);
                        const __m128i K4 = _mm_loadu_si128(key_mm + 4);
                        const __m128i K5 = _mm_loadu_si128(key_mm + 5);
                        const __m128i K6 = _mm_loadu_si128(key_mm + 6);
                        const __m128i K7 = _mm_loadu_si128(key_mm + 7);
                        const __m128i K8 = _mm_loadu_si128(key_mm + 8);
                        const __m128i K9 = _mm_loadu_si128(key_mm + 9);
                        const __m128i K10 = _mm_loadu_si128(key_mm + 10);
                        const __m128i K11 = _mm_loadu_si128(key_mm + 11);
                        const __m128i K12 = _mm_loadu_si128(key_mm + 12);
                        const __m128i K13 = _mm_loadu_si128(key_mm + 13);
                        const __m128i K14 = _mm_loadu_si128(key_mm + 14);

                        __m128i B = _mm_loadu_si128(in_mm);

                        B = _mm_xor_si128(B, K0);

                        B = _mm_aesdec_si128(B, K1);
                        B = _mm_aesdec_si128(B, K2);
                        B = _mm_aesdec_si128(B, K3);
                        B = _mm_aesdec_si128(B, K4);
                        B = _mm_aesdec_si128(B, K5);
                        B = _mm_aesdec_si128(B, K6);
                        B = _mm_aesdec_si128(B, K7);
                        B = _mm_aesdec_si128(B, K8);
                        B = _mm_aesdec_si128(B, K9);
                        B = _mm_aesdec_si128(B, K10);
                        B = _mm_aesdec_si128(B, K11);
                        B = _mm_aesdec_si128(B, K12);
                        B = _mm_aesdec_si128(B, K13);
                        B = _mm_aesdeclast_si128(B, K14);

                        _mm_storeu_si128(out_mm, B);

                        return out;
                    }

                    BOOST_ATTRIBUTE_TARGET("ssse3,aes")
                    static void schedule_key(const key_type &input_key,
                                             key_schedule_type &encryption_key,
                                             key_schedule_type &decryption_key) {
                        const __m128i K0 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(input_key.data()));
                        const __m128i K1 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(input_key.data() + 16));

                        const __m128i K2 = detail::aes_128_key_expansion(K0, _mm_aeskeygenassist_si128(K1, 0x01));
                        const __m128i K3 = detail::aes_256_key_expansion(K1, K2);

                        const __m128i K4 = detail::aes_128_key_expansion(K2, _mm_aeskeygenassist_si128(K3, 0x02));
                        const __m128i K5 = detail::aes_256_key_expansion(K3, K4);

                        const __m128i K6 = detail::aes_128_key_expansion(K4, _mm_aeskeygenassist_si128(K5, 0x04));
                        const __m128i K7 = detail::aes_256_key_expansion(K5, K6);

                        const __m128i K8 = detail::aes_128_key_expansion(K6, _mm_aeskeygenassist_si128(K7, 0x08));
                        const __m128i K9 = detail::aes_256_key_expansion(K7, K8);

                        const __m128i K10 = detail::aes_128_key_expansion(K8, _mm_aeskeygenassist_si128(K9, 0x10));
                        const __m128i K11 = detail::aes_256_key_expansion(K9, K10);

                        const __m128i K12 = detail::aes_128_key_expansion(K10, _mm_aeskeygenassist_si128(K11, 0x20));
                        const __m128i K13 = detail::aes_256_key_expansion(K11, K12);

                        const __m128i K14 = detail::aes_128_key_expansion(K12, _mm_aeskeygenassist_si128(K13, 0x40));

                        __m128i *EK_mm = reinterpret_cast<__m128i *>(encryption_key.data());
                        _mm_storeu_si128(EK_mm, K0);
                        _mm_storeu_si128(EK_mm + 1, K1);
                        _mm_storeu_si128(EK_mm + 2, K2);
                        _mm_storeu_si128(EK_mm + 3, K3);
                        _mm_storeu_si128(EK_mm + 4, K4);
                        _mm_storeu_si128(EK_mm + 5, K5);
                        _mm_storeu_si128(EK_mm + 6, K6);
                        _mm_storeu_si128(EK_mm + 7, K7);
                        _mm_storeu_si128(EK_mm + 8, K8);
                        _mm_storeu_si128(EK_mm + 9, K9);
                        _mm_storeu_si128(EK_mm + 10, K10);
                        _mm_storeu_si128(EK_mm + 11, K11);
                        _mm_storeu_si128(EK_mm + 12, K12);
                        _mm_storeu_si128(EK_mm + 13, K13);
                        _mm_storeu_si128(EK_mm + 14, K14);

                        // Now generate decryption keys
                        __m128i *DK_mm = reinterpret_cast<__m128i *>(decryption_key.data());
                        _mm_storeu_si128(DK_mm, K14);
                        _mm_storeu_si128(DK_mm + 1, _mm_aesimc_si128(K13));
                        _mm_storeu_si128(DK_mm + 2, _mm_aesimc_si128(K12));
                        _mm_storeu_si128(DK_mm + 3, _mm_aesimc_si128(K11));
                        _mm_storeu_si128(DK_mm + 4, _mm_aesimc_si128(K10));
                        _mm_storeu_si128(DK_mm + 5, _mm_aesimc_si128(K9));
                        _mm_storeu_si128(DK_mm + 6, _mm_aesimc_si128(K8));
                        _mm_storeu_si128(DK_mm + 7, _mm_aesimc_si128(K7));
                        _mm_storeu_si128(DK_mm + 8, _mm_aesimc_si128(K6));
                        _mm_storeu_si128(DK_mm + 9, _mm_aesimc_si128(K5));
                        _mm_storeu_si128(DK_mm + 10, _mm_aesimc_si128(K4));
                        _mm_storeu_si128(DK_mm + 11, _mm_aesimc_si128(K3));
                        _mm_storeu_si128(DK_mm + 12, _mm_aesimc_si128(K2));
                        _mm_storeu_si128(DK_mm + 13, _mm_aesimc_si128(K1));
                        _mm_storeu_si128(DK_mm + 14, K0);
                    }
                };
            }    // namespace detail
            /*!
             * @endcond
             */
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RIJNDAEL_NI_IMPL_HPP
