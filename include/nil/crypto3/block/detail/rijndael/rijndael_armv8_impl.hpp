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

#ifndef CRYPTO3_RIJNDAEL_ARMV8_IMPL_HPP
#define CRYPTO3_RIJNDAEL_ARMV8_IMPL_HPP

#include <nil/crypto3/block/detail/rijndael_impl.hpp>

#include <cstddef>
#include <arm_neon.h>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
#define AES_ENC_4_ROUNDS(K)                \
    do {                                   \
        B0 = vaesmcq_u8(vaeseq_u8(B0, K)); \
        B1 = vaesmcq_u8(vaeseq_u8(B1, K)); \
        B2 = vaesmcq_u8(vaeseq_u8(B2, K)); \
        B3 = vaesmcq_u8(vaeseq_u8(B3, K)); \
    } while (0)

#define AES_ENC_4_LAST_ROUNDS(K, K2)         \
    do {                                     \
        B0 = veorq_u8(vaeseq_u8(B0, K), K2); \
        B1 = veorq_u8(vaeseq_u8(B1, K), K2); \
        B2 = veorq_u8(vaeseq_u8(B2, K), K2); \
        B3 = veorq_u8(vaeseq_u8(B3, K), K2); \
    } while (0)

#define AES_DEC_4_ROUNDS(K)                 \
    do {                                    \
        B0 = vaesimcq_u8(vaesdq_u8(B0, K)); \
        B1 = vaesimcq_u8(vaesdq_u8(B1, K)); \
        B2 = vaesimcq_u8(vaesdq_u8(B2, K)); \
        B3 = vaesimcq_u8(vaesdq_u8(B3, K)); \
    } while (0)

#define AES_DEC_4_LAST_ROUNDS(K, K2)         \
    do {                                     \
        B0 = veorq_u8(vaesdq_u8(B0, K), K2); \
        B1 = veorq_u8(vaesdq_u8(B1, K), K2); \
        B2 = veorq_u8(vaesdq_u8(B2, K), K2); \
        B3 = veorq_u8(vaesdq_u8(B3, K), K2); \
    } while (0)

                template<std::size_t KeyBitsImpl, std::size_t BlockBitsImpl, typename PolicyType>
                class basic_armv8_rijndael_impl {
                    static_assert(BlockBitsImpl != 128, "Wrong block size!");
                };

                template<std::size_t KeyBitsImpl, typename PolicyType>
                class basic_armv8_rijndael_impl<KeyBitsImpl, 128, PolicyType>;

                template<std::size_t KeyBitsImpl, std::size_t BlockBitsImpl, typename PolicyType>
                class rijndael_armv8_impl : public basic_armv8_rijndael_impl<KeyBitsImpl, BlockBitsImpl, PolicyType> {
                    static_assert(BlockBitsImpl != 128, "Wrong block size!");
                };

                template<std::size_t KeyBitsImpl, typename PolicyType>
                class rijndael_armv8_impl<KeyBitsImpl, 128, PolicyType>;

                template<std::size_t KeyBitsImpl, typename PolicyType>
                class basic_armv8_rijndael_impl<KeyBitsImpl, 128, PolicyType> {
                protected:
                    typedef PolicyType policy_type;
                    typedef typename policy_type::block_type block_type;
                    typedef typename policy_type::key_type key_type;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                public:
                    static inline void schedule_key(const key_type &key,
                                                    key_schedule_type encryption_key,
                                                    key_schedule_type &decryption_key) {
                        rijndael_impl<KeyBitsImpl, 128>::schedule_key(key, encryption_key, decryption_key);

                        for (typename basic_type::key_schedule_type::value_type &c : encryption_key) {
                            c = reverse_bytes(c);
                        }
                        for (typename basic_type::key_schedule_type::value_type &c : decryption_key) {
                            c = reverse_bytes(c);
                        }
                    }
                };
            }    // namespace detail

            template<typename PolicyType>
            class rijndael_armv8_impl<128, 128, PolicyType> : public basic_armv8_rijndael_impl<128, 128, PolicyType> {
            public:
                static block_type encrypt_block(const block_type &plaintext, const key_schedule_type &encryption_key) {
                    typename basic_type::block_type out = {0};

                    const uint8_t *skey = reinterpret_cast<const uint8_t *>(encryption_key.data());
                    const uint8_t *mkey = reinterpret_cast<const uint8_t *>(m_ME.data());

                    const uint8x16_t K0 = vld1q_u8(skey + 0);
                    const uint8x16_t K1 = vld1q_u8(skey + 16);
                    const uint8x16_t K2 = vld1q_u8(skey + 32);
                    const uint8x16_t K3 = vld1q_u8(skey + 48);
                    const uint8x16_t K4 = vld1q_u8(skey + 64);
                    const uint8x16_t K5 = vld1q_u8(skey + 80);
                    const uint8x16_t K6 = vld1q_u8(skey + 96);
                    const uint8x16_t K7 = vld1q_u8(skey + 112);
                    const uint8x16_t K8 = vld1q_u8(skey + 128);
                    const uint8x16_t K9 = vld1q_u8(skey + 144);
                    const uint8x16_t K10 = vld1q_u8(mkey);

                    uint8x16_t B = vld1q_u8(plaintext.data());
                    B = vaesmcq_u8(vaeseq_u8(B, K0));
                    B = vaesmcq_u8(vaeseq_u8(B, K1));
                    B = vaesmcq_u8(vaeseq_u8(B, K2));
                    B = vaesmcq_u8(vaeseq_u8(B, K3));
                    B = vaesmcq_u8(vaeseq_u8(B, K4));
                    B = vaesmcq_u8(vaeseq_u8(B, K5));
                    B = vaesmcq_u8(vaeseq_u8(B, K6));
                    B = vaesmcq_u8(vaeseq_u8(B, K7));
                    B = vaesmcq_u8(vaeseq_u8(B, K8));
                    B = veorq_u8(vaeseq_u8(B, K9), K10);
                    vst1q_u8(out.data(), B);

                    return out;
                }

                static block_type decrypt_block(const block_type &plaintext, const key_schedule_type &decryption_key) {
                    block_type out = {0};

                    const uint8_t *skey = reinterpret_cast<const uint8_t *>(decryption_key.data());
                    const uint8_t *mkey = reinterpret_cast<const uint8_t *>(m_MD.data());

                    const uint8x16_t K0 = vld1q_u8(skey + 0);
                    const uint8x16_t K1 = vld1q_u8(skey + 16);
                    const uint8x16_t K2 = vld1q_u8(skey + 32);
                    const uint8x16_t K3 = vld1q_u8(skey + 48);
                    const uint8x16_t K4 = vld1q_u8(skey + 64);
                    const uint8x16_t K5 = vld1q_u8(skey + 80);
                    const uint8x16_t K6 = vld1q_u8(skey + 96);
                    const uint8x16_t K7 = vld1q_u8(skey + 112);
                    const uint8x16_t K8 = vld1q_u8(skey + 128);
                    const uint8x16_t K9 = vld1q_u8(skey + 144);
                    const uint8x16_t K10 = vld1q_u8(mkey);

                    uint8x16_t B = vld1q_u8(plaintext.data());
                    B = vaesimcq_u8(vaesdq_u8(B, K0));
                    B = vaesimcq_u8(vaesdq_u8(B, K1));
                    B = vaesimcq_u8(vaesdq_u8(B, K2));
                    B = vaesimcq_u8(vaesdq_u8(B, K3));
                    B = vaesimcq_u8(vaesdq_u8(B, K4));
                    B = vaesimcq_u8(vaesdq_u8(B, K5));
                    B = vaesimcq_u8(vaesdq_u8(B, K6));
                    B = vaesimcq_u8(vaesdq_u8(B, K7));
                    B = vaesimcq_u8(vaesdq_u8(B, K8));
                    B = veorq_u8(vaesdq_u8(B, K9), K10);

                    vst1q_u8(out.data(), B);

                    return out;
                }
            };

            template<typename PolicyType>
            class rijndael_armv8_impl<192, 128, PolicyType> : public basic_armv8_rijndael_impl<192, 128, PolicyType> {
            public:
                static block_type encrypt_block(const block_type &plaintext, const key_schedule_type &encryption_key) {
                    block_type out = {0};

                    const uint8_t *skey = reinterpret_cast<const uint8_t *>(encryption_key.data());
                    const uint8_t *mkey = reinterpret_cast<const uint8_t *>(m_ME.data());

                    const uint8x16_t K0 = vld1q_u8(skey + 0);
                    const uint8x16_t K1 = vld1q_u8(skey + 16);
                    const uint8x16_t K2 = vld1q_u8(skey + 32);
                    const uint8x16_t K3 = vld1q_u8(skey + 48);
                    const uint8x16_t K4 = vld1q_u8(skey + 64);
                    const uint8x16_t K5 = vld1q_u8(skey + 80);
                    const uint8x16_t K6 = vld1q_u8(skey + 96);
                    const uint8x16_t K7 = vld1q_u8(skey + 112);
                    const uint8x16_t K8 = vld1q_u8(skey + 128);
                    const uint8x16_t K9 = vld1q_u8(skey + 144);
                    const uint8x16_t K10 = vld1q_u8(skey + 160);
                    const uint8x16_t K11 = vld1q_u8(skey + 176);
                    const uint8x16_t K12 = vld1q_u8(mkey);

                    uint8x16_t B = vld1q_u8(plaintext.data());
                    B = vaesmcq_u8(vaeseq_u8(B, K0));
                    B = vaesmcq_u8(vaeseq_u8(B, K1));
                    B = vaesmcq_u8(vaeseq_u8(B, K2));
                    B = vaesmcq_u8(vaeseq_u8(B, K3));
                    B = vaesmcq_u8(vaeseq_u8(B, K4));
                    B = vaesmcq_u8(vaeseq_u8(B, K5));
                    B = vaesmcq_u8(vaeseq_u8(B, K6));
                    B = vaesmcq_u8(vaeseq_u8(B, K7));
                    B = vaesmcq_u8(vaeseq_u8(B, K8));
                    B = vaesmcq_u8(vaeseq_u8(B, K9));
                    B = vaesmcq_u8(vaeseq_u8(B, K10));
                    B = veorq_u8(vaeseq_u8(B, K11), K12);
                    vst1q_u8(out.data(), B);

                    return out;
                }

                static block_type decrypt_block(const block_type &plaintext, const key_schedule_type &decryption_key) {
                    block_type out = {0};
                    const uint8_t *skey = reinterpret_cast<const uint8_t *>(decryption_key.data());
                    const uint8_t *mkey = reinterpret_cast<const uint8_t *>(m_MD.data());

                    const uint8x16_t K0 = vld1q_u8(skey + 0);
                    const uint8x16_t K1 = vld1q_u8(skey + 16);
                    const uint8x16_t K2 = vld1q_u8(skey + 32);
                    const uint8x16_t K3 = vld1q_u8(skey + 48);
                    const uint8x16_t K4 = vld1q_u8(skey + 64);
                    const uint8x16_t K5 = vld1q_u8(skey + 80);
                    const uint8x16_t K6 = vld1q_u8(skey + 96);
                    const uint8x16_t K7 = vld1q_u8(skey + 112);
                    const uint8x16_t K8 = vld1q_u8(skey + 128);
                    const uint8x16_t K9 = vld1q_u8(skey + 144);
                    const uint8x16_t K10 = vld1q_u8(skey + 160);
                    const uint8x16_t K11 = vld1q_u8(skey + 176);
                    const uint8x16_t K12 = vld1q_u8(mkey);

                    uint8x16_t B = vld1q_u8(plaintext.data());
                    B = vaesimcq_u8(vaesdq_u8(B, K0));
                    B = vaesimcq_u8(vaesdq_u8(B, K1));
                    B = vaesimcq_u8(vaesdq_u8(B, K2));
                    B = vaesimcq_u8(vaesdq_u8(B, K3));
                    B = vaesimcq_u8(vaesdq_u8(B, K4));
                    B = vaesimcq_u8(vaesdq_u8(B, K5));
                    B = vaesimcq_u8(vaesdq_u8(B, K6));
                    B = vaesimcq_u8(vaesdq_u8(B, K7));
                    B = vaesimcq_u8(vaesdq_u8(B, K8));
                    B = vaesimcq_u8(vaesdq_u8(B, K9));
                    B = vaesimcq_u8(vaesdq_u8(B, K10));
                    B = veorq_u8(vaesdq_u8(B, K11), K12);
                    vst1q_u8(out.data(), B);

                    return out;
                }
            };

            template<typename PolicyType>
            class rijndael_armv8_impl<256, 128, PolicyType> : public basic_armv8_rijndael_impl<256, 128, PolicyType> {
            public:
                static block_type encrypt_block(const block_type &plaintext, const key_schedule_type &encryption_key) {
                    block_type out = {0};
                    const uint8_t *skey = reinterpret_cast<const uint8_t *>(encryption_key.data());
                    const uint8_t *mkey = reinterpret_cast<const uint8_t *>(m_ME.data());

                    const uint8x16_t K0 = vld1q_u8(skey + 0);
                    const uint8x16_t K1 = vld1q_u8(skey + 16);
                    const uint8x16_t K2 = vld1q_u8(skey + 32);
                    const uint8x16_t K3 = vld1q_u8(skey + 48);
                    const uint8x16_t K4 = vld1q_u8(skey + 64);
                    const uint8x16_t K5 = vld1q_u8(skey + 80);
                    const uint8x16_t K6 = vld1q_u8(skey + 96);
                    const uint8x16_t K7 = vld1q_u8(skey + 112);
                    const uint8x16_t K8 = vld1q_u8(skey + 128);
                    const uint8x16_t K9 = vld1q_u8(skey + 144);
                    const uint8x16_t K10 = vld1q_u8(skey + 160);
                    const uint8x16_t K11 = vld1q_u8(skey + 176);
                    const uint8x16_t K12 = vld1q_u8(skey + 192);
                    const uint8x16_t K13 = vld1q_u8(skey + 208);
                    const uint8x16_t K14 = vld1q_u8(mkey);

                    uint8x16_t B = vld1q_u8(plaintext.data());
                    B = vaesmcq_u8(vaeseq_u8(B, K0));
                    B = vaesmcq_u8(vaeseq_u8(B, K1));
                    B = vaesmcq_u8(vaeseq_u8(B, K2));
                    B = vaesmcq_u8(vaeseq_u8(B, K3));
                    B = vaesmcq_u8(vaeseq_u8(B, K4));
                    B = vaesmcq_u8(vaeseq_u8(B, K5));
                    B = vaesmcq_u8(vaeseq_u8(B, K6));
                    B = vaesmcq_u8(vaeseq_u8(B, K7));
                    B = vaesmcq_u8(vaeseq_u8(B, K8));
                    B = vaesmcq_u8(vaeseq_u8(B, K9));
                    B = vaesmcq_u8(vaeseq_u8(B, K10));
                    B = vaesmcq_u8(vaeseq_u8(B, K11));
                    B = vaesmcq_u8(vaeseq_u8(B, K12));
                    B = veorq_u8(vaeseq_u8(B, K13), K14);
                    vst1q_u8(out.data(), B);

                    return out;
                }

                static block_type decrypt_block(const block_type &plaintext, const key_schedule_type &decryption_key) {
                    const uint8_t *skey = reinterpret_cast<const uint8_t *>(decryption_key.data());
                    const uint8_t *mkey = reinterpret_cast<const uint8_t *>(m_MD.data());

                    const uint8x16_t K0 = vld1q_u8(skey + 0);
                    const uint8x16_t K1 = vld1q_u8(skey + 16);
                    const uint8x16_t K2 = vld1q_u8(skey + 32);
                    const uint8x16_t K3 = vld1q_u8(skey + 48);
                    const uint8x16_t K4 = vld1q_u8(skey + 64);
                    const uint8x16_t K5 = vld1q_u8(skey + 80);
                    const uint8x16_t K6 = vld1q_u8(skey + 96);
                    const uint8x16_t K7 = vld1q_u8(skey + 112);
                    const uint8x16_t K8 = vld1q_u8(skey + 128);
                    const uint8x16_t K9 = vld1q_u8(skey + 144);
                    const uint8x16_t K10 = vld1q_u8(skey + 160);
                    const uint8x16_t K11 = vld1q_u8(skey + 176);
                    const uint8x16_t K12 = vld1q_u8(skey + 192);
                    const uint8x16_t K13 = vld1q_u8(skey + 208);
                    const uint8x16_t K14 = vld1q_u8(mkey);

                    uint8x16_t B = vld1q_u8(plaintext.data());
                    B = vaesimcq_u8(vaesdq_u8(B, K0));
                    B = vaesimcq_u8(vaesdq_u8(B, K1));
                    B = vaesimcq_u8(vaesdq_u8(B, K2));
                    B = vaesimcq_u8(vaesdq_u8(B, K3));
                    B = vaesimcq_u8(vaesdq_u8(B, K4));
                    B = vaesimcq_u8(vaesdq_u8(B, K5));
                    B = vaesimcq_u8(vaesdq_u8(B, K6));
                    B = vaesimcq_u8(vaesdq_u8(B, K7));
                    B = vaesimcq_u8(vaesdq_u8(B, K8));
                    B = vaesimcq_u8(vaesdq_u8(B, K9));
                    B = vaesimcq_u8(vaesdq_u8(B, K10));
                    B = vaesimcq_u8(vaesdq_u8(B, K11));
                    B = vaesimcq_u8(vaesdq_u8(B, K12));
                    B = veorq_u8(vaesdq_u8(B, K13), K14);
                    vst1q_u8(out.data(), B);

                    return out;
                }
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RIJNDAEL_ARMV8_IMPL_HPP
