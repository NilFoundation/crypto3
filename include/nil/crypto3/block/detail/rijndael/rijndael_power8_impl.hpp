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

#ifndef CRYPTO3_RIJNDAEL_POWER8_IMPL_HPP
#define CRYPTO3_RIJNDAEL_POWER8_IMPL_HPP

#include <nil/crypto3/block/detail/rijndael_impl.hpp>

#include <cstddef>
#include <altivec.h>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {

#undef vector
#undef bool

                __vector unsigned long long LoadKey(const uint32_t *src) {
                    __vector unsigned int vec = vec_vsx_ld(0, src);

                    if (cpuid::is_little_endian()) {
                        const __vector unsigned char mask = {12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3};
                        const __vector unsigned char zero = {0};
                        return (__vector unsigned long long)vec_perm((__vector unsigned char)vec, zero, mask);
                    } else {
                        return (__vector unsigned long long)vec;
                    }
                }

                __vector unsigned char Reverse8x16(const __vector unsigned char src) {
                    if (cpuid::is_little_endian()) {
                        const __vector unsigned char mask = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
                        const __vector unsigned char zero = {0};
                        return vec_perm(src, zero, mask);
                    } else {
                        return src;
                    }
                }

                __vector unsigned long long LoadBlock(const uint8_t *src) {
                    return (__vector unsigned long long)Reverse8x16(vec_vsx_ld(0, src));
                }

                void StoreBlock(const __vector unsigned long long src, uint8_t *dest) {
                    vec_vsx_st(Reverse8x16((__vector unsigned char)src), 0, dest);
                }

                template<std::size_t KeyBitsImpl, std::size_t BlockBitsImpl, typename PolicyType>
                class basic_rijndael_power8_impl {
                    BOOST_STATIC_ASSERT(BlockBitsImpl == 128);

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

                template<std::size_t KeyBitsImpl, std::size_t BlockBitsImpl, typename PolicyType>
                class rijndael_power8_impl : public basic_rijndael_power8_impl<KeyBitsImpl, BlockBitsImpl, PolicyType> {
                    BOOST_STATIC_ASSERT(BlockBitsImpl == 128);
                };

                template<typename PolicyType>
                class rijndael_power8_impl<128, 128, PolicyType>
                    : public basic_rijndael_power8_impl<128, 128, PolicyType> {
                protected:
                    typedef PolicyType policy_type;
                    typedef typename policy_type::block_type block_type;
                    typedef typename policy_type::key_type key_type;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    BOOST_STATIC_ASSERT(PolicyType::key_bits == 128);
                    BOOST_STATIC_ASSERT(PolicyType::block_bits == 128);

                public:
                    static block_type encrypt_block(const block_type &plaintext,
                                                    const key_schedule_type &encryption_key) {
                        block_type out = {0};

                        const __vector unsigned long long K0 = LoadKey(&encryption_key[0]);
                        const __vector unsigned long long K1 = LoadKey(&encryption_key[4]);
                        const __vector unsigned long long K2 = LoadKey(&encryption_key[8]);
                        const __vector unsigned long long K3 = LoadKey(&encryption_key[12]);
                        const __vector unsigned long long K4 = LoadKey(&encryption_key[16]);
                        const __vector unsigned long long K5 = LoadKey(&encryption_key[20]);
                        const __vector unsigned long long K6 = LoadKey(&encryption_key[24]);
                        const __vector unsigned long long K7 = LoadKey(&encryption_key[28]);
                        const __vector unsigned long long K8 = LoadKey(&encryption_key[32]);
                        const __vector unsigned long long K9 = LoadKey(&encryption_key[36]);
                        const __vector unsigned long long K10 = LoadBlock(m_ME.data());

                        __vector unsigned long long B = LoadBlock(plaintext.data());

                        B = vec_xor(B, K0);
                        B = __builtin_crypto_vcipher(B, K1);
                        B = __builtin_crypto_vcipher(B, K2);
                        B = __builtin_crypto_vcipher(B, K3);
                        B = __builtin_crypto_vcipher(B, K4);
                        B = __builtin_crypto_vcipher(B, K5);
                        B = __builtin_crypto_vcipher(B, K6);
                        B = __builtin_crypto_vcipher(B, K7);
                        B = __builtin_crypto_vcipher(B, K8);
                        B = __builtin_crypto_vcipher(B, K9);
                        B = __builtin_crypto_vcipherlast(B, K10);

                        StoreBlock(B, out.data());

                        return out;
                    }

                    static block_type decrypt_block(const block_type &plaintext,
                                                    const key_schedule_type &encryption_key) {
                        block_type out = {0};

                        const __vector unsigned long long K0 = LoadBlock(&m_ME.data());
                        const __vector unsigned long long K1 = LoadKey(&encryption_key[36]);
                        const __vector unsigned long long K2 = LoadKey(&encryption_key[32]);
                        const __vector unsigned long long K3 = LoadKey(&encryption_key[28]);
                        const __vector unsigned long long K4 = LoadKey(&encryption_key[24]);
                        const __vector unsigned long long K5 = LoadKey(&encryption_key[20]);
                        const __vector unsigned long long K6 = LoadKey(&encryption_key[16]);
                        const __vector unsigned long long K7 = LoadKey(&encryption_key[12]);
                        const __vector unsigned long long K8 = LoadKey(&encryption_key[8]);
                        const __vector unsigned long long K9 = LoadKey(&encryption_key[4]);
                        const __vector unsigned long long K10 = LoadKey(&encryption_key[0]);

                        __vector unsigned long long B = LoadBlock(plaintext.data());

                        B = vec_xor(B, K0);
                        B = __builtin_crypto_vncipher(B, K1);
                        B = __builtin_crypto_vncipher(B, K2);
                        B = __builtin_crypto_vncipher(B, K3);
                        B = __builtin_crypto_vncipher(B, K4);
                        B = __builtin_crypto_vncipher(B, K5);
                        B = __builtin_crypto_vncipher(B, K6);
                        B = __builtin_crypto_vncipher(B, K7);
                        B = __builtin_crypto_vncipher(B, K8);
                        B = __builtin_crypto_vncipher(B, K9);
                        B = __builtin_crypto_vncipherlast(B, K10);

                        StoreBlock(B, out.data());

                        return out;
                    }
                };

                template<typename PolicyType>
                class rijndael_power8_impl<192, 128, PolicyType>
                    : public basic_rijndael_power8_impl<192, 128, PolicyType> {
                protected:
                    typedef PolicyType policy_type;
                    typedef typename policy_type::block_type block_type;
                    typedef typename policy_type::key_type key_type;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    BOOST_STATIC_ASSERT(PolicyType::key_bits == 192);
                    BOOST_STATIC_ASSERT(PolicyType::block_bits == 128);

                public:
                    static block_type encrypt_block(const block_type &plaintext,
                                                    const key_schedule_type &encryption_key) {
                        block_type out = {0};

                        const __vector unsigned long long K0 = LoadKey(&encryption_key[0]);
                        const __vector unsigned long long K1 = LoadKey(&encryption_key[4]);
                        const __vector unsigned long long K2 = LoadKey(&encryption_key[8]);
                        const __vector unsigned long long K3 = LoadKey(&encryption_key[12]);
                        const __vector unsigned long long K4 = LoadKey(&encryption_key[16]);
                        const __vector unsigned long long K5 = LoadKey(&encryption_key[20]);
                        const __vector unsigned long long K6 = LoadKey(&encryption_key[24]);
                        const __vector unsigned long long K7 = LoadKey(&encryption_key[28]);
                        const __vector unsigned long long K8 = LoadKey(&encryption_key[32]);
                        const __vector unsigned long long K9 = LoadKey(&encryption_key[36]);
                        const __vector unsigned long long K10 = LoadKey(&encryption_key[40]);
                        const __vector unsigned long long K11 = LoadKey(&encryption_key[44]);
                        const __vector unsigned long long K12 = LoadBlock(m_ME.data());

                        __vector unsigned long long B = LoadBlock(plaintext.data());

                        B = vec_xor(B, K0);
                        B = __builtin_crypto_vcipher(B, K1);
                        B = __builtin_crypto_vcipher(B, K2);
                        B = __builtin_crypto_vcipher(B, K3);
                        B = __builtin_crypto_vcipher(B, K4);
                        B = __builtin_crypto_vcipher(B, K5);
                        B = __builtin_crypto_vcipher(B, K6);
                        B = __builtin_crypto_vcipher(B, K7);
                        B = __builtin_crypto_vcipher(B, K8);
                        B = __builtin_crypto_vcipher(B, K9);
                        B = __builtin_crypto_vcipher(B, K10);
                        B = __builtin_crypto_vcipher(B, K11);
                        B = __builtin_crypto_vcipherlast(B, K12);

                        StoreBlock(B, out.data());

                        return out;
                    }

                    static block_type decrypt_block(const block_type &plaintext,
                                                    const key_schedule_type &encryption_key) {
                        block_type out = {0};

                        const __vector unsigned long long K0 = LoadBlock(m_ME.data());
                        const __vector unsigned long long K1 = LoadKey(&encryption_key[44]);
                        const __vector unsigned long long K2 = LoadKey(&encryption_key[40]);
                        const __vector unsigned long long K3 = LoadKey(&encryption_key[36]);
                        const __vector unsigned long long K4 = LoadKey(&encryption_key[32]);
                        const __vector unsigned long long K5 = LoadKey(&encryption_key[28]);
                        const __vector unsigned long long K6 = LoadKey(&encryption_key[24]);
                        const __vector unsigned long long K7 = LoadKey(&encryption_key[20]);
                        const __vector unsigned long long K8 = LoadKey(&encryption_key[16]);
                        const __vector unsigned long long K9 = LoadKey(&encryption_key[12]);
                        const __vector unsigned long long K10 = LoadKey(&encryption_key[8]);
                        const __vector unsigned long long K11 = LoadKey(&encryption_key[4]);
                        const __vector unsigned long long K12 = LoadKey(&encryption_key[0]);

                        __vector unsigned long long B = LoadBlock(plaintext.data());

                        B = vec_xor(B, K0);
                        B = __builtin_crypto_vncipher(B, K1);
                        B = __builtin_crypto_vncipher(B, K2);
                        B = __builtin_crypto_vncipher(B, K3);
                        B = __builtin_crypto_vncipher(B, K4);
                        B = __builtin_crypto_vncipher(B, K5);
                        B = __builtin_crypto_vncipher(B, K6);
                        B = __builtin_crypto_vncipher(B, K7);
                        B = __builtin_crypto_vncipher(B, K8);
                        B = __builtin_crypto_vncipher(B, K9);
                        B = __builtin_crypto_vncipher(B, K10);
                        B = __builtin_crypto_vncipher(B, K11);
                        B = __builtin_crypto_vncipherlast(B, K12);

                        StoreBlock(B, out.data());
                    }
                };

                template<typename PolicyType>
                class rijndael_power8_impl<256, 128, PolicyType>
                    : public basic_rijndael_power8_impl<256, 128, PolicyType> {
                protected:
                    typedef PolicyType policy_type;
                    typedef typename policy_type::block_type block_type;
                    typedef typename policy_type::key_type key_type;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    BOOST_STATIC_ASSERT(PolicyType::key_bits == 256);
                    BOOST_STATIC_ASSERT(PolicyType::block_bits == 128);

                public:
                    static block_type encrypt_block(const block_type &plaintext,
                                                    const key_schedule_type &encryption_key) {
                        block_type out = {0};

                        const __vector unsigned long long K0 = LoadKey(&encryption_key[0]);
                        const __vector unsigned long long K1 = LoadKey(&encryption_key[4]);
                        const __vector unsigned long long K2 = LoadKey(&encryption_key[8]);
                        const __vector unsigned long long K3 = LoadKey(&encryption_key[12]);
                        const __vector unsigned long long K4 = LoadKey(&encryption_key[16]);
                        const __vector unsigned long long K5 = LoadKey(&encryption_key[20]);
                        const __vector unsigned long long K6 = LoadKey(&encryption_key[24]);
                        const __vector unsigned long long K7 = LoadKey(&encryption_key[28]);
                        const __vector unsigned long long K8 = LoadKey(&encryption_key[32]);
                        const __vector unsigned long long K9 = LoadKey(&encryption_key[36]);
                        const __vector unsigned long long K10 = LoadKey(&encryption_key[40]);
                        const __vector unsigned long long K11 = LoadKey(&encryption_key[44]);
                        const __vector unsigned long long K12 = LoadKey(&encryption_key[48]);
                        const __vector unsigned long long K13 = LoadKey(&encryption_key[52]);
                        const __vector unsigned long long K14 = LoadBlock(m_ME.data());

                        __vector unsigned long long B = LoadBlock(plaintext.data());

                        B = vec_xor(B, K0);
                        B = __builtin_crypto_vcipher(B, K1);
                        B = __builtin_crypto_vcipher(B, K2);
                        B = __builtin_crypto_vcipher(B, K3);
                        B = __builtin_crypto_vcipher(B, K4);
                        B = __builtin_crypto_vcipher(B, K5);
                        B = __builtin_crypto_vcipher(B, K6);
                        B = __builtin_crypto_vcipher(B, K7);
                        B = __builtin_crypto_vcipher(B, K8);
                        B = __builtin_crypto_vcipher(B, K9);
                        B = __builtin_crypto_vcipher(B, K10);
                        B = __builtin_crypto_vcipher(B, K11);
                        B = __builtin_crypto_vcipher(B, K12);
                        B = __builtin_crypto_vcipher(B, K13);
                        B = __builtin_crypto_vcipherlast(B, K14);

                        StoreBlock(B, out.data());

                        return out;
                    }

                    static block_type decrypt_block(const block_type &plaintext,
                                                    const key_schedule_type &encryption_key) {

                        block_type out = {0};

                        const __vector unsigned long long K0 = LoadBlock(m_ME.data());
                        const __vector unsigned long long K1 = LoadKey(&encryption_key[52]);
                        const __vector unsigned long long K2 = LoadKey(&encryption_key[48]);
                        const __vector unsigned long long K3 = LoadKey(&encryption_key[44]);
                        const __vector unsigned long long K4 = LoadKey(&encryption_key[40]);
                        const __vector unsigned long long K5 = LoadKey(&encryption_key[36]);
                        const __vector unsigned long long K6 = LoadKey(&encryption_key[32]);
                        const __vector unsigned long long K7 = LoadKey(&encryption_key[28]);
                        const __vector unsigned long long K8 = LoadKey(&encryption_key[24]);
                        const __vector unsigned long long K9 = LoadKey(&encryption_key[20]);
                        const __vector unsigned long long K10 = LoadKey(&encryption_key[16]);
                        const __vector unsigned long long K11 = LoadKey(&encryption_key[12]);
                        const __vector unsigned long long K12 = LoadKey(&encryption_key[8]);
                        const __vector unsigned long long K13 = LoadKey(&encryption_key[4]);
                        const __vector unsigned long long K14 = LoadKey(&encryption_key[0]);

                        __vector unsigned long long B = LoadBlock(plaintext.data());

                        B = vec_xor(B, K0);
                        B = __builtin_crypto_vncipher(B, K1);
                        B = __builtin_crypto_vncipher(B, K2);
                        B = __builtin_crypto_vncipher(B, K3);
                        B = __builtin_crypto_vncipher(B, K4);
                        B = __builtin_crypto_vncipher(B, K5);
                        B = __builtin_crypto_vncipher(B, K6);
                        B = __builtin_crypto_vncipher(B, K7);
                        B = __builtin_crypto_vncipher(B, K8);
                        B = __builtin_crypto_vncipher(B, K9);
                        B = __builtin_crypto_vncipher(B, K10);
                        B = __builtin_crypto_vncipher(B, K11);
                        B = __builtin_crypto_vncipher(B, K12);
                        B = __builtin_crypto_vncipher(B, K13);
                        B = __builtin_crypto_vncipherlast(B, K14);

                        StoreBlock(B, out.data());

                        return out;
                    }
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RIJNDAEL_POWER8_IMPL_HPP
