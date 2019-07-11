//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_RIJNDAEL_H_
#define CRYPTO3_RIJNDAEL_H_

#include <boost/range/adaptor/sliced.hpp>

#include <nil/crypto3/block/block_cipher.hpp>

#include <nil/crypto3/block/detail/block_stream_processor.hpp>
#include <nil/crypto3/block/detail/cipher_modes.hpp>

#include <nil/crypto3/block/detail/rijndael/rijndael_policy.hpp>
#include <nil/crypto3/block/detail/rijndael/rijndael_impl.hpp>

#if defined(CRYPTO3_HAS_RIJNDAEL_SSSE3)

#include <nil/crypto3/block/detail/rijndael/rijndael_ssse3_impl.hpp>

#elif defined(CRYPTO3_HAS_RIJNDAEL_NI)

#include <nil/crypto3/block/detail/rijndael/rijndael_ni_impl.hpp>

#elif defined(CRYPTO3_HAS_RIJNDAEL_ARMV8)

#include <nil/crypto3/block/detail/rijndael/rijndael_armv8_impl.hpp>

#elif defined(CRYPTO3_HAS_RIJNDAEL_POWER8)

#include <nil/crypto3/block/detail/rijndael/rijndael_power8_impl.hpp>

#endif

#include <nil/crypto3/utilities/cpuid/cpuid.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {

            /*!
             * @brief Rijndael. AES competition winner.
             *
             * @ingroup block
             *
             * Generic Rijndael cipher implementation. Contains AES-standardized
             * cipher modifications with timing-attack and cache-line leaking
             * attack preventing mechanisms. Optimized for particular architecture
             * used.
             * AES-standartized version comes in three variants, AES-128, AES-192,
             * and AES-256.
             *
             * The standard 128-bit block cipher. Many modern platforms offer hardware
             * acceleration. However, on platforms without hardware support, AES
             * implementations typically are vulnerable to side channel attacks. For x86
             * systems with SSSE3 but without AES-NI, crypto3 has an implementation which avoids
             * known side channels.
             *
             * This implementation is intended to be based on table lookups which
             * are known to be vulnerable to timing and cache based side channel
             * attacks. Some countermeasures are used which may be helpful in some
             * situations:
             *
             * - Only a single 256-word T-table is used, with rotations applied.
             *   Most implementations use 4 T-tables which leaks much more
             *   information via cache usage.
             *
             * - The TE and TD tables are computed at runtime to avoid flush+reload
             *   attacks using clflush. As different processes will not share the
             *   same underlying table data, an attacker can't manipulate another
             *   processes cache lines via their shared reference to the library
             *   read only segment.
             *
             * - Each cache line of the lookup tables is accessed at the beginning
             *   of each call to encrypt or decrypt. (See the Z variable below)
             *
             * If available SSSE3 or AES-NI are used instead of this version, as both
             * are faster and immune to side channel attacks.
             *
             * Some AES cache timing papers for reference:
             *
             * [Software mitigations to hedge AES against cache-based software side channel vulnerabilities](https://eprint.iacr.org/2006/052.pdf)
             *
             * [Cache Games - Bringing Access-Based Cache Attacks on AES to Practice](http://www.ieee-security.org/TC/SP2011/PAPERS/2011/paper031.pdf)
             *
             * [Cache-Collision Timing Attacks Against AES. Bonneau, Mironov](http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.88.4753)
             *
             * @tparam KeyBits Key length used in bits.
             * @tparam BlockBits Block length used in bits.
             */
            template<std::size_t KeyBits, std::size_t BlockBits>
            class rijndael {

                BOOST_STATIC_ASSERT(KeyBits >= 128 && KeyBits <= 256 && KeyBits % 32 == 0);
                BOOST_STATIC_ASSERT(BlockBits >= 128 && BlockBits <= 256 && BlockBits % 32 == 0);

                constexpr static const std::size_t version = KeyBits;
                typedef detail::rijndael_policy<KeyBits, BlockBits> policy_type;

                typedef typename std::conditional<
                        BlockBits == 128 && (KeyBits == 128 || KeyBits == 192 || KeyBits == 256),
#if defined(CRYPTO3_HAS_RIJNDAEL_SSSE3)
                        detail::rijndael_ssse3_impl<KeyBits, BlockBits, policy_type>,
#elif defined(CRYPTO3_HAS_RIJNDAEL_NI)
                        detail::ni_rijndael_impl<KeyBits, BlockBits, policy_type>,
#elif defined(CRYPTO3_HAS_RIJNDAEL_ARMV8)
                        detail::armv8_rijndael_impl<KeyBits, BlockBits, policy_type>,
#elif defined(CRYPTO3_HAS_RIJNDAEL_POWER8)
                        detail::rijndael_power8_impl<KeyBits, BlockBits, policy_type>,
#else
                        detail::rijndael_impl<KeyBits, BlockBits, policy_type>,
#endif
                        detail::rijndael_impl<KeyBits, BlockBits, policy_type>>::type impl_type;

            public:

                typedef typename detail::isomorphic_encryption_mode<rijndael<KeyBits, BlockBits>> stream_encrypter_type;
                typedef typename detail::isomorphic_decryption_mode<rijndael<KeyBits, BlockBits>> stream_decrypter_type;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                constexpr static const std::size_t word_bytes = policy_type::word_bytes;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef typename policy_type::key_schedule_word_type key_schedule_word_type;
                typedef typename policy_type::key_type key_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::uint8_t rounds = policy_type::rounds;
                typedef typename policy_type::round_constants_type round_constants_type;

                constexpr static const std::size_t key_schedule_words = policy_type::key_schedule_words;
                constexpr static const std::size_t key_schedule_bytes = policy_type::key_schedule_bytes;
                typedef typename policy_type::key_schedule_type key_schedule_type;

                template<template<typename, typename> class Mode,
                                                      typename StateAccumulator, std::size_t ValueBits,
                                                      typename Padding>
                struct stream_cipher {
                    typedef block_stream_processor<Mode<rijndael<KeyBits, BlockBits>, Padding>, StateAccumulator,
                                                   stream_endian::little_octet_big_bit, ValueBits,
                                                   policy_type::word_bits * 2> type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };

                rijndael(const key_type &key) : encryption_key({0}), decryption_key({0}) {
                    impl_type::schedule_key(key, encryption_key, decryption_key);
                }

                virtual ~rijndael() {
                    encryption_key.fill(0);
                    decryption_key.fill(0);
                }

                block_type encrypt(const block_type &plaintext) {
                    return impl_type::encrypt_block(plaintext, encryption_key);
                }

                block_type decrypt(const block_type &plaintext) {
                    return impl_type::decrypt_block(plaintext, decryption_key);
                }

            private:

                key_schedule_type encryption_key, decryption_key;
            };

            /*!
             * @brief AES block cipher. Equals to Rijndael block cipher with 128 bit block length.
             */
            template<std::size_t KeyBits> using aes = rijndael<KeyBits, 128>;
        }
    }
}

#endif
