//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_BLOCK_RIJNDAEL_HPP
#define CRYPTO3_BLOCK_RIJNDAEL_HPP

#include <boost/range/adaptor/sliced.hpp>

#include <nil/crypto3/block/detail/block_stream_processor.hpp>
#include <nil/crypto3/block/detail/cipher_modes.hpp>

#include <nil/crypto3/block/detail/rijndael/rijndael_policy.hpp>
#include <nil/crypto3/block/detail/rijndael/rijndael_impl.hpp>

#if defined(CRYPTO3_HAS_RIJNDAEL_NI)

#include <nil/crypto3/block/detail/rijndael/rijndael_ni_impl.hpp>

#elif defined(CRYPTO3_HAS_RIJNDAEL_SSSE3) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_SSSE3_VERSION

#include <nil/crypto3/block/detail/rijndael/rijndael_ssse3_impl.hpp>

#elif defined(CRYPTO3_HAS_RIJNDAEL_ARMV8)

#include <nil/crypto3/block/detail/rijndael/rijndael_armv8_impl.hpp>

#elif defined(CRYPTO3_HAS_RIJNDAEL_POWER8)

#include <nil/crypto3/block/detail/rijndael/rijndael_power8_impl.hpp>

#endif

#include <nil/crypto3/block/detail/utilities/cpuid/cpuid.hpp>

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
             * [Software mitigations to hedge AES against cache-based software side channel
             * vulnerabilities](https://eprint.iacr.org/2006/052.pdf)
             *
             * [Cache Games - Bringing Access-Based Cache Attacks on AES to
             * Practice](http://www.ieee-security.org/TC/SP2011/PAPERS/2011/paper031.pdf)
             *
             * [Cache-Collision Timing Attacks Against AES. Bonneau,
             * Mironov](http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.88.4753)
             *
             * @tparam KeyBits Key length used in bits. Available values are: 128, 192, 256
             * @tparam BlockBits Block length used in bits. Available values are: 128, 192, 256
             */
            template<std::size_t KeyBits, std::size_t BlockBits>
            class rijndael {

                BOOST_STATIC_ASSERT(KeyBits >= 128 && KeyBits <= 256 && KeyBits % 32 == 0);
                BOOST_STATIC_ASSERT(BlockBits >= 128 && BlockBits <= 256 && BlockBits % 32 == 0);

                constexpr static const std::size_t version = KeyBits;
                typedef detail::rijndael_policy<KeyBits, BlockBits> policy_type;

                typedef
                    typename std::conditional<BlockBits == 128 && (KeyBits == 128 || KeyBits == 192 || KeyBits == 256),
#if defined(CRYPTO3_HAS_RIJNDAEL_NI)
                                              detail::rijndael_ni_impl<KeyBits, BlockBits, policy_type>,
#elif defined(CRYPTO3_HAS_RIJNDAEL_SSSE3) || BOOST_HW_SIMD_X86 >= BOOST_HW_SIMD_X86_SSSE3_VERSION
                                              detail::rijndael_ssse3_impl<KeyBits, BlockBits, policy_type>,
#elif defined(CRYPTO3_HAS_RIJNDAEL_ARMV8)
                                              detail::rijndael_armv8_impl<KeyBits, BlockBits, policy_type>,
#elif defined(CRYPTO3_HAS_RIJNDAEL_POWER8)
                                              detail::rijndael_power8_impl<KeyBits, BlockBits, policy_type>,
#else
                                              detail::rijndael_impl<KeyBits, BlockBits, policy_type>,
#endif
                                              detail::rijndael_impl<KeyBits, BlockBits, policy_type>>::type impl_type;

                constexpr static const std::size_t key_schedule_words = policy_type::key_schedule_words;
                constexpr static const std::size_t key_schedule_bytes = policy_type::key_schedule_bytes;
                typedef typename policy_type::key_schedule_type key_schedule_type;

            public:
                constexpr static const std::size_t word_bits = policy_type::word_bits;
                constexpr static const std::size_t word_bytes = policy_type::word_bytes;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                //                typedef typename policy_type::key_schedule_word_type key_schedule_word_type;
                typedef typename policy_type::key_type key_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::uint8_t rounds = policy_type::rounds;
                typedef typename policy_type::round_constants_type round_constants_type;

                template<class Mode, typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = policy_type::word_bits * 2;
                    };

                    typedef block_stream_processor<Mode, StateAccumulator, params_type> type;
                };

                typedef typename stream_endian::little_octet_big_bit endian_type;

                rijndael(const key_type &key) : encryption_key({0}), decryption_key({0}) {
                    impl_type::schedule_key(key, encryption_key, decryption_key);
                }

                virtual ~rijndael() {
                    encryption_key.fill(0);
                    decryption_key.fill(0);
                }

                inline block_type encrypt(const block_type &plaintext) const {
                    return impl_type::encrypt_block(plaintext, encryption_key);
                }

                inline block_type decrypt(const block_type &plaintext) const {
                    return impl_type::decrypt_block(plaintext, decryption_key);
                }

            protected:
                key_schedule_type encryption_key, decryption_key;
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif
