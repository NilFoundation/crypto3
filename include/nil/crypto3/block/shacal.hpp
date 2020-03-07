//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_CIPHERS_SHACAL_HPP
#define CRYPTO3_BLOCK_CIPHERS_SHACAL_HPP

#include <nil/crypto3/block/basic_shacal.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Shacal. Merkle-Damgård construction foundation for
             * @ref nil::crypto3::hash::sha "SHA" hashes.
             *
             * @ingroup block
             *
             * Implemented directly from the SHA standard as found at
             * http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
             *
             * The original FIPS-180 seems to be gone, but FIPS 180-1
             * (http://www.itl.nist.gov/fipspubs/fip180-1.htm) says the onl
             * in SHA-1 from SHA(-0) is the rotation in the key scheduling.
             *
             * In SHA terminology:
             * - plaintext = H^(i-1)
             * - ciphertext = H^(i)
             * - key = M^(i)
             * - schedule = W
             */
            class shacal : public basic_shacal {
            public:
                shacal(const key_type &k) : basic_shacal(build_schedule(k)) {
                }

                shacal(schedule_type s) : basic_shacal((prepare_schedule(s), s)) {
                }

            private:
                static schedule_type build_schedule(const key_type &key) {
                    // Copy key into beginning of round_constants_words
                    schedule_type schedule;
                    for (unsigned t = 0; t < key_words; ++t) {
                        schedule[t] = key[t];
                    }
                    prepare_schedule(schedule);
                    return schedule;
                }

                static void prepare_schedule(schedule_type &schedule) {
#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                    for (unsigned t = 0; t < key_words; ++t) {
                        std::printf(word_bits == 32 ? "WordBits[%2d] = %.8x\n" : "WordBits[%2d] = %.16lx\n", t,
                                    round_constants_words[t]);
                    }
#endif

                    for (unsigned t = key_words; t < rounds; ++t) {
                        schedule[t] = schedule[t - 3] ^ schedule[t - 8] ^ schedule[t - 14] ^ schedule[t - 16];
                    }
                }
            };

            typedef shacal shacal0;

        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_CIPHERS_SHACAL_HPP
