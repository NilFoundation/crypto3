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

#ifndef CRYPTO3_BLOCK_SHACAL1_HPP
#define CRYPTO3_BLOCK_SHACAL1_HPP

#include <nil/crypto3/block/basic_shacal.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Shacal1. Merkle-Damgård construction foundation for
             * @ref nil::crypto3::hashes::sha1 "SHA1" hashes.
             *
             * @ingroup block
             *
             * Implemented directly from the SHA standard as found at
             * http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
             *
             * In SHA terminology:
             * - plaintext = H^(i-1)
             * - ciphertext = H^(i)
             * - key = M^(i)
             * - schedule = W
             */
            class shacal1 : public basic_shacal {
            public:
                shacal1(const key_type &k) : basic_shacal(build_schedule(k)) {
                }

                shacal1(schedule_type s) : basic_shacal((prepare_schedule(s), s)) {
                }

            private:
                static schedule_type build_schedule(key_type const &key) {
                    // Copy key into beginning of round_constants_words
                    schedule_type schedule;
                    for (unsigned t = 0; t < key_words; ++t) {
                        schedule[t] = key[t];
                    }
                    prepare_schedule(schedule);
                    return schedule;
                }

                static void prepare_schedule(schedule_type &schedule) {
                    for (unsigned t = key_words; t < rounds; ++t) {
                        schedule[t] = schedule[t - 3] ^ schedule[t - 8] ^ schedule[t - 14] ^ schedule[t - 16];
                        schedule[t] = policy_type::rotl<1>(schedule[t]);
                    }
                }
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_CIPHERS_SHACAL1_HPP
