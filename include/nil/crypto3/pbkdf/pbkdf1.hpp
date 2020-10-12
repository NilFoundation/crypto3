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

#ifndef CRYPTO3_PBKDF_PBKDF1_HPP
#define CRYPTO3_PBKDF_PBKDF1_HPP

#include <chrono>

#include <nil/crypto3/pbkdf/detail/pbkdf1/pbkdf1_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace pbkdf {
            /*!
             * @brief PKCS #5 v1 PBKDF, aka PBKDF1
             * Can only generate a key up to the size of the hash output.
             * Unless needed for backwards compatibility, use PKCS5_PBKDF2
             * @tparam Hash
             * @ingroup pbkdf
             */
            template<typename Hash>
            class pkcs5_pkbdf1 {
                typedef detail::pkcs5_pkbdf1_functions<Hash> policy_type;

            public:
                typedef typename policy_type::hash_type hash_type;

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;

                constexpr static const std::size_t salt_bits = policy_type::salt_bits;
                typedef typename policy_type::salt_type salt_type;

                std::size_t derive(digest_type &digest, const std::string &passphrase, const salt_type &salt,
                                   size_t iterations, std::chrono::milliseconds msec) const {
                    m_hash->update(passphrase);
                    m_hash->update(salt, salt_len);
                    secure_vector<uint8_t> key = m_hash->final();

                    const auto start = std::chrono::high_resolution_clock::now();
                    size_t iterations_performed = 1;

                    while (true) {
                        if (iterations == 0) {
                            if (iterations_performed % 10000 == 0) {
                                auto time_taken = std::chrono::high_resolution_clock::now() - start;
                                auto msec_taken = std::chrono::duration_cast<std::chrono::milliseconds>(time_taken);
                                if (msec_taken > msec) {
                                    break;
                                }
                            }
                        } else if (iterations_performed == iterations) {
                            break;
                        }

                        m_hash->update(key);
                        m_hash->final(key.data());

                        ++iterations_performed;
                    }

                    copy_mem(output_buf, key.data(), output_len);
                    return iterations_performed;
                }
            };
        }    // namespace pbkdf
    }        // namespace crypto3
}    // namespace nil

#endif
