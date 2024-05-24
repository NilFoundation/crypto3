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

#ifndef CRYPTO3_OPENPGP_S2K_HPP
#define CRYPTO3_OPENPGP_S2K_HPP

#include <chrono>

#include <nil/crypto3/pbkdf/detail/pgp_s2k/pgp_s2k_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace pbkdf {
            /*!
             * @brief OpenPGP's S2K
             *
             * See RFC 4880 sections 3.7.1.1, 3.7.1.2, and 3.7.1.3
             * If the salt is empty and iterations == 1, "simple" S2K is used
             * If the salt is non-empty and iterations == 1, "salted" S2K is used
             * If the salt is non-empty and iterations > 1, "iterated" S2K is used
             *
             * Due to complexities of the PGP S2K algorithm, time-based derivation
             * is not supported. So if iterations == 0 and msec.count() > 0, an
             * exception is thrown. In the future this may be supported, in which
             * case "iterated" S2K will be used and the number of iterations
             * performed is returned.
             *
             * Note that unlike PBKDF2, OpenPGP S2K's "iterations" are defined as
             * the number of bytes hashed.
             * @tparam Hash
             * @ingroup pbkdf
             */
            template<typename Hash>
            class pgp_s2k {
                typedef detail::pgp_s2k_functions<Hash> policy_type;

            public:
                typedef typename policy_type::hash_type hash_type;

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;

                constexpr static const std::size_t salt_bits = policy_type::salt_bits;
                typedef typename policy_type::salt_type salt_type;

                std::size_t derive(digest_type &digest, const std::string &passphrase, const salt_type &salt,
                                   size_t iterations, std::chrono::milliseconds msec) const override {
                    if (iterations == 0 && msec.count() > 0) {    // FIXME
                        throw Not_Implemented("OpenPGP_S2K does not implemented timed KDF");
                    }

                    if (iterations > 1 && salt_len == 0) {
                        throw std::invalid_argument("OpenPGP_S2K requires a salt in iterated mode");
                    }

                    secure_vector<uint8_t> input_buf(salt_len + passphrase.size());
                    if (salt_len > 0) {
                        copy_mem(&input_buf[0], salt, salt_len);
                    }
                    if (passphrase.empty() == false) {
                        copy_mem(&input_buf[salt_len], cast_char_ptr_to_uint8(passphrase.data()), passphrase.size());
                    }

                    secure_vector<uint8_t> hash_buf(m_hash->output_length());

                    size_t pass = 0;
                    size_t generated = 0;

                    while (generated != output_len) {
                        const size_t output_this_pass = std::min(hash_buf.size(), output_len - generated);

                        // Preload some number of zero bytes (empty first iteration)
                        std::vector<uint8_t> zero_padding(pass);
                        m_hash->update(zero_padding);

                        // The input is always fully processed even if iterations is very small
                        if (input_buf.empty() == false) {
                            size_t left = std::max(iterations, input_buf.size());
                            while (left > 0) {
                                const size_t input_to_take = std::min(left, input_buf.size());
                                m_hash->update(input_buf.data(), input_to_take);
                                left -= input_to_take;
                            }
                        }

                        m_hash->final(hash_buf.data());
                        copy_mem(output_buf + generated, hash_buf.data(), output_this_pass);
                        generated += output_this_pass;
                        ++pass;
                    }

                    return iterations;
                }
            };

            template<typename Hash>
            using openpgp_s2k = pgp_s2k<Hash>;
        }    // namespace pbkdf
    }        // namespace crypto3
}    // namespace nil

#endif
