//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_EMSA_PKCS1_HPP
#define CRYPTO3_EMSA_PKCS1_HPP

#include <nil/crypto3/pkpad/emsa.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                namespace detail {
                    secure_vector<uint8_t> emsa3_encoding(const secure_vector<uint8_t> &msg, size_t output_bits,
                                                          const uint8_t hash_id[], size_t hash_id_length) {
                        size_t output_length = output_bits / 8;
                        if (output_length < hash_id_length + msg.size() + 10) {
                            throw encoding_error("emsa3_encoding: Output length is too small");
                        }

                        secure_vector<uint8_t> T(output_length);
                        const size_t P_LENGTH = output_length - msg.size() - hash_id_length - 2;

                        T[0] = 0x01;
                        set_mem(&T[1], P_LENGTH, 0xFF);
                        T[P_LENGTH + 1] = 0x00;

                        if (hash_id_length > 0) {
                            BOOST_ASSERT(hash_id != nullptr)
                            buffer_insert(T, P_LENGTH + 2, hash_id, hash_id_length);
                        }

                        buffer_insert(T, output_length - msg.size(), msg.data(), msg.size());
                        return T;
                    }
                }    // namespace detail

                template<typename Scheme, typename Hash>
                struct emsa_pkcs1v15_base : public emsa<Scheme, Hash> {
                    template<typename InputMessageIterator, typename OutputIterator>
                    secure_vector<uint8_t> emsa3_encoding(InputMessageIterator first1, InputMessageIterator last1,
                                                          size_t output_bits) {
                        size_t output_length = output_bits / 8;
                        std::ptrdiff_t message_length = std::distance(first1, last1);

                        if (output_length < Hash::policy_type::pkcs_id.size() + message_length + 10) {
                            throw encoding_error("emsa3_encoding: Output length is too small");
                        }

                        secure_vector<uint8_t> T(output_length);
                        const size_t P_LENGTH = output_length - message_length - Hash::policy_type::pkcs_id.size() - 2;

                        T[0] = 0x01;
                        set_mem(&T[1], P_LENGTH, 0xFF);
                        T[P_LENGTH + 1] = 0x00;

                        if (Hash::policy_type::pkcs_id.size() > 0) {
                            BOOST_ASSERT(Hash::policy_type::pkcs_id != nullptr);
                            buffer_insert(T, P_LENGTH + 2, Hash::policy_type::pkcs_id,
                                          Hash::policy_type::pkcs_id.size());
                        }

                        buffer_insert(T, output_length - message_length, msg.data(), message_length);
                        return T;
                    }
                };

                /*!
                 * @brief * PKCS #1 v1.5 signature padding aka PKCS #1 block type 1 aka EMSA3 from IEEE 1363
                 * @tparam Hash
                 */
                template<typename Scheme, typename Hash>
                struct emsa_pkcs1v15 : public emsa_pkcs1v15_base<Hash> {
                    template<typename InputIterator1, typename InputIterator2>
                    bool verify(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2,
                                InputIterator2 last2, std::size_t key_bits) const {
                        std::ptrdiff_t raw_length = std::distance(first2, last2);
                        if (raw_length != Hash::policy_type::digest_bits) {
                            return false;
                        }

                        try {
                            return std::equal(first1, last1, emsa3_encoding(first2, last2, key_bits));
                        } catch (const std::exception &) {
                            return false;
                        }
                    }

                    template<typename SinglePassRange1, typename SinglePassRange2>
                    bool verify(const SinglePassRange1 &range1, const SinglePassRange2 &range2,
                                std::size_t key_bits) const {
                        return verify(boost::begin(range1), boost::end(range1), boost::begin(range2),
                                      boost::end(range2), key_bits);
                    }
                };

                /*!
                 * @brief
                 *
                 * EMSA_PKCS1v15_Raw which is EMSA_PKCS1v15 without a hash or digest id
                 * (which according to QCA docs is "identical to PKCS#11's CKM_RSA_PKCS
                 * mechanism", something I have not confirmed)
                 * @tparam Hash
                 */

                template<typename Scheme, typename Hash>
                struct emsa_pkcs1v15_raw : public emsa_pkcs1v15_base<Hash> {
                    template<typename InputIterator1, typename InputIterator2>
                    bool verify(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2,
                                InputIterator2 last2, std::size_t key_bits) const {
                        if (Hash::policy_type::digest_bits > 0 &&
                            std::distance(first2, last2) != Hash::policy_type::digest_bits) {
                            return false;
                        }

                        try {
                            return std::equal(first1, last1, emsa3_encoding(first2, last2, key_bits));
                        } catch (const std::exception &) {
                            return false;
                        }
                    }

                    template<typename SinglePassRange1, typename SinglePassRange2>
                    bool verify(const SinglePassRange1 &range1, const SinglePassRange2 &range2,
                                std::size_t key_bits) const {
                        return verify(boost::begin(range1), boost::end(range1), boost::begin(range2),
                                      boost::end(range2), 0);
                    }
                };
            }    // namespace padding
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif
