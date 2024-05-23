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

#ifndef CRYPTO3_PSSR_HPP
#define CRYPTO3_PSSR_HPP

#include <nil/crypto3/pkpad/emsa.hpp>

#include <nil/crypto3/utilities/bit_ops.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                namespace detail {
                    /*
                     * PSSR Encode Operation
                     */
                    secure_vector<uint8_t> pss_encode(HashFunction &hash, const secure_vector<uint8_t> &msg,
                                                      const secure_vector<uint8_t> &salt, size_t output_bits) {
                        const size_t HASH_SIZE = hash.output_length();
                        const size_t SALT_SIZE = salt.size();

                        if (msg.size() != HASH_SIZE) {
                            throw encoding_error("Cannot encode PSS string, input length invalid for hash");
                        }
                        if (output_bits < 8 * HASH_SIZE + 8 * SALT_SIZE + 9) {
                            throw encoding_error("Cannot encode PSS string, output length too small");
                        }

                        const size_t output_length = (output_bits + 7) / 8;

                        for (size_t i = 0; i != 8; ++i) {
                            hash.update(0);
                        }
                        hash.update(msg);
                        hash.update(salt);
                        secure_vector<uint8_t> H = hash.final();

                        secure_vector<uint8_t> EM(output_length);

                        EM[output_length - HASH_SIZE - SALT_SIZE - 2] = 0x01;
                        buffer_insert(EM, output_length - 1 - HASH_SIZE - SALT_SIZE, salt);
                        mgf1_mask(hash, H.data(), HASH_SIZE, EM.data(), output_length - HASH_SIZE - 1);
                        EM[0] &= 0xFF >> (8 * ((output_bits + 7) / 8) - output_bits);
                        buffer_insert(EM, output_length - 1 - HASH_SIZE, H);
                        EM[output_length - 1] = 0xBC;
                        return EM;
                    }

                    bool pss_verify(HashFunction &hash, const secure_vector<uint8_t> &pss_repr,
                                    const secure_vector<uint8_t> &message_hash, size_t key_bits,
                                    size_t *out_salt_size) {
                        const size_t HASH_SIZE = hash.output_length();
                        const size_t KEY_BYTES = (key_bits + 7) / 8;

                        if (key_bits < 8 * HASH_SIZE + 9) {
                            return false;
                        }

                        if (message_hash.size() != HASH_SIZE) {
                            return false;
                        }

                        if (pss_repr.size() > KEY_BYTES || pss_repr.size() <= 1) {
                            return false;
                        }

                        if (pss_repr[pss_repr.size() - 1] != 0xBC) {
                            return false;
                        }

                        secure_vector<uint8_t> coded = pss_repr;
                        if (coded.size() < KEY_BYTES) {
                            secure_vector<uint8_t> temp(KEY_BYTES);
                            buffer_insert(temp, KEY_BYTES - coded.size(), coded);
                            coded = temp;
                        }

                        const size_t TOP_BITS = 8 * ((key_bits + 7) / 8) - key_bits;
                        if (TOP_BITS > 8 - high_bit(coded[0])) {
                            return false;
                        }

                        uint8_t *DB = coded.data();
                        const size_t DB_size = coded.size() - HASH_SIZE - 1;

                        const uint8_t *H = &coded[DB_size];
                        const size_t H_size = HASH_SIZE;

                        mgf1_mask(hash, H, H_size, DB, DB_size);
                        DB[0] &= 0xFF >> TOP_BITS;

                        size_t salt_offset = 0;
                        for (size_t j = 0; j != DB_size; ++j) {
                            if (DB[j] == 0x01) {
                                salt_offset = j + 1;
                                break;
                            }
                            if (DB[j]) {
                                return false;
                            }
                        }
                        if (salt_offset == 0) {
                            return false;
                        }

                        const size_t salt_size = DB_size - salt_offset;

                        for (size_t j = 0; j != 8; ++j) {
                            hash.update(0);
                        }
                        hash.update(message_hash);
                        hash.update(&DB[salt_offset], salt_size);

                        const secure_vector<uint8_t> H2 = hash.final();

                        const bool ok = constant_time_compare(H, H2.data(), HASH_SIZE);

                        if (out_salt_size && ok) {
                            *out_salt_size = salt_size;
                        }

                        return ok;
                    }
                }    // namespace detail

                /*!
                 * @brief PSSR aka EMSA4 in IEEE 1363
                 * @tparam Hash
                 */
                template<typename Scheme, typename Hash>
                struct emsa_pssr : public emsa<Scheme, Hash> {
                    template<typename InputIterator1, typename InputIterator2>
                    bool verify(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2,
                                InputIterator2 last2, std::size_t key_bits) const {
                        size_t salt_size = 0;
                        const bool ok = pss_verify(this->hash, first1, last1, first2, last2, key_bits, &salt_size);

                        if (required_salt_len && salt_size != m_salt_size) {
                            return false;
                        }

                        return ok;
                    }

                    template<typename SinglePassRange1, typename SinglePassRange2>
                    bool verify(const SinglePassRange1 &range1, const SinglePassRange2 &range2,
                                std::size_t key_bits) const {
                        return verify(boost::begin(range1), boost::end(range1), boost::begin(range2),
                                      boost::end(range2), 0);
                    }

                protected:
                    std::size_t required_salt_length;
                    std::size_t salt_size;

                    template<typename InputMessageIterator, typename InputSaltIterator, typename OutputIterator>
                    OutputIterator pss_encode(Hash &hash, InputMessageIterator firstm, InputMessageIterator lastm,
                                              InputSaltIterator firsts, InputSaltIterator lasts, size_t output_bits) {
                        std::ptrdiff_t message_size = std::distance(firstm, lastm);
                        std::ptrdiff_t salt_size = std::distance(firsts, lasts);

                        if (message_size != Hash::policy_type::digest_bits / 8) {
                            throw encoding_error("Cannot encode PSS string, input length invalid for hash");
                        }
                        if (output_bits < Hash::policy_type::digest_bits + 8 * salt_size + 9) {
                            throw encoding_error("Cannot encode PSS string, output length too small");
                        }

                        const size_t output_length = (output_bits + 7) / 8;

                        for (size_t i = 0; i != 8; ++i) {
                            hash.update(0);
                        }
                        hash.update(msg);
                        hash.update(salt);
                        secure_vector<uint8_t> H = hash.final();

                        secure_vector<uint8_t> EM(output_length);

                        EM[output_length - Hash::policy_type::digest_bits / 8 - salt_size - 2] = 0x01;
                        buffer_insert(EM, output_length - 1 - Hash::policy_type::digest_bits / 8 - salt_size, salt);
                        mgf1_mask(hash, H.data(), Hash::policy_type::digest_bits / 8, EM.data(),
                                  output_length - Hash::policy_type::digest_bits / 8 - 1);
                        EM[0] &= 0xFF >> (8 * ((output_bits + 7) / 8) - output_bits);
                        buffer_insert(EM, output_length - 1 - Hash::policy_type::digest_bits / 8, H);
                        EM[output_length - 1] = 0xBC;
                        return EM;
                    }

                    template<typename InputIterator1, typename InputMessageIterator>
                    bool pss_verify(HashFunction &hash, const secure_vector<uint8_t> &pss_repr,
                                    const secure_vector<uint8_t> &message_hash, size_t key_bits,
                                    size_t *out_salt_size) {
                        const size_t KEY_BYTES = (key_bits + 7) / 8;

                        if (key_bits < Hash::policy_type::digest_bits + 9) {
                            return false;
                        }

                        if (message_hash.size() != Hash::policy_type::digest_bits / 8) {
                            return false;
                        }

                        if (pss_repr.size() > KEY_BYTES || pss_repr.size() <= 1) {
                            return false;
                        }

                        if (pss_repr[pss_repr.size() - 1] != 0xBC) {
                            return false;
                        }

                        secure_vector<uint8_t> coded = pss_repr;
                        if (coded.size() < KEY_BYTES) {
                            secure_vector<uint8_t> temp(KEY_BYTES);
                            buffer_insert(temp, KEY_BYTES - coded.size(), coded);
                            coded = temp;
                        }

                        const size_t TOP_BITS = 8 * ((key_bits + 7) / 8) - key_bits;
                        if (TOP_BITS > 8 - high_bit(coded[0])) {
                            return false;
                        }

                        uint8_t *DB = coded.data();
                        const size_t DB_size = coded.size() - Hash::policy_type::digest_bits / 8 - 1;

                        const uint8_t *H = &coded[DB_size];

                        mgf1_mask(hash, H, Hash::policy_type::digest_bits / 8, DB, DB_size);
                        DB[0] &= 0xFF >> TOP_BITS;

                        size_t salt_offset = 0;
                        for (size_t j = 0; j != DB_size; ++j) {
                            if (DB[j] == 0x01) {
                                salt_offset = j + 1;
                                break;
                            }
                            if (DB[j]) {
                                return false;
                            }
                        }
                        if (salt_offset == 0) {
                            return false;
                        }

                        const size_t salt_size = DB_size - salt_offset;

                        for (size_t j = 0; j != 8; ++j) {
                            hash.update(0);
                        }
                        hash.update(message_hash);
                        hash.update(&DB[salt_offset], salt_size);

                        const secure_vector<uint8_t> H2 = hash.final();

                        const bool ok = constant_time_compare(H, H2.data(), Hash::policy_type::digest_bits / 8);

                        if (out_salt_size && ok) {
                            *out_salt_size = salt_size;
                        }

                        return ok;
                    }
                };
            }    // namespace padding
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif
