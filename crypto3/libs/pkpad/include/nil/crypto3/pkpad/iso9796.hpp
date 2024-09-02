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

#ifndef CRYPTO3_ISO9796_HPP
#define CRYPTO3_ISO9796_HPP

#include <nil/crypto3/pkpad/emsa.hpp>
#include <nil/crypto3/pkpad/mgf1.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                template<typename Hash>
                secure_vector<uint8_t> iso9796_encoding(const secure_vector<uint8_t> &msg, size_t output_bits,
                                                        size_t SALT_SIZE, bool implicit, random_number_generator &rng) {
                    const size_t output_length = (output_bits + 7) / 8;

                    // set trailer length
                    size_t tLength = 1;
                    if (!implicit) {
                        tLength = 2;
                    }
                    const size_t HASH_SIZE = hash->output_length();

                    if (output_length <= HASH_SIZE + SALT_SIZE + tLength) {
                        throw encoding_error("ISO9796-2::encoding_of: Output length is too small");
                    }

                    // calculate message capacity
                    const size_t capacity = output_length - HASH_SIZE - SALT_SIZE - tLength - 1;

                    // msg1 is the recoverable and msg2 the unrecoverable message part.
                    secure_vector<uint8_t> msg1;
                    secure_vector<uint8_t> msg2;
                    if (msg.size() > capacity) {
                        msg1 = secure_vector<uint8_t>(msg.begin(), msg.begin() + capacity);
                        msg2 = secure_vector<uint8_t>(msg.begin() + capacity, msg.end());
                        hash->update(msg2);
                    } else {
                        msg1 = msg;
                    }
                    msg2 = hash->final();

                    // compute H(C||msg1 ||H(msg2)||S)
                    uint64_t msgLength = msg1.size();
                    secure_vector<uint8_t> salt = rng.random_vec(SALT_SIZE);
                    hash->update_be(msgLength * 8);
                    hash->update(msg1);
                    hash->update(msg2);
                    hash->update(salt);
                    secure_vector<uint8_t> H = hash->final();

                    secure_vector<uint8_t> EM(output_length);

                    // compute message offset.
                    size_t offset = output_length - HASH_SIZE - SALT_SIZE - tLength - msgLength - 1;

                    // insert message border (0x01), msg1 and salt into the output buffer
                    EM[offset] = 0x01;
                    buffer_insert(EM, offset + 1, msg1);
                    buffer_insert(EM, offset + 1 + msgLength, salt);

                    // apply mask
                    mgf1_mask(*hash, H.data(), HASH_SIZE, EM.data(), output_length - HASH_SIZE - tLength);
                    buffer_insert(EM, output_length - HASH_SIZE - tLength, H);
                    // set implicit/ISO trailer
                    if (!implicit) {
                        uint8_t hash_id = ieee1363_hash_id(hash->name());
                        if (!hash_id) {
                            throw encoding_error("ISO9796-2::encoding_of: no hash identifier for " + hash->name());
                        }
                        EM[output_length - 1] = 0xCC;
                        EM[output_length - 2] = hash_id;

                    } else {
                        EM[output_length - 1] = 0xBC;
                    }
                    // clear the leftmost bit (confer bouncy castle)
                    EM[0] &= 0x7F;

                    return EM;
                }

                bool iso9796_verification(const secure_vector<uint8_t> &const_coded, const secure_vector<uint8_t> &raw,
                                          size_t key_bits, std::unique_ptr<HashFunction> &hash, size_t SALT_SIZE) {
                    const size_t HASH_SIZE = hash->output_length();
                    const size_t KEY_BYTES = (key_bits + 7) / 8;

                    if (const_coded.size() != KEY_BYTES) {
                        return false;
                    }
                    // get trailer length
                    size_t tLength;
                    if (const_coded[const_coded.size() - 1] == 0xBC) {
                        tLength = 1;
                    } else {
                        uint8_t hash_id = ieee1363_hash_id(hash->name());
                        if ((!const_coded[const_coded.size() - 2]) ||
                            (const_coded[const_coded.size() - 2] != hash_id) ||
                            (const_coded[const_coded.size() - 1] != 0xCC)) {
                            return false;    // in case of wrong ISO trailer.
                        }
                        tLength = 2;
                    }

                    secure_vector<uint8_t> coded = const_coded;

                    ct::poison(coded.data(), coded.size());
                    // remove mask
                    uint8_t *DB = coded.data();
                    const size_t DB_size = coded.size() - HASH_SIZE - tLength;

                    const uint8_t *H = &coded[DB_size];

                    mgf1_mask(*hash, H, HASH_SIZE, DB, DB_size);
                    // clear the leftmost bit (confer bouncy castle)
                    DB[0] &= 0x7F;

                    // recover msg1 and salt
                    size_t msg1_offset = 1;
                    uint8_t waiting_for_delim = 0xFF;
                    uint8_t bad_input = 0;
                    for (size_t j = 0; j < DB_size; ++j) {
                        const uint8_t one_m = ct::is_equal<uint8_t>(DB[j], 0x01);
                        const uint8_t zero_m = ct::is_zero(DB[j]);
                        const uint8_t add_m = waiting_for_delim & zero_m;

                        bad_input |= waiting_for_delim & ~(zero_m | one_m);
                        msg1_offset += ct::select<uint8_t>(add_m, 1, 0);

                        waiting_for_delim &= zero_m;
                    }

                    // invalid, if delimiter 0x01 was not found or msg1_offset is too big
                    bad_input |= waiting_for_delim;
                    bad_input |= ct::is_less(coded.size(), tLength + HASH_SIZE + msg1_offset + SALT_SIZE);

                    // in case that msg1_offset is too big, just continue with offset = 0.
                    msg1_offset = ct::select<size_t>(bad_input, 0, msg1_offset);

                    ct::unpoison(coded.data(), coded.size());
                    ct::unpoison(msg1_offset);

                    secure_vector<uint8_t> msg1(coded.begin() + msg1_offset,
                                                coded.end() - tLength - HASH_SIZE - SALT_SIZE);
                    secure_vector<uint8_t> salt(coded.begin() + msg1_offset + msg1.size(),
                                                coded.end() - tLength - HASH_SIZE);

                    // compute H2(C||msg1||H(msg2)||S*). * indicates a recovered value
                    const size_t capacity = (key_bits - 2 + 7) / 8 - HASH_SIZE - SALT_SIZE - tLength - 1;
                    secure_vector<uint8_t> msg1raw;
                    secure_vector<uint8_t> msg2;
                    if (raw.size() > capacity) {
                        msg1raw = secure_vector<uint8_t>(raw.begin(), raw.begin() + capacity);
                        msg2 = secure_vector<uint8_t>(raw.begin() + capacity, raw.end());
                        hash->update(msg2);
                    } else {
                        msg1raw = raw;
                    }
                    msg2 = hash->final();

                    uint64_t msg1rawLength = msg1raw.size();
                    hash->update_be(msg1rawLength * 8);
                    hash->update(msg1raw);
                    hash->update(msg2);
                    hash->update(salt);
                    secure_vector<uint8_t> H3 = hash->final();

                    // compute H3(C*||msg1*||H(msg2)||S*) * indicates a recovered value
                    uint64_t msgLength = msg1.size();
                    hash->update_be(msgLength * 8);
                    hash->update(msg1);
                    hash->update(msg2);
                    hash->update(salt);
                    secure_vector<uint8_t> H2 = hash->final();

                    // check if H3 == H2
                    bad_input |= ct::is_equal<uint8_t>(constant_time_compare(H3.data(), H2.data(), HASH_SIZE), false);

                    ct::unpoison(bad_input);
                    return (bad_input == 0);
                }
            }    // namespace padding
        }        // namespace pubkey

        template<typename Scheme, typename Hash>
        struct iso_9796 : public emsa<Scheme, Hash> {
        protected:
            template<typename InputIterator, typename OutputIterator>
            OutputIterator iso9796_encoding(InputIterator first, InputIterator last, size_t output_bits,
                                            size_t SALT_SIZE, bool implicit, random_number_generator &rng) {
                std::ptrdiff_t message_size = std::distance(first, last);

                const size_t output_length = (output_bits + 7) / 8;

                // set trailer length
                size_t t_length = 1;
                if (!implicit) {
                    t_length = 2;
                }
                const size_t HASH_SIZE = this->hash.output_length();

                if (output_length <= HASH_SIZE + SALT_SIZE + t_length) {
                    throw encoding_error("ISO9796-2::encoding_of: Output length is too small");
                }

                // calculate message capacity
                const size_t capacity = output_length - HASH_SIZE - SALT_SIZE - t_length - 1;

                // msg1 is the recoverable and msg2 the unrecoverable message part.
                secure_vector<uint8_t> msg1;
                secure_vector<uint8_t> msg2;
                if (message_size > capacity) {
                    msg1 = secure_vector<uint8_t>(first, first + capacity);
                    msg2 = secure_vector<uint8_t>(first + capacity, last);
                    hash->update(msg2);
                } else {
                    std::copy(first, last, msg1);
                }
                msg2 = hash->final();

                // compute H(C||msg1 ||H(msg2)||S)
                uint64_t msgLength = msg1.size();
                secure_vector<uint8_t> salt = rng.random_vec(SALT_SIZE);
                hash->update_be(msgLength * 8);
                hash->update(msg1);
                hash->update(msg2);
                hash->update(salt);
                secure_vector<uint8_t> H = hash->final();

                secure_vector<uint8_t> EM(output_length);

                // compute message offset.
                size_t offset = output_length - HASH_SIZE - SALT_SIZE - t_length - msgLength - 1;

                // insert message border (0x01), msg1 and salt into the output buffer
                EM[offset] = 0x01;
                buffer_insert(EM, offset + 1, msg1);
                buffer_insert(EM, offset + 1 + msgLength, salt);

                // apply mask
                mgf1_mask(*hash, H.data(), HASH_SIZE, EM.data(), output_length - HASH_SIZE - t_length);
                buffer_insert(EM, output_length - HASH_SIZE - t_length, H);
                // set implicit/ISO trailer
                if (!implicit) {
                    uint8_t hash_id = ieee1363_hash_id(hash->name());
                    if (!hash_id) {
                        throw encoding_error("ISO9796-2::encoding_of: no hash identifier for " + hash->name());
                    }
                    EM[output_length - 1] = 0xCC;
                    EM[output_length - 2] = hash_id;

                } else {
                    EM[output_length - 1] = 0xBC;
                }
                // clear the leftmost bit (confer bouncy castle)
                EM[0] &= 0x7F;

                return EM;
            }

            template<typename InputCodedIterator, typename InputRawIterator, typename OutputIterator>
            bool iso9796_verification(InputCodedIterator first_coded, InputCodedIterator last_coded,
                                      InputRawIterator first_raw, InputRawIterator last_raw, size_t key_bits,
                                      std::unique_ptr<HashFunction> &hash, size_t SALT_SIZE) {
                std::ptrdiff_t coded_size = std::distance(first_coded, last_coded);
                std::ptrdiff_t raw_size = std::distance(first_raw, last_raw);

                const size_t HASH_SIZE = hash->output_length();
                const size_t KEY_BYTES = (key_bits + 7) / 8;

                if (coded_size != KEY_BYTES) {
                    return false;
                }
                // get trailer length
                size_t tLength;
                if (const_coded[coded_size - 1] == 0xBC) {
                    tLength = 1;
                } else {
                    uint8_t hash_id = ieee1363_hash_id(hash->name());
                    if ((!const_coded[coded_size - 2]) || (const_coded[coded_size - 2] != hash_id) ||
                        (const_coded[coded_size - 1] != 0xCC)) {
                        return false;    // in case of wrong ISO trailer.
                    }
                    tLength = 2;
                }

                secure_vector<uint8_t> coded = const_coded;

                ct::poison(coded.data(), coded.size());
                // remove mask
                uint8_t *DB = coded.data();
                const size_t DB_size = coded.size() - HASH_SIZE - tLength;

                const uint8_t *H = &coded[DB_size];

                mgf1_mask(*hash, H, HASH_SIZE, DB, DB_size);
                // clear the leftmost bit (confer bouncy castle)
                DB[0] &= 0x7F;

                // recover msg1 and salt
                size_t msg1_offset = 1;
                uint8_t waiting_for_delim = 0xFF;
                uint8_t bad_input = 0;
                for (size_t j = 0; j < DB_size; ++j) {
                    const uint8_t one_m = ct::is_equal<uint8_t>(DB[j], 0x01);
                    const uint8_t zero_m = ct::is_zero(DB[j]);
                    const uint8_t add_m = waiting_for_delim & zero_m;

                    bad_input |= waiting_for_delim & ~(zero_m | one_m);
                    msg1_offset += ct::select<uint8_t>(add_m, 1, 0);

                    waiting_for_delim &= zero_m;
                }

                // invalid, if delimiter 0x01 was not found or msg1_offset is too big
                bad_input |= waiting_for_delim;
                bad_input |= ct::is_less(coded.size(), tLength + HASH_SIZE + msg1_offset + SALT_SIZE);

                // in case that msg1_offset is too big, just continue with offset = 0.
                msg1_offset = ct::select<size_t>(bad_input, 0, msg1_offset);

                ct::unpoison(coded.data(), coded.size());
                ct::unpoison(msg1_offset);

                secure_vector<uint8_t> msg1(coded.begin() + msg1_offset, coded.end() - tLength - HASH_SIZE - SALT_SIZE);
                secure_vector<uint8_t> salt(coded.begin() + msg1_offset + msg1.size(),
                                            coded.end() - tLength - HASH_SIZE);

                // compute H2(C||msg1||H(msg2)||S*). * indicates a recovered value
                const size_t capacity = (key_bits - 2 + 7) / 8 - HASH_SIZE - SALT_SIZE - tLength - 1;
                secure_vector<uint8_t> msg1raw;
                secure_vector<uint8_t> msg2;
                if (raw_size > capacity) {
                    msg1raw = secure_vector<uint8_t>(first_raw, first_raw + capacity);
                    msg2 = secure_vector<uint8_t>(first_raw + capacity, last_raw);
                    hash->update(msg2);
                } else {
                    std::copy(first_raw, last_raw, msg1raw);
                }
                msg2 = hash->final();

                uint64_t msg1rawLength = msg1raw.size();
                hash->update_be(msg1rawLength * 8);
                hash->update(msg1raw);
                hash->update(msg2);
                hash->update(salt);
                secure_vector<uint8_t> H3 = hash->final();

                // compute H3(C*||msg1*||H(msg2)||S*) * indicates a recovered value
                uint64_t msgLength = msg1.size();
                hash->update_be(msgLength * 8);
                hash->update(msg1);
                hash->update(msg2);
                hash->update(salt);
                secure_vector<uint8_t> H2 = hash->final();

                // check if H3 == H2
                bad_input |= ct::is_equal<uint8_t>(constant_time_compare(H3.data(), H2.data(), HASH_SIZE), false);

                ct::unpoison(bad_input);
                return (bad_input == 0);
            }
        };

        template<typename Scheme, typename Hash>
        struct iso_9796_ds2 : public iso_9796<Scheme, Hash> {
            template<typename InputIterator1, typename InputIterator2>
            bool verify(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2, InputIterator2 last2,
                        std::size_t key_bits) const {
                return iso9796_verification(first1, last1, first2, last2, key_bits, m_hash, m_SALT_SIZE);
            }

            template<typename SinglePassRange1, typename SinglePassRange2>
            bool verify(const SinglePassRange1 &range1, const SinglePassRange2 &range2, std::size_t key_bits) const {
                return verify(boost::begin(range1), boost::end(range1), boost::begin(range2), boost::end(range2), 0);
            }
        };

        template<typename Scheme, typename Hash>
        struct iso_9796_ds3 : public iso_9796<Scheme, Hash> {
            template<typename InputIterator1, typename InputIterator2>
            bool verify(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2, InputIterator2 last2,
                        std::size_t key_bits) const {
                return iso9796_verification(first1, last1, first2, last2, key_bits, m_hash, 0);
            }

            template<typename SinglePassRange1, typename SinglePassRange2>
            bool verify(const SinglePassRange1 &range1, const SinglePassRange2 &range2, std::size_t key_bits) const {
                return verify(boost::begin(range1), boost::end(range1), boost::begin(range2), boost::end(range2), 0);
            }
        };
    }    // namespace crypto3
}    // namespace nil

#endif
