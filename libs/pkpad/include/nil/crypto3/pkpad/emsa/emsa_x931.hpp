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

#ifndef CRYPTO3_EMSA_X931_HPP
#define CRYPTO3_EMSA_X931_HPP

#include <nil/crypto3/pkpad/emsa.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                namespace detail {
                    secure_vector<uint8_t> emsa2_encoding(const secure_vector<uint8_t> &msg, size_t output_bits,
                                                          const secure_vector<uint8_t> &empty_hash, uint8_t hash_id) {
                        const size_t HASH_SIZE = empty_hash.size();

                        size_t output_length = (output_bits + 1) / 8;

                        if (msg.size() != HASH_SIZE) {
                            throw encoding_error("EMSA_X931::encoding_of: Bad input length");
                        }
                        if (output_length < HASH_SIZE + 4) {
                            throw encoding_error("EMSA_X931::encoding_of: Output length is too small");
                        }

                        const bool empty_input = (msg == empty_hash);

                        secure_vector<uint8_t> output(output_length);

                        output[0] = (empty_input ? 0x4B : 0x6B);
                        output[output_length - 3 - HASH_SIZE] = 0xBA;
                        set_mem(&output[1], output_length - 4 - HASH_SIZE, 0xBB);
                        buffer_insert(output, output_length - (HASH_SIZE + 2), msg.data(), msg.size());
                        output[output_length - 2] = hash_id;
                        output[output_length - 1] = 0xCC;

                        return output;
                    }
                }    // namespace detail
                template<typename Scheme, typename Hash>
                struct emsa_x931 : public emsa<Scheme, Hash> {
                    template<typename InputIterator1, typename InputIterator2>
                    bool verify(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2,
                                InputIterator2 last2, std::size_t key_bits) const {
                        try {
                            return (std::equal(first1, last1, emsa2_encoding(first2, last2, key_bits, )));
                        } catch (const std::exception &exception) {
                            return false;
                        }
                    }

                    template<typename SinglePassRange1, typename SinglePassRange2>
                    bool verify(const SinglePassRange1 &range1, const SinglePassRange2 &range2,
                                std::size_t key_bits) const {
                        return verify(boost::begin(range1), boost::end(range1), boost::begin(range2),
                                      boost::end(range2), 0);
                    }

                protected:
                    typedef SequenceContainer<uint8_t, Allocator<uint8_t>> empty_hash_type;

                    template<typename InputIterator1, typename InputIterator2, typename OutputIterator>
                    OutputIterator emsa2_encoding(InputIterator1 first1, InputIterator1 last1, std::size_t output_bits,
                                                  InputIterator2 key_first2, InputIterator2 key_last2,
                                                  OutputIterator out) {
                        std::ptrdiff_t msg_size = std::distance(first1, last1);
                        std::ptrdiff_t empty_hash_size = std::distance(key_first2, key_last2);

                        size_t output_length = (output_bits + 1) / 8;

                        if (msg_size != empty_hash_size) {
                            throw encoding_error("EMSA_X931::encoding_of: Bad input length");
                        }

                        if (output_length < empty_hash_size + 4) {
                            throw encoding_error("EMSA_X931::encoding_of: Output length is too small");
                        }

                        const bool empty_input = std::equal(first1, last1, key_first2, key_last2);

                        secure_vector<uint8_t> output(output_length);

                        *out = (empty_input ? 0x4B : 0x6B);
                        *(out + output_length - 3 - empty_hash_size) = 0xBA;
                        set_mem(&output[1], output_length - 4 - empty_hash_size, 0xBB);
                        buffer_insert(output, output_length - (empty_hash_size + 2), msg.data(), msg.size());
                        output[output_length - 2] = Hash::policy_type::ieee1363_hash_id;
                        output[output_length - 1] = 0xCC;

                        return out;
                    }

                protected:
                    empty_hash_type empty_hash;
                };
            }    // namespace padding
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif
