//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_EMSA1_HPP
#define CRYPTO3_EMSA1_HPP

#include <nil/crypto3/pkpad/emsa.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                template<typename Scheme, typename Hash>
                struct emsa1 : public emsa<Scheme, Hash> {
                    template<typename UniformRandomBitGenerator, typename RandomNumberDistribution,
                             typename InputIterator, typename OutputIterator>
                    OutputIterator encode(InputIterator first, InputIterator last, OutputIterator out,
                                          UniformRandomBitGenerator rand, RandomNumberDistribution dist) {
                        std::ptrdiff_t distance = std::distance(first, last);

                        if (distance != Hash::policy_type::digest_bits / 8) {
                            throw encoding_error("EMSA1::encoding_of: Invalid size for input");
                        }
                        return emsa1_encoding(first, last, output_bits);
                    }

                    template<typename InputIterator1, typename InputIterator2>
                    bool verify(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2,
                                InputIterator2 last2, std::size_t key_bits) const {
                        std::ptrdiff_t input_size = std::distance(first1, last1);
                        std::ptrdiff_t raw_size = std::distance(first2, last2);

                        if (raw_size != Hash::policy_type::digest_bits) {
                            return false;
                        }

                        // Call emsa1_encoding to handle any required bit shifting
                        const secure_vector<uint8_t> our_coding = emsa1_encoding(first2, last2, key_bits);

                        if (our_coding.size() < input_size) {
                            return false;
                        }

                        const size_t offset = our_coding.size() - input_size;    // must be >= 0 per check above

                        // If our encoding is longer, all the bytes in it must be zero
                        for (size_t i = 0; i != offset; ++i) {
                            if (our_coding[i] != 0) {
                                return false;
                            }
                        }

                        return constant_time_compare(input.data(), &our_coding[offset], input_size);
                    }

                    template<typename SinglePassRange1, typename SinglePassRange2>
                    bool verify(const SinglePassRange1 &range1, const SinglePassRange2 &range2,
                                std::size_t key_bits) const {
                        return verify(boost::begin(range1), boost::end(range1), boost::begin(range2),
                                      boost::end(range2), key_bits);
                    }

                protected:
                    template<typename InputIterator, typename OutputIterator>
                    OutputIterator emsa1_encoding(InputIterator first, InputIterator last, OutputIterator out,
                                                  size_t output_bits) {
                        std::ptrdiff_t message_size = std::distance(first, last);

                        if (8 * message_size <= output_bits) {
                            return std::move(first, last, out);
                        }

                        size_t shift = 8 * message_size - output_bits;

                        size_t byte_shift = shift / 8, bit_shift = shift % 8;
                        secure_vector<uint8_t> digest(message_size - byte_shift);

                        for (size_t j = 0; j != message_size - byte_shift; ++j) {
                            digest[j] = msg[j];
                        }

                        if (bit_shift) {
                            uint8_t carry = 0;
                            for (size_t j = 0; j != digest.size(); ++j) {
                                uint8_t temp = digest[j];
                                digest[j] = (temp >> bit_shift) | carry;
                                carry = (temp << (8 - bit_shift));
                            }
                        }
                        return digest;
                    }
                };
            }    // namespace padding
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif
