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
        template<typename Hash>
        struct emsa1 : public emsa<Hash> {
            template<typename UniformRandomBitGenerator, typename RandomNumberDistribution, typename InputIterator,
                     typename OutputIterator>
            OutputIterator encode(InputIterator first, InputIterator last, OutputIterator out,
                                  UniformRandomBitGenerator rand, RandomNumberDistribution dist) {
                std::ptrdiff_t distance = std::distance(first, last);

                if (distance != Hash::policy_type::digest_bits / 8) {
                    throw encoding_error("EMSA1::encoding_of: Invalid size for input");
                }
                return emsa1_encoding(first, last, output_bits);
            }

            template<typename InputIterator1, typename InputIterator2>
            bool verify(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2, InputIterator2 last2,
                        std::size_t key_bits) const {
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
            bool verify(const SinglePassRange1 &range1, const SinglePassRange2 &range2, std::size_t key_bits) const {
                return verify(boost::begin(range1), boost::end(range1), boost::begin(range2), boost::end(range2),
                              key_bits);
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

        /**
         * EMSA1 from IEEE 1363
         * Essentially, sign the hash directly
         */
        class EMSA1 final : public emsa {
        public:
            /**
             * @param hash the hash function to use
             */
            explicit EMSA1(HashFunction *hash) : m_hash(hash) {
            }

            emsa *clone() override {
                return new EMSA1(m_hash->clone());
            }

            std::string name() const override;

            algorithm_identifier config_for_x509(const private_key_policy &key,
                                                 const std::string &cert_hash_name) const override;

        private:
            size_t hash_output_length() const {
                return m_hash->output_length();
            }

            void update(const uint8_t[], size_t) override {
                m_hash->update(input, length);
            }

            secure_vector<uint8_t> raw_data() override {
                return m_hash->final();
            }

            secure_vector<uint8_t> encoding_of(const secure_vector<uint8_t> &msg, size_t output_bits,
                                               random_number_generator &rng) override {
                if (msg.size() != hash_output_length()) {
                    throw encoding_error("EMSA1::encoding_of: Invalid size for input");
                }
                return emsa1_encoding(msg, output_bits);
            }

            bool verify(const secure_vector<uint8_t> &coded, const secure_vector<uint8_t> &raw,
                        size_t key_bits) override {
                if (raw.size() != m_hash->output_length()) {
                    return false;
                }

                // Call emsa1_encoding to handle any required bit shifting
                const secure_vector<uint8_t> our_coding = emsa1_encoding(raw, key_bits);

                if (our_coding.size() < input.size()) {
                    return false;
                }

                const size_t offset = our_coding.size() - input.size(); // must be >= 0 per check above

                // If our encoding is longer, all the bytes in it must be zero
                for (size_t i = 0; i != offset; ++i) {
                    if (our_coding[i] != 0) {
                        return false;
                    }
                }

                return constant_time_compare(input.data(), &our_coding[offset], input.size());
            }

            std::unique_ptr<HashFunction> m_hash;
        };
    }    // namespace crypto3
}    // namespace nil

#endif
