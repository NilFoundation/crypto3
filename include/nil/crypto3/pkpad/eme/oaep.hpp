//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_OAEP_HPP
#define CRYPTO3_OAEP_HPP

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/pkpad/eme.hpp>
#include <nil/crypto3/pkpad/mgf1.hpp>

namespace nil {
    namespace crypto3 {

        /*!
         * @brief OAEP (called EME1 in IEEE 1363 and in earlier versions of the library) as specified in PKCS#1 v2.0
         * (RFC 2437)
         * @tparam Hasher Hash function type used for optional label hashing
         * @tparam SequenceContainer Hashed optional label storage container
         */
        template<typename Hasher, typename SequenceContainer>
        class oaep : public eme {
        public:
            typedef Hasher hash_type;

            /*!
             * @brief
             * @tparam InputIterator
             * @param first
             * @param last
             * @param hash
             */
            template<typename InputIterator>
            oaep(InputIterator first, InputIterator last) : phash(first, last) {
            }

            /*!
             * @brief
             * @tparam SinglePassRange
             * @param range
             * @param hash
             */
            template<typename SinglePassRange>
            oaep(const SinglePassRange &range = SequenceContainer()) : phash(range) {
            }

            /*!
             * @brief OAEP Pad Operation
             * @tparam UniformRandomBitGenerator
             * @tparam InputIterator
             * @tparam OutputIterator
             * @param first
             * @param last
             * @param out
             * @param key_length
             * @param rand
             * @return
             */
            template<typename UniformRandomBitGenerator, typename RandomNumberDistribution, typename InputIterator,
                     typename OutputIterator>
            OutputIterator pad(InputIterator first, InputIterator last, OutputIterator out, std::size_t key_length,
                               const UniformRandomBitGenerator &rand, const RandomNumberDistribution &dist) {
                std::ptrdiff_t distance = std::distance(first, last);

                if (distance > maximum_input_size(key_length)) {
                    throw std::invalid_argument("OAEP: Input is too large");
                }

                key_length /= 8;

                secure_vector<uint8_t> out(key_length);

                std::generate(out, out + phash.size(), [&rand, &dist]() { return dist(rand); });

                rand.randomize(out.data(), phash.size());

                buffer_insert(out, phash.size(), phash.data(), phash.size());
                out[out.size() - distance - 1] = 0x01;
                buffer_insert(out, out.size() - distance, in, distance);

                mgf1_mask<hash_type>(out.data(), phash.size(), &out[phash.size()], out.size() - phash.size());

                mgf1_mask<hash_type>(&out[phash.size()], out.size() - phash.size(), out.data(), phash.size());

                return out;
            }

            /*!
             * @brief OAEP Unpad Operation
             * @tparam MaskType
             * @tparam InputIterator
             * @tparam OutputIterator
             * @param first
             * @param last
             * @param out
             * @param valid_mask
             * @return
             *
             *
             * Must be careful about error messages here; if an attacker can
             *   distinguish them, it is easy to use the differences as an oracle to
             *   find the secret key, as described in "A Chosen Ciphertext Attack on
             *   RSA Optimal Asymmetric Encryption Padding (OAEP) as Standardized in
             *   PKCS #1 v2.0", James Manger, Crypto 2001
             *
             *   Also have to be careful about timing attacks! Pointed out by Falko
             *   Strenzke.
             *
             *   According to the standard (Section 7.1.1), the encryptor always
             *   creates a message as follows:
             *      i. Concatenate a single octet with hexadecimal value 0x00,
             *         maskedSeed, and maskedDB to form an encoded message EM of
             *         length k octets as
             *            EM = 0x00 || maskedSeed || maskedDB.
             *   where k is the length of the modulus N.
             *   Therefore, the first byte can always be skipped safely.
             */
            template<typename InputIterator, typename OutputIterator>
            OutputIterator unpad(InputIterator first, InputIterator last, OutputIterator out) {
                uint8_t skip_first = ct::is_zero<uint8_t>(*first) & 0x01;
                std::ptrdiff_t distance = std::distance(first, last);

                secure_vector<uint8_t> input(first + skip_first, first + distance);

                ct::poison(input.data(), input.size());

                const size_t hlen = phash.size();

                mgf1_mask<hash_type>(&input[hlen], input.size() - hlen, input.data(), hlen);

                mgf1_mask<hash_type>(input.data(), hlen, &input[hlen], input.size() - hlen);

                size_t delim_idx = 2 * hlen;
                uint8_t waiting_for_delim = 0xFF;
                uint8_t bad_input = 0;

                for (size_t i = delim_idx; i < input.size(); ++i) {
                    const uint8_t zero_m = ct::is_zero<uint8_t>(input[i]);
                    const uint8_t one_m = ct::is_equal<uint8_t>(input[i], 1);

                    const uint8_t add_m = waiting_for_delim & zero_m;

                    bad_input |= waiting_for_delim & ~(zero_m | one_m);

                    delim_idx += ct::select<uint8_t>(add_m, 1, 0);

                    waiting_for_delim &= zero_m;
                }

                // If we never saw any non-zero byte, then it's not valid input
                bad_input |= waiting_for_delim;
                bad_input |= ct::is_equal<uint8_t>(constant_time_compare(&input[hlen], phash.data(), hlen), false);

                ct::unpoison(input.data(), input.size());
                ct::unpoison(&bad_input, 1);
                ct::unpoison(&delim_idx, 1);

                secure_vector<uint8_t> output(input.begin() + delim_idx + 1, input.end());
                ct::cond_zero_mem(bad_input, output.data(), output.size());

                return output;
            }

            virtual std::size_t maximum_input_size(std::size_t key_bits) const override {
                if (key_bits / 8 > 2 * phash.size() + 1) {
                    return ((key_bits / 8) - 2 * phash.size() - 1);
                } else {
                    return 0;
                }
            }

        protected:
            SequenceContainer phash;
        };

        class OAEP final : public eme {
        public:
            size_t maximum_input_size(size_t) const override {
                if (keybits / 8 > 2 * m_Phash.size() + 1) {
                    return ((keybits / 8) - 2 * m_Phash.size() - 1);
                } else {
                    return 0;
                }
            }

            /**
             * @param hash function to use for hashing (takes ownership)
             * @param P an optional label. Normally empty.
             */
            OAEP(HashFunction *hash, const std::string &P = "") : m_mgf1_hash(hash) {
                m_Phash = m_mgf1_hash->process(P);
            }

            /**
             * @param hash function to use for hashing (takes ownership)
             * @param mgf1_hash function to use for MGF1 (takes ownership)
             * @param P an optional label. Normally empty.
             */
            OAEP(HashFunction *hash, HashFunction *mgf1_hash, const std::string &P = "") : m_mgf1_hash(mgf1_hash) {
                std::unique_ptr<HashFunction> phash(hash);    // takes ownership
                m_Phash = phash->process(P);
            }

        private:
            secure_vector<uint8_t> pad(const uint8_t in[], size_t in_length, size_t key_length,
                                       random_number_generator &rng) const override {
                key_length /= 8;

                if (in_length > maximum_input_size(key_length * 8)) {
                    throw std::invalid_argument("OAEP: Input is too large");
                }

                secure_vector<uint8_t> out(key_length);

                rng.randomize(out.data(), m_Phash.size());

                buffer_insert(out, m_Phash.size(), m_Phash.data(), m_Phash.size());
                out[out.size() - in_length - 1] = 0x01;
                buffer_insert(out, out.size() - in_length, in, in_length);

                mgf1_mask(*m_mgf1_hash, out.data(), m_Phash.size(), &out[m_Phash.size()], out.size() - m_Phash.size());

                mgf1_mask(*m_mgf1_hash, &out[m_Phash.size()], out.size() - m_Phash.size(), out.data(), m_Phash.size());

                return out;
            }

            secure_vector<uint8_t> unpad(uint8_t &valid_mask, const uint8_t in[], size_t in_len) const override {
                uint8_t skip_first = ct::is_zero<uint8_t>(in[0]) & 0x01;

                secure_vector<uint8_t> input(in + skip_first, in + in_length);

                ct::poison(input.data(), input.size());

                const size_t hlen = m_Phash.size();

                mgf1_mask(*m_mgf1_hash, &input[hlen], input.size() - hlen, input.data(), hlen);

                mgf1_mask(*m_mgf1_hash, input.data(), hlen, &input[hlen], input.size() - hlen);

                size_t delim_idx = 2 * hlen;
                uint8_t waiting_for_delim = 0xFF;
                uint8_t bad_input = 0;

                for (size_t i = delim_idx; i < input.size(); ++i) {
                    const uint8_t zero_m = ct::is_zero<uint8_t>(input[i]);
                    const uint8_t one_m = ct::is_equal<uint8_t>(input[i], 1);

                    const uint8_t add_m = waiting_for_delim & zero_m;

                    bad_input |= waiting_for_delim & ~(zero_m | one_m);

                    delim_idx += ct::select<uint8_t>(add_m, 1, 0);

                    waiting_for_delim &= zero_m;
                }

                // If we never saw any non-zero byte, then it's not valid input
                bad_input |= waiting_for_delim;
                bad_input |= ct::is_equal<uint8_t>(constant_time_compare(&input[hlen], m_Phash.data(), hlen), false);

                ct::unpoison(input.data(), input.size());
                ct::unpoison(&bad_input, 1);
                ct::unpoison(&delim_idx, 1);

                valid_mask = ~bad_input;

                secure_vector<uint8_t> output(input.begin() + delim_idx + 1, input.end());
                ct::cond_zero_mem(bad_input, output.data(), output.size());

                return output;
            }

            secure_vector<uint8_t> m_Phash;
            std::unique_ptr<HashFunction> m_mgf1_hash;
        };
    }    // namespace crypto3
}    // namespace nil

#endif
