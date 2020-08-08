//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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
            }        // namespace padding
        }            // namespace pubkey

        /*!
         * @brief PSSR aka EMSA4 in IEEE 1363
         * @tparam Hash
         */
        template<typename Hash>
        struct emsa_pssr : public emsa<Hash> {
            template<typename InputIterator1, typename InputIterator2>
            bool verify(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2, InputIterator2 last2,
                        std::size_t key_bits) const {
                size_t salt_size = 0;
                const bool ok = pss_verify(this->hash, first1, last1, first2, last2, key_bits, &salt_size);

                if (required_salt_len && salt_size != m_salt_size) {
                    return false;
                }

                return ok;
            }

            template<typename SinglePassRange1, typename SinglePassRange2>
            bool verify(const SinglePassRange1 &range1, const SinglePassRange2 &range2, std::size_t key_bits) const {
                return verify(boost::begin(range1), boost::end(range1), boost::begin(range2), boost::end(range2), 0);
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
                            const secure_vector<uint8_t> &message_hash, size_t key_bits, size_t *out_salt_size) {
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

        /**
         * PSSR (called EMSA4 in IEEE 1363 and in old versions of the library)
         */
        class PSSR final : public emsa {
        public:
            /**
             * @param hash the hash function to use
             */
            explicit PSSR(HashFunction *hash) :
                m_hash(h), m_salt_size(m_hash->output_length()), m_required_salt_len(false) {
            }

            /**
             * @param hash the hash function to use
             * @param salt_size the size of the salt to use in bytes
             */
            PSSR(HashFunction *hash, size_t salt_size) : m_hash(h), m_salt_size(salt_size), m_required_salt_len(true) {
            }

            emsa *clone() override {
                return new PSSR(m_hash->clone(), m_SALT_SIZE);
            }

            std::string name() const override {
                return "EMSA4(" + m_hash->name() + ",MGF1," + std::to_string(m_salt_size) + ")";
            }

            algorithm_identifier config_for_x509(const private_key_policy &key,
                                                 const std::string &cert_hash_name) const override {
                if (cert_hash_name != m_hash->name()) {
                    throw std::invalid_argument(
                        "Hash function from opts and hash_fn argument"
                        " need to be identical");
                }
                // check that the signature algorithm and the padding scheme fit
                if (!sig_algo_and_pad_ok(key.algo_name(), "EMSA4")) {
                    throw std::invalid_argument(
                        "Encoding scheme with canonical name EMSA4"
                        " not supported for signature algorithm " +
                        key.algo_name());
                }

                algorithm_identifier sig_algo;
                // hardcoded as RSA is the only valid algorithm for EMSA4 at the moment
                sig_algo.oid = oids::lookup("RSA/EMSA4");

                const algorithm_identifier hash_id(cert_hash_name, algorithm_identifier::USE_NULL_PARAM);
                const algorithm_identifier mgf_id("MGF1", hash_id.ber_encode());

                der_encoder(sig_algo.parameters)
                    .start_cons(SEQUENCE)
                    .start_cons(asn1_tag(0), CONTEXT_SPECIFIC)
                    .encode(hash_id)
                    .end_cons()
                    .start_cons(asn1_tag(1), CONTEXT_SPECIFIC)
                    .encode(mgf_id)
                    .end_cons()
                    .start_cons(asn1_tag(2), CONTEXT_SPECIFIC)
                    .encode(m_salt_size)
                    .end_cons()
                    .start_cons(asn1_tag(3),
                                CONTEXT_SPECIFIC)
                    .encode(size_t(1))
                    .end_cons()    // trailer field
                    .end_cons();

                return sig_algo;
            }

        private:
            void update(const uint8_t input[], size_t length) override {
                m_hash->update(input, length);
            }

            secure_vector<uint8_t> raw_data() override {
                return m_hash->final();
            }

            secure_vector<uint8_t> encoding_of(const secure_vector<uint8_t> &msg, size_t output_bits,
                                               random_number_generator &rng) override {
                const secure_vector<uint8_t> salt = rng.random_vec(m_salt_size);
                return pss_encode(*m_hash, msg, salt, output_bits);
            }

            bool verify(const secure_vector<uint8_t> &coded, const secure_vector<uint8_t> &raw,
                        size_t key_bits) override {
                size_t salt_size = 0;
                const bool ok = pss_verify(*m_hash, coded, raw, key_bits, &salt_size);

                if (m_required_salt_len && salt_size != m_salt_size) {
                    return false;
                }

                return ok;
            }

            std::unique_ptr<HashFunction> m_hash;
            size_t m_SALT_SIZE;
        };

        /**
         * PSSR_Raw
         * This accepts a pre-hashed buffer
         */
        class PSSR_Raw final : public emsa {
        public:
            /**
             * @param hash the hash function to use
             */
            explicit PSSR_Raw(HashFunction *hash) :
                m_hash(h), m_salt_size(m_hash->output_length()), m_required_salt_len(false) {
            }

            /**
             * @param hash the hash function to use
             * @param salt_size the size of the salt to use in bytes
             */
            PSSR_Raw(HashFunction *hash, size_t salt_size) :
                m_hash(h), m_salt_size(salt_size), m_required_salt_len(true) {
            }

            emsa *clone() override {
                return new PSSR_Raw(m_hash->clone(), m_SALT_SIZE);
            }

            std::string name() const override {
                return "PSSR_Raw(" + m_hash->name() + ",MGF1," + std::to_string(m_salt_size) + ")";
            }

        private:
            void update(const uint8_t input[], size_t length) override {
                m_msg.insert(m_msg.end(), input, input + length);
            }

            secure_vector<uint8_t> raw_data() override {
                secure_vector<uint8_t> ret;
                std::swap(ret, m_msg);

                if (ret.size() != m_hash->output_length()) {
                    throw encoding_error("PSSR_Raw Bad input length, did not match hash");
                }

                return ret;
            }

            secure_vector<uint8_t> encoding_of(const secure_vector<uint8_t> &msg, size_t output_bits,
                                               random_number_generator &rng) override {
                secure_vector<uint8_t> salt = rng.random_vec(m_salt_size);
                return pss_encode(*m_hash, msg, salt, output_bits);
            }

            bool verify(const secure_vector<uint8_t> &coded, const secure_vector<uint8_t> &raw,
                        size_t key_bits) override {
                size_t salt_size = 0;
                const bool ok = pss_verify(*m_hash, coded, raw, key_bits, &salt_size);

                if (m_required_salt_len && salt_size != m_salt_size) {
                    return false;
                }

                return ok;
            }

            std::unique_ptr<HashFunction> m_hash;
            size_t m_SALT_SIZE;
            secure_vector<uint8_t> m_msg;
        };
    }    // namespace crypto3
}    // namespace nil

#endif
