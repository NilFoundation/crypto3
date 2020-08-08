//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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
            }        // namespace padding
        }            // namespace pubkey

        template<typename Hash>
        struct emsa_pkcs1v15_base : public emsa<Hash> {
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
                    buffer_insert(T, P_LENGTH + 2, Hash::policy_type::pkcs_id, Hash::policy_type::pkcs_id.size());
                }

                buffer_insert(T, output_length - message_length, msg.data(), message_length);
                return T;
            }
        };

        /*!
         * @brief * PKCS #1 v1.5 signature padding aka PKCS #1 block type 1 aka EMSA3 from IEEE 1363
         * @tparam Hash
         */
        template<typename Hash>
        struct emsa_pkcs1v15 : public emsa_pkcs1v15_base<Hash> {
            template<typename InputIterator1, typename InputIterator2>
            bool verify(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2, InputIterator2 last2,
                        std::size_t key_bits) const {
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
            bool verify(const SinglePassRange1 &range1, const SinglePassRange2 &range2, std::size_t key_bits) const {
                return verify(boost::begin(range1), boost::end(range1), boost::begin(range2), boost::end(range2),
                              key_bits);
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

        template<typename Hash>
        struct emsa_pkcs1v15_raw : public emsa_pkcs1v15_base<Hash> {
            template<typename InputIterator1, typename InputIterator2>
            bool verify(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2, InputIterator2 last2,
                        std::size_t key_bits) const {
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
            bool verify(const SinglePassRange1 &range1, const SinglePassRange2 &range2, std::size_t key_bits) const {
                return verify(boost::begin(range1), boost::end(range1), boost::begin(range2), boost::end(range2), 0);
            }
        };

        /**
         * PKCS #1 v1.5 signature padding
         * aka PKCS #1 block type 1
         * aka EMSA3 from IEEE 1363
         */
        class EMSA_PKCS1v15 final : public emsa {
        public:
            /**
             * @param hash the hash function to use
             */
            explicit EMSA_PKCS1v15(HashFunction *hash) : m_hash(hash) {
                m_hash_id = pkcs_hash_id(m_hash->name());
            }

            emsa *clone() override {
                return new EMSA_PKCS1v15(m_hash->clone());
            }

            void update(const uint8_t[], size_t) override {
                m_hash->update(input, length);
            }

            secure_vector<uint8_t> raw_data() override {
                return m_hash->final();
            }

            secure_vector<uint8_t> encoding_of(const secure_vector<uint8_t> &, size_t,
                                               random_number_generator &rng) override {
                if (msg.size() != m_hash->output_length()) {
                    throw encoding_error("EMSA_PKCS1v15::encoding_of: Bad input length");
                }

                return emsa3_encoding(msg, output_bits, m_hash_id.data(), m_hash_id.size());
            }

            bool verify(const secure_vector<uint8_t> &, const secure_vector<uint8_t> &, size_t) override {
                if (raw.size() != m_hash->output_length()) {
                    return false;
                }

                try {
                    return (coded == emsa3_encoding(raw, key_bits, m_hash_id.data(), m_hash_id.size()));
                } catch (...) {
                    return false;
                }
            }

            std::string name() const override {
                return "EMSA3(" + m_hash->name() + ")";
            }

            algorithm_identifier config_for_x509(const private_key_policy &key,
                                                 const std::string &cert_hash_name) const override {
                if (cert_hash_name != m_hash->name()) {
                    throw std::invalid_argument("Hash function from opts and hash_fn argument"
                                                " need to be identical");
                }
                // check that the signature algorithm and the padding scheme fit
                if (!sig_algo_and_pad_ok(key.algo_name(), "EMSA3")) {
                    throw std::invalid_argument("Encoding scheme with canonical name EMSA3"
                                                " not supported for signature algorithm " + key.algo_name());
                }


                algorithm_identifier sig_algo;
                sig_algo.oid = oids::lookup(key.algo_name() + "/" + name());
                // for RSA PKCSv1.5 parameters "SHALL" be NULL as configured by
                // rsa_public_key::get_algorithm_identifier()
                sig_algo.parameters = key.algorithm_identifier().parameters;
                return sig_algo;
            }

        private:
            std::unique_ptr<HashFunction> m_hash;
            std::vector<uint8_t> m_hash_id;
        };

        /**
         * EMSA_PKCS1v15_Raw which is EMSA_PKCS1v15 without a hash or digest id
         * (which according to QCA docs is "identical to PKCS#11's CKM_RSA_PKCS
         * mechanism", something I have not confirmed)
         */
        class EMSA_PKCS1v15_Raw final : public emsa {
        public:
            emsa *clone() override {
                return new EMSA_PKCS1v15_Raw();
            }

            void update(const uint8_t[], size_t) override {
                m_message += std::make_pair(input, length);
            }

            secure_vector<uint8_t> raw_data() override {
                secure_vector<uint8_t> ret;
                std::swap(ret, m_message);

                if (m_hash_output_len > 0 && ret.size() != m_hash_output_len) {
                    throw encoding_error("EMSA_PKCS1v15_Raw::encoding_of: Bad input length");
                }

                return ret;
            }

            secure_vector<uint8_t> encoding_of(const secure_vector<uint8_t> &, size_t,
                                               random_number_generator &rng) override {
                return emsa3_encoding(msg, output_bits, m_hash_id.data(), m_hash_id.size());
            }

            bool verify(const secure_vector<uint8_t> &, const secure_vector<uint8_t> &, size_t) override {
                if (m_hash_output_len > 0 && raw.size() != m_hash_output_len) {
                    return false;
                }

                try {
                    return (coded == emsa3_encoding(raw, key_bits, m_hash_id.data(), m_hash_id.size()));
                } catch (...) {
                    return false;
                }
            }

            /**
             * @param hash_algo if non-empty, the digest id for that hash is
             * included in the signature.
             */
            EMSA_PKCS1v15_Raw(const std::string &hash_algo = "") {
                if (!hash_algo.empty()) {
                    m_hash_id = pkcs_hash_id(hash_algo);
                    std::unique_ptr<HashFunction> hash(HashFunction::create_or_throw(hash_algo));
                    m_hash_name = hash->name();
                    m_hash_output_len = hash->output_length();
                } else {
                    m_hash_output_len = 0;
                }
            }

            std::string name() const override {
                if (m_hash_name.empty()) {
                    return "EMSA3(Raw)";
                } else {
                    return "EMSA3(Raw," + m_hash_name + ")";
                }
            }

        private:
            size_t m_hash_output_len = 0;
            std::string m_hash_name;
            std::vector<uint8_t> m_hash_id;
            secure_vector<uint8_t> m_message;
        };
    }    // namespace crypto3
}    // namespace nil

#endif
