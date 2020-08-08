//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_EME_ENCRYPTION_PAD_HPP
#define CRYPTO3_PUBKEY_EME_ENCRYPTION_PAD_HPP

namespace nil {
    namespace crypto3 {
        namespace pkpad {
            template<typename Hash>
            struct eme {
                typedef Hash hash_type;
            };
        }

        class random_number_generator;

        /**
         * Encoding Method for Encryption
         */
        class eme {
        public:
            virtual ~eme() = default;

            /**
             * Return the maximum input size in bytes we can support
             * @param keybits the size of the key in bits
             * @return upper bound of input in bytes
             */
            virtual size_t maximum_input_size(size_t keybits) const = 0;

            /**
             * @brief Encode an input
             * @param in the plaintext
             * @param in_length length of plaintext in bytes
             * @param key_length length of the key in bits
             * @param rng a random number generator
             * @return encoded plaintext
             */
            secure_vector<uint8_t> encode(const uint8_t in[], size_t in_length, size_t key_length,
                                          random_number_generator &rng) const;

            /**
             * @brief Encode an input
             * @param in the plaintext
             * @param key_length length of the key in bits
             * @param rng a random number generator
             * @return encoded plaintext
             */
            secure_vector<uint8_t> encode(const secure_vector<uint8_t> &in, size_t key_length,
                                          random_number_generator &rng) const;

            /**
             * Decode an input
             * @param valid_mask written to specifies if output is valid
             * @param in the encoded plaintext
             * @param in_len length of encoded plaintext in bytes
             * @return bytes of out[] written to along with
             *         validity mask (0xFF if valid, else 0x00)
             */
            virtual secure_vector<uint8_t> unpad(uint8_t &valid_mask, const uint8_t in[], size_t in_len) const = 0;

            /**
             * Encode an input
             * @param in the plaintext
             * @param in_length length of plaintext in bytes
             * @param key_length length of the key in bits
             * @param rng a random number generator
             * @return encoded plaintext
             */
            virtual secure_vector<uint8_t> pad(const uint8_t in[], size_t in_length, size_t key_length,
                                               random_number_generator &rng) const = 0;
        };

        /**
         * Factory method for EME (message-encoding methods for encryption) objects
         * @param algo_spec the name of the EME to create
         * @return pointer to newly allocated object of that type
         */

        eme *get_eme(const std::string &algo_spec);

        eme *get_eme(const std::string &algo_spec) {
#if defined(CRYPTO3_HAS_EME_RAW)
            if (algo_spec == "Raw") {
                return new EME_Raw;
            }
#endif

#if defined(CRYPTO3_HAS_EME_PKCS1v15)
            if (algo_spec == "PKCS1v15" || algo_spec == "eme-PKCS1-v1_5")
                return new EME_PKCS1v15;
#endif

#if defined(CRYPTO3_HAS_EME_OAEP)
            scan_name req(algo_spec);

            if (req.algo_name() == "OAEP" || req.algo_name() == "eme-OAEP" || req.algo_name() == "EME1") {
                if (req.arg_count() == 1 || ((req.arg_count() == 2 || req.arg_count() == 3) && req.arg(1) == "MGF1")) {
                    if (auto hash = HashFunction::create(req.arg(0))) {
                        return new OAEP(hash.release(), req.arg(2, ""));
                    }
                } else if (req.arg_count() == 2 || req.arg_count() == 3) {
                    auto mgf_params = parse_algorithm_name(req.arg(1));

                    if (mgf_params.size() == 2 && mgf_params[0] == "MGF1") {
                        auto hash = HashFunction::create(req.arg(0));
                        auto mgf1_hash = HashFunction::create(mgf_params[1]);

                        if (hash && mgf1_hash) {
                            return new OAEP(hash.release(), mgf1_hash.release(), req.arg(2, ""));
                        }
                    }
                }
            }
#endif

            throw algorithm_not_found(algo_spec);
        }

        /*
         * Encode a message
         */
        secure_vector<uint8_t> eme::encode(const uint8_t msg[], size_t msg_len, size_t key_bits,
                                           random_number_generator &rng) const {
            return pad(msg, msg_len, key_bits, rng);
        }

        /*
         * Encode a message
         */
        secure_vector<uint8_t> eme::encode(const secure_vector<uint8_t> &msg, size_t key_bits,
                                           random_number_generator &rng) const {
            return pad(msg.data(), msg.size(), key_bits, rng);
        }
    }    // namespace crypto3
}    // namespace nil

#endif
