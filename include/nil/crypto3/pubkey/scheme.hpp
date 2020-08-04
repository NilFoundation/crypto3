//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SCHEME_HPP
#define CRYPTO3_SCHEME_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            /*!
             * @brief
             * @tparam Scheme
             * @tparam Mode
             * @tparam Padding
             */
            template<typename Scheme, typename Mode, typename Padding>
            struct scheme : public Mode::template bind<Scheme, Padding>::type {
                typedef std::size_t size_type;

                typedef Scheme cipher_type;
                typedef Mode mode_type;
                typedef Padding padding_strategy;
            };
        }    // namespace pubkey

        class random_number_generator;

        /**
         * The two types of signature format supported by Botan.
         */
        enum signature_format { IEEE_1363, DER_SEQUENCE };

        /**
         * Public Key Encryptor
         * This is the primary interface for public key encryption
         */
        class pk_encryptor {
        public:
            /**
             * Encrypt a message.
             * @param in the message as a byte array
             * @param length the length of the above byte array
             * @param rng the random number source to use
             * @return encrypted message
             */
            std::vector<uint8_t> encrypt(const uint8_t in[], size_t length, random_number_generator &rng) const {
                return enc(in, length, rng);
            }

            /**
             * Encrypt a message.
             * @param in the message
             * @param rng the random number source to use
             * @return encrypted message
             */
            template<typename Alloc>
            std::vector<uint8_t> encrypt(const std::vector<uint8_t, Alloc> &in, random_number_generator &rng) const {
                return enc(in.data(), in.size(), rng);
            }

            /**
             * Return the maximum allowed message size in bytes.
             * @return maximum message size in bytes
             */
            virtual size_t maximum_input_size() const = 0;

            pk_encryptor() = default;

            virtual ~pk_encryptor() = default;

            pk_encryptor(const pk_encryptor &) = delete;

            pk_encryptor &operator=(const pk_encryptor &) = delete;

        private:
            virtual std::vector<uint8_t> enc(const uint8_t[], size_t, random_number_generator &) const = 0;
        };

        /**
         * Public Key Decryptor
         */
        class pk_decryptor {
        public:
            /**
             * Decrypt a ciphertext, throwing an exception if the input
             * seems to be invalid (eg due to an accidental or malicious
             * error in the ciphertext).
             *
             * @param in the ciphertext as a byte array
             * @param length the length of the above byte array
             * @return decrypted message
             */
            secure_vector<uint8_t> decrypt(const uint8_t in[], size_t length) const;

            /**
             * Same as above, but taking a vector
             * @param in the ciphertext
             * @return decrypted message
             */
            template<typename Alloc>
            secure_vector<uint8_t> decrypt(const std::vector<uint8_t, Alloc> &in) const {
                return decrypt(in.data(), in.size());
            }

            /**
             * Decrypt a ciphertext. If the ciphertext is invalid (eg due to
             * invalid padding) or is not the expected length, instead
             * returns a random string of the expected length. Use to avoid
             * oracle attacks, especially against PKCS #1 v1.5 decryption.
             */
            secure_vector<uint8_t> decrypt_or_random(const uint8_t in[], size_t length, size_t expected_pt_len,
                                                     random_number_generator &rng) const;

            /**
             * Decrypt a ciphertext. If the ciphertext is invalid (eg due to
             * invalid padding) or is not the expected length, instead
             * returns a random string of the expected length. Use to avoid
             * oracle attacks, especially against PKCS #1 v1.5 decryption.
             *
             * Additionally checks (also in const time) that:
             *    contents[required_content_offsets[i]] == required_content_bytes[i]
             * for 0 <= i < required_contents
             *
             * Used for example in TLS, which encodes the client version in
             * the content bytes: if there is any timing variation the version
             * check can be used as an oracle to recover the key.
             */
            secure_vector<uint8_t> decrypt_or_random(const uint8_t in[], size_t length, size_t expected_pt_len,
                                                     random_number_generator &rng,
                                                     const uint8_t required_content_bytes[],
                                                     const uint8_t required_content_offsets[],
                                                     size_t required_contents) const;

            pk_decryptor() = default;

            virtual ~pk_decryptor() = default;

            pk_decryptor(const pk_decryptor &) = delete;

            pk_decryptor &operator=(const pk_decryptor &) = delete;

        private:
            virtual secure_vector<uint8_t> do_decrypt(uint8_t &valid_mask, const uint8_t in[], size_t in_len) const = 0;
        };

        /**
         * Public Key Signer. Use the sign_message() functions for small
         * messages. Use multiple calls update() to process large messages and
         * generate the signature by finally calling signature().
         */
        class pk_signer final {
        public:
            /**
             * Construct a PK Signer.
             * @param key the key to use inside this signer
             * @param rng the random generator to use
             * @param emsa the EMSA to use
             * An example would be "EMSA1(SHA-224)".
             * @param format the signature format to use
             * @param provider the provider to use
             */
            pk_signer(const private_key_policy &key, random_number_generator &rng, const std::string &emsa,
                      signature_format format = IEEE_1363, const std::string &provider = "");

            ~pk_signer();

            pk_signer(const pk_signer &) = delete;

            pk_signer &operator=(const pk_signer &) = delete;

            /**
             * Sign a message all in one go
             * @param in the message to sign as a byte array
             * @param length the length of the above byte array
             * @param rng the rng to use
             * @return signature
             */
            std::vector<uint8_t> sign_message(const uint8_t in[], size_t length, random_number_generator &rng) {
                this->update(in, length);
                return this->signature(rng);
            }

            /**
             * Sign a message.
             * @param in the message to sign
             * @param rng the rng to use
             * @return signature
             */
            std::vector<uint8_t> sign_message(const std::vector<uint8_t> &in, random_number_generator &rng) {
                return sign_message(in.data(), in.size(), rng);
            }

            /**
             * Sign a message.
             * @param in the message to sign
             * @param rng the rng to use
             * @return signature
             */
            std::vector<uint8_t> sign_message(const secure_vector<uint8_t> &in, random_number_generator &rng) {
                return sign_message(in.data(), in.size(), rng);
            }

            /**
             * Add a message part (single byte).
             * @param in the byte to add
             */
            void update(uint8_t in) {
                update(&in, 1);
            }

            /**
             * Add a message part.
             * @param in the message part to add as a byte array
             * @param length the length of the above byte array
             */
            void update(const uint8_t in[], size_t length);

            /**
             * Add a message part.
             * @param in the message part to add
             */
            void update(const std::vector<uint8_t> &in) {
                update(in.data(), in.size());
            }

            /**
             * Add a message part.
             * @param in the message part to add
             */
            void update(const std::string &in) {
                update(cast_char_ptr_to_uint8(in.data()), in.size());
            }

            /**
             * Get the signature of the so far processed message (provided by the
             * calls to update()).
             * @param rng the rng to use
             * @return signature of the total message
             */
            std::vector<uint8_t> signature(random_number_generator &rng);

            /**
             * Set the output format of the signature.
             * @param format the signature format to use
             */
            void set_output_format(signature_format format) {
                m_sig_format = format;
            }

        private:
            std::unique_ptr<pk_operations::signature> m_op;
            signature_format m_sig_format;
            size_t m_parts, m_part_size;
        };

        /**
         * Public Key Verifier. Use the verify_message() functions for small
         * messages. Use multiple calls update() to process large messages and
         * verify the signature by finally calling check_signature().
         */
        class pk_verifier final {
        public:
            /**
             * Construct a PK Verifier.
             * @param pub_key the public key to verify against
             * @param emsa the EMSA to use (eg "EMSA3(SHA-1)")
             * @param format the signature format to use
             * @param provider the provider to use
             */
            pk_verifier(const public_key_policy &pub_key, const std::string &emsa, signature_format format = IEEE_1363,
                        const std::string &provider = "");

            ~pk_verifier();

            pk_verifier &operator=(const pk_verifier &) = delete;

            pk_verifier(const pk_verifier &) = delete;

            /**
             * Verify a signature.
             * @param msg the message that the signature belongs to, as a byte array
             * @param msg_length the length of the above byte array msg
             * @param sig the signature as a byte array
             * @param sig_length the length of the above byte array sig
             * @return true if the signature is valid
             */
            bool verify_message(const uint8_t msg[], size_t msg_length, const uint8_t sig[], size_t sig_length);

            /**
             * Verify a signature.
             * @param msg the message that the signature belongs to
             * @param sig the signature
             * @return true if the signature is valid
             */
            template<typename Alloc, typename Alloc2>
            bool verify_message(const std::vector<uint8_t, Alloc> &msg, const std::vector<uint8_t, Alloc2> &sig) {
                return verify_message(msg.data(), msg.size(), sig.data(), sig.size());
            }

            /**
             * Add a message part (single byte) of the message corresponding to the
             * signature to be verified.
             * @param in the byte to add
             */
            void update(uint8_t in) {
                update(&in, 1);
            }

            /**
             * Add a message part of the message corresponding to the
             * signature to be verified.
             * @param msg_part the new message part as a byte array
             * @param length the length of the above byte array
             */
            void update(const uint8_t msg_part[], size_t length);

            /**
             * Add a message part of the message corresponding to the
             * signature to be verified.
             * @param in the new message part
             */
            void update(const std::vector<uint8_t> &in) {
                update(in.data(), in.size());
            }

            /**
             * Add a message part of the message corresponding to the
             * signature to be verified.
             */
            void update(const std::string &in) {
                update(cast_char_ptr_to_uint8(in.data()), in.size());
            }

            /**
             * Check the signature of the buffered message, i.e. the one build
             * by successive calls to update.
             * @param sig the signature to be verified as a byte array
             * @param length the length of the above byte array
             * @return true if the signature is valid, false otherwise
             */
            bool check_signature(const uint8_t sig[], size_t length);

            /**
             * Check the signature of the buffered message, i.e. the one build
             * by successive calls to update.
             * @param sig the signature to be verified
             * @return true if the signature is valid, false otherwise
             */
            template<typename Alloc>
            bool check_signature(const std::vector<uint8_t, Alloc> &sig) {
                return check_signature(sig.data(), sig.size());
            }

            /**
             * Set the format of the signatures fed to this verifier.
             * @param format the signature format to use
             */
            void set_input_format(signature_format format);

        private:
            std::unique_ptr<pk_operations::verification> m_op;
            signature_format m_sig_format;
            size_t m_parts, m_part_size;
        };

        /**
         * Key used for key agreement
         */
        class pk_key_agreement final {
        public:
            /**
             * Construct a PK Key Agreement.
             * @param key the key to use
             * @param rng the random generator to use
             * @param kdf name of the KDF to use (or 'Raw' for no KDF)
             * @param provider the algo provider to use (or empty for default)
             */
            pk_key_agreement(const private_key_policy &key, random_number_generator &rng, const std::string &kdf,
                             const std::string &provider = "");

            ~pk_key_agreement();

            // For ECIES
            pk_key_agreement &operator=(pk_key_agreement &&);

            pk_key_agreement(pk_key_agreement &&);

            pk_key_agreement &operator=(const pk_key_agreement &) = delete;

            pk_key_agreement(const pk_key_agreement &) = delete;

            /*
             * Perform Key Agreement Operation
             * @param key_len the desired key output size
             * @param in the other parties key
             * @param in_len the length of in in bytes
             * @param params extra derivation params
             * @param params_len the length of params in bytes
             */
            symmetric_key derive_key(size_t key_len, const uint8_t in[], size_t in_len, const uint8_t params[],
                                     size_t params_len) const;

            /*
             * Perform Key Agreement Operation
             * @param key_len the desired key output size
             * @param in the other parties key
             * @param in_len the length of in in bytes
             * @param params extra derivation params
             * @param params_len the length of params in bytes
             */
            symmetric_key derive_key(size_t key_len, const std::vector<uint8_t> &in, const uint8_t params[],
                                     size_t params_len) const {
                return derive_key(key_len, in.data(), in.size(), params, params_len);
            }

            /*
             * Perform Key Agreement Operation
             * @param key_len the desired key output size
             * @param in the other parties key
             * @param in_len the length of in in bytes
             * @param params extra derivation params
             */
            symmetric_key derive_key(size_t key_len, const uint8_t in[], size_t in_len,
                                     const std::string &params = "") const {
                return derive_key(key_len, in, in_len, cast_char_ptr_to_uint8(params.data()), params.length());
            }

            /*
             * Perform Key Agreement Operation
             * @param key_len the desired key output size
             * @param in the other parties key
             * @param params extra derivation params
             */
            symmetric_key derive_key(size_t key_len, const std::vector<uint8_t> &in,
                                     const std::string &params = "") const {
                return derive_key(key_len, in.data(), in.size(), cast_char_ptr_to_uint8(params.data()),
                                  params.length());
            }

        private:
            std::unique_ptr<pk_operations::key_agreement> m_op;
        };

        /**
         * Encryption using a standard message recovery algorithm like RSA or
         * ElGamal, paired with an encoding scheme like OAEP.
         */
        class pk_encryptor_eme final : public pk_encryptor {
        public:
            size_t maximum_input_size() const override;

            /**
             * Construct an instance.
             * @param key the key to use inside the encryptor
             * @param rng the RNG to use
             * @param padding the message encoding scheme to use (eg "OAEP(SHA-256)")
             * @param provider the provider to use
             */
            pk_encryptor_eme(const public_key_policy &key, random_number_generator &rng, const std::string &padding,
                             const std::string &provider = "");

            ~pk_encryptor_eme();

            pk_encryptor_eme &operator=(const pk_encryptor_eme &) = delete;

            pk_encryptor_eme(const pk_encryptor_eme &) = delete;

        private:
            std::vector<uint8_t> enc(const uint8_t[], size_t, random_number_generator &rng) const override;

            std::unique_ptr<pk_operations::encryption> m_op;
        };

        /**
         * Decryption with an MR algorithm and an EME.
         */
        class pk_decryptor_eme final : public pk_decryptor {
        public:
            /**
             * Construct an instance.
             * @param key the key to use inside the decryptor
             * @param rng the random generator to use
             * @param eme the EME to use
             * @param provider the provider to use
             */
            pk_decryptor_eme(const private_key_policy &key, random_number_generator &rng, const std::string &eme,
                             const std::string &provider = "");

            ~pk_decryptor_eme();

            pk_decryptor_eme &operator=(const pk_decryptor_eme &) = delete;

            pk_decryptor_eme(const pk_decryptor_eme &) = delete;

        private:
            secure_vector<uint8_t> do_decrypt(uint8_t &valid_mask, const uint8_t in[], size_t in_len) const override;

            std::unique_ptr<pk_operations::decryption> m_op;
        };

        /**
         * Public Key Key Encapsulation Mechanism Encryption.
         */
        class pk_kem_encryptor final {
        public:
            /**
             * Construct an instance.
             * @param key the key to use inside the encryptor
             * @param rng the RNG to use
             * @param kem_param additional KEM parameters
             * @param provider the provider to use
             */
            pk_kem_encryptor(const public_key_policy &key, random_number_generator &rng,
                             const std::string &kem_param = "", const std::string &provider = "");

            ~pk_kem_encryptor();

            pk_kem_encryptor &operator=(const pk_kem_encryptor &) = delete;

            pk_kem_encryptor(const pk_kem_encryptor &) = delete;

            /**
             * Generate a shared key for data encryption.
             * @param out_encapsulated_key the generated encapsulated key
             * @param out_shared_key the generated shared key
             * @param desired_shared_key_len desired size of the shared key in bytes
             * @param rng the RNG to use
             * @param salt a salt value used in the KDF
             * @param salt_len size of the salt value in bytes
             */
            void encrypt(secure_vector<uint8_t> &out_encapsulated_key, secure_vector<uint8_t> &out_shared_key,
                         size_t desired_shared_key_len, nil::crypto3::random_number_generator &rng,
                         const uint8_t salt[], size_t salt_len);

            /**
             * Generate a shared key for data encryption.
             * @param out_encapsulated_key the generated encapsulated key
             * @param out_shared_key the generated shared key
             * @param desired_shared_key_len desired size of the shared key in bytes
             * @param rng the RNG to use
             * @param salt a salt value used in the KDF
             */
            template<typename Alloc>
            void encrypt(secure_vector<uint8_t> &out_encapsulated_key, secure_vector<uint8_t> &out_shared_key,
                         size_t desired_shared_key_len, nil::crypto3::random_number_generator &rng,
                         const std::vector<uint8_t, Alloc> &salt) {
                this->encrypt(out_encapsulated_key, out_shared_key, desired_shared_key_len, rng, salt.data(),
                              salt.size());
            }

            /**
             * Generate a shared key for data encryption.
             * @param out_encapsulated_key the generated encapsulated key
             * @param out_shared_key the generated shared key
             * @param desired_shared_key_len desired size of the shared key in bytes
             * @param rng the RNG to use
             */
            void encrypt(secure_vector<uint8_t> &out_encapsulated_key, secure_vector<uint8_t> &out_shared_key,
                         size_t desired_shared_key_len, nil::crypto3::random_number_generator &rng) {
                this->encrypt(out_encapsulated_key, out_shared_key, desired_shared_key_len, rng, nullptr, 0);
            }

        private:
            std::unique_ptr<pk_operations::kem_encryption> m_op;
        };

        /**
         * Public Key Key Encapsulation Mechanism Decryption.
         */
        class pk_kem_decryptor final {
        public:
            /**
             * Construct an instance.
             * @param key the key to use inside the decryptor
             * @param rng the RNG to use
             * @param kem_param additional KEM parameters
             * @param provider the provider to use
             */
            pk_kem_decryptor(const private_key_policy &key, random_number_generator &rng,
                             const std::string &kem_param = "", const std::string &provider = "");

            ~pk_kem_decryptor();

            pk_kem_decryptor &operator=(const pk_kem_decryptor &) = delete;

            pk_kem_decryptor(const pk_kem_decryptor &) = delete;

            /**
             * Decrypts the shared key for data encryption.
             * @param encap_key the encapsulated key
             * @param encap_key_len size of the encapsulated key in bytes
             * @param desired_shared_key_len desired size of the shared key in bytes
             * @param salt a salt value used in the KDF
             * @param salt_len size of the salt value in bytes
             * @return the shared data encryption key
             */
            secure_vector<uint8_t> decrypt(const uint8_t encap_key[], size_t encap_key_len,
                                           size_t desired_shared_key_len, const uint8_t salt[], size_t salt_len);

            /**
             * Decrypts the shared key for data encryption.
             * @param encap_key the encapsulated key
             * @param encap_key_len size of the encapsulated key in bytes
             * @param desired_shared_key_len desired size of the shared key in bytes
             * @return the shared data encryption key
             */
            secure_vector<uint8_t> decrypt(const uint8_t encap_key[], size_t encap_key_len,
                                           size_t desired_shared_key_len) {
                return this->decrypt(encap_key, encap_key_len, desired_shared_key_len, nullptr, 0);
            }

            /**
             * Decrypts the shared key for data encryption.
             * @param encap_key the encapsulated key
             * @param desired_shared_key_len desired size of the shared key in bytes
             * @param salt a salt value used in the KDF
             * @return the shared data encryption key
             */
            template<typename Alloc1, typename Alloc2>
            secure_vector<uint8_t> decrypt(const std::vector<uint8_t, Alloc1> &encap_key, size_t desired_shared_key_len,
                                           const std::vector<uint8_t, Alloc2> &salt) {
                return this->decrypt(encap_key.data(), encap_key.size(), desired_shared_key_len, salt.data(),
                                     salt.size());
            }

        private:
            std::unique_ptr<pk_operations::kem_decryption> m_op;
        };

        secure_vector<uint8_t> pk_decryptor::decrypt(const uint8_t in[], size_t length) const {
            uint8_t valid_mask = 0;

            secure_vector<uint8_t> decoded = do_decrypt(valid_mask, in, length);

            if (!valid_mask) {
                throw decoding_error("Invalid public key ciphertext, cannot isomorphic_decryption_mode");
            }

            return decoded;
        }

        secure_vector<uint8_t> pk_decryptor::decrypt_or_random(const uint8_t in[], size_t length,
                                                               size_t expected_pt_len, random_number_generator &rng,
                                                               const uint8_t required_content_bytes[],
                                                               const uint8_t required_content_offsets[],
                                                               size_t required_contents_length) const {
            const secure_vector<uint8_t> fake_pms = rng.random_vec(expected_pt_len);

            uint8_t valid_mask = 0;
            secure_vector<uint8_t> decoded = do_decrypt(valid_mask, in, length);

            valid_mask &= ct::is_equal(decoded.size(), expected_pt_len);

            decoded.resize(expected_pt_len);

            for (size_t i = 0; i != required_contents_length; ++i) {
                /*
                These values are chosen by the application and for TLS are constants,
                so this early failure via assert is fine since we know 0,1 < 48

                If there is a protocol that has content checks on the key where
                the expected offsets are controllable by the attacker this could
                still leak.

                Alternately could always reduce the offset modulo the length?
                */

                const uint8_t exp = required_content_bytes[i];
                const uint8_t off = required_content_offsets[i];

                BOOST_ASSERT_MSG(off < expected_pt_len, "Offset in range of plaintext");

                valid_mask &= ct::is_equal(decoded[off], exp);
            }

            ct::conditional_copy_mem(valid_mask,
                                     /*output*/ decoded.data(),
                                     /*from0*/ decoded.data(),
                                     /*from1*/ fake_pms.data(), expected_pt_len);

            return decoded;
        }

        secure_vector<uint8_t> pk_decryptor::decrypt_or_random(const uint8_t in[], size_t length,
                                                               size_t expected_pt_len,
                                                               random_number_generator &rng) const {
            return decrypt_or_random(in, length, expected_pt_len, rng, nullptr, nullptr, 0);
        }

        pk_encryptor_eme::pk_encryptor_eme(const public_key_policy &key, random_number_generator &rng,
                                           const std::string &padding, const std::string &provider) {
            m_op = key.create_encryption_op(rng, padding, provider);
            if (!m_op) {
                throw std::invalid_argument("Key type " + key.algo_name() + " does not support encryption");
            }
        }

        pk_encryptor_eme::~pk_encryptor_eme() { /* for unique_ptr */
        }

        size_t pk_encryptor_eme::ciphertext_length(size_t ptext_len) const {
            return m_op->ciphertext_length(ptext_len);
        }

        std::vector<uint8_t> pk_encryptor_eme::enc(const uint8_t in[], size_t length,
                                                   random_number_generator &rng) const {
            return unlock(m_op->encrypt(in, length, rng));
        }

        size_t pk_encryptor_eme::maximum_input_size() const {
            return m_op->max_input_bits() / 8;
        }

        pk_decryptor_eme::pk_decryptor_eme(const private_key_policy &key, random_number_generator &rng,
                                           const std::string &padding, const std::string &provider) {
            m_op = key.create_decryption_op(rng, padding, provider);
            if (!m_op) {
                throw std::invalid_argument("Key type " + key.algo_name() + " does not support decryption");
            }
        }

        pk_decryptor_eme::~pk_decryptor_eme() { /* for unique_ptr */
        }

        size_t pk_decryptor_eme::plaintext_length(size_t ctext_len) const {
            return m_op->plaintext_length(ctext_len);
        }

        secure_vector<uint8_t> pk_decryptor_eme::do_decrypt(uint8_t &valid_mask, const uint8_t in[],
                                                            size_t in_len) const {
            return m_op->decrypt(valid_mask, in, in_len);
        }

        pk_kem_encryptor::pk_kem_encryptor(const public_key_policy &key, random_number_generator &rng,
                                           const std::string &param, const std::string &provider) {
            m_op = key.create_kem_encryption_op(rng, param, provider);
            if (!m_op) {
                throw std::invalid_argument("Key type " + key.algo_name() + " does not support KEM encryption");
            }
        }

        pk_kem_encryptor::~pk_kem_encryptor() { /* for unique_ptr */
        }

        void pk_kem_encryptor::encrypt(secure_vector<uint8_t> &out_encapsulated_key,
                                       secure_vector<uint8_t> &out_shared_key, size_t desired_shared_key_len,
                                       nil::crypto3::random_number_generator &rng, const uint8_t salt[],
                                       size_t salt_len) {
            m_op->kem_encrypt(out_encapsulated_key, out_shared_key, desired_shared_key_len, rng, salt, salt_len);
        }

        pk_kem_decryptor::pk_kem_decryptor(const private_key_policy &key, random_number_generator &rng,
                                           const std::string &param, const std::string &provider) {
            m_op = key.create_kem_decryption_op(rng, param, provider);
            if (!m_op) {
                throw std::invalid_argument("Key type " + key.algo_name() + " does not support KEM decryption");
            }
        }

        pk_kem_decryptor::~pk_kem_decryptor() { /* for unique_ptr */
        }

        secure_vector<uint8_t> pk_kem_decryptor::decrypt(const uint8_t encap_key[], size_t encap_key_len,
                                                         size_t desired_shared_key_len, const uint8_t salt[],
                                                         size_t salt_len) {
            return m_op->kem_decrypt(encap_key, encap_key_len, desired_shared_key_len, salt, salt_len);
        }

        pk_key_agreement::pk_key_agreement(const private_key_policy &key, random_number_generator &rng,
                                           const std::string &kdf, const std::string &provider) {
            m_op = key.create_key_agreement_op(rng, kdf, provider);
            if (!m_op) {
                throw std::invalid_argument("Key type " + key.algo_name() + " does not support key agreement");
            }
        }

        pk_key_agreement::~pk_key_agreement() { /* for unique_ptr */
        }

        pk_key_agreement &pk_key_agreement::operator=(pk_key_agreement &&other) {
            if (this != &other) {
                m_op = std::move(other.m_op);
            }
            return (*this);
        }

        pk_key_agreement::pk_key_agreement(pk_key_agreement &&other) : m_op(std::move(other.m_op)) {
        }

        size_t pk_key_agreement::agreed_value_size() const {
            return m_op->agreed_value_size();
        }

        symmetric_key pk_key_agreement::derive_key(size_t key_len, const uint8_t in[], size_t in_len,
                                                   const uint8_t salt[], size_t salt_len) const {
            return m_op->agree(key_len, in, in_len, salt, salt_len);
        }

        pk_signer::pk_signer(const private_key_policy &key, random_number_generator &rng, const std::string &emsa,
                             signature_format format, const std::string &provider) {
            m_op = key.create_signature_op(rng, emsa, provider);
            if (!m_op) {
                throw std::invalid_argument("Key type " + key.algo_name() + " does not support signature generation");
            }
            m_sig_format = format;
            m_parts = key.message_parts();
            m_part_size = key.message_part_size();
        }

        pk_signer::~pk_signer() { /* for unique_ptr */
        }

        void pk_signer::update(const uint8_t in[], size_t length) {
            m_op->update(in, length);
        }

        namespace {

            std::vector<uint8_t> der_encode_signature(const std::vector<uint8_t> &sig, size_t parts, size_t part_size) {
                if (sig.size() % parts != 0 || sig.size() != parts * part_size) {
                    throw encoding_error("Unexpected size for DER signature");
                }

                std::vector<boost::multiprecision::number<Backend, ExpressionTemplates>> sig_parts(parts);
                for (size_t i = 0; i != sig_parts.size(); ++i) {
                    sig_parts[i].binary_decode(&sig[part_size * i], part_size);
                }

                std::vector<uint8_t> output;
                der_encoder(output).start_cons(SEQUENCE).encode_list(sig_parts).end_cons();
                return output;
            }

        }    // namespace

        size_t pk_signer::signature_length() const {
            if (m_sig_format == IEEE_1363) {
                return m_op->signature_length();
            } else if (m_sig_format == DER_SEQUENCE) {
                // This is a large over-estimate but its easier than computing
                // the exact value
                return m_op->signature_length() + (8 + 4 * m_parts);
            } else {
                throw internal_error("pk_signer: Invalid signature format enum");
            }
        }

        std::vector<uint8_t> pk_signer::signature(random_number_generator &rng) {
            const std::vector<uint8_t> sig = unlock(m_op->sign(rng));

            if (m_sig_format == IEEE_1363) {
                return sig;
            } else if (m_sig_format == DER_SEQUENCE) {
                return der_encode_signature(sig, m_parts, m_part_size);
            } else {
                throw internal_error("pk_signer: Invalid signature format enum");
            }
        }

        pk_verifier::pk_verifier(const public_key_policy &key, const std::string &emsa, signature_format format,
                                 const std::string &provider) {
            m_op = key.create_verification_op(emsa, provider);
            if (!m_op) {
                throw std::invalid_argument("Key type " + key.algo_name() + " does not support signature verification");
            }
            m_sig_format = format;
            m_parts = key.message_parts();
            m_part_size = key.message_part_size();
        }

        pk_verifier::~pk_verifier() { /* for unique_ptr */
        }

        void pk_verifier::set_input_format(signature_format format) {
            if (format != IEEE_1363 && m_parts == 1) {
                throw std::invalid_argument("pk_verifier: This algorithm does not support DER encoding");
            }
            m_sig_format = format;
        }

        bool pk_verifier::verify_message(const uint8_t msg[], size_t msg_length, const uint8_t sig[],
                                         size_t sig_length) {
            update(msg, msg_length);
            return check_signature(sig, sig_length);
        }

        void pk_verifier::update(const uint8_t in[], size_t length) {
            m_op->update(in, length);
        }

        bool pk_verifier::check_signature(const uint8_t sig[], size_t length) {
            try {
                if (m_sig_format == IEEE_1363) {
                    return m_op->is_valid_signature(sig, length);
                } else if (m_sig_format == DER_SEQUENCE) {
                    std::vector<uint8_t> real_sig;
                    ber_decoder decoder(sig, length);
                    ber_decoder ber_sig = decoder.start_cons(SEQUENCE);

                    BOOST_ASSERT(m_parts != 0 && m_part_size != 0);

                    size_t count = 0;

                    while (ber_sig.more_items()) {
                        boost::multiprecision::number<Backend, ExpressionTemplates> sig_part;
                        ber_sig.decode(sig_part);
                        real_sig += boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(
                            sig_part, m_part_size);
                        ++count;
                    }

                    if (count != m_parts) {
                        throw decoding_error("pk_verifier: signature size invalid");
                    }

                    const std::vector<uint8_t> reencoded = der_encode_signature(real_sig, m_parts, m_part_size);

                    if (reencoded.size() != length || !same_mem(reencoded.data(), sig, reencoded.size())) {
                        throw decoding_error("pk_verifier: signature is not the canonical DER encoding");
                    }

                    return m_op->is_valid_signature(real_sig.data(), real_sig.size());
                } else {
                    throw internal_error("pk_verifier: Invalid signature format enum");
                }
            } catch (std::invalid_argument &) {
                return false;
            }
        }
    }    // namespace crypto3
}    // namespace nil

#endif
