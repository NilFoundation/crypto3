#ifndef CRYPTO3_PK_OPERATION_IMPL_HPP
#define CRYPTO3_PK_OPERATION_IMPL_HPP

#include <nil/crypto3/pubkey/pk_operations.hpp>
#include <nil/crypto3/pk_pad/eme.hpp>
#include <nil/crypto3/pk_pad/emsa.hpp>
#include <nil/crypto3/kdf/kdf.hpp>

namespace nil {
    namespace crypto3 {

        namespace pk_operations {

            class encryption_with_eme : public encryption {
            public:
                size_t max_input_bits() const override;

                secure_vector<uint8_t> encrypt(const uint8_t msg[], size_t msg_len,
                                               random_number_generator &rng) override;

                ~encryption_with_eme() = default;

            protected:
                explicit encryption_with_eme(const std::string &eme);

            private:
                virtual size_t max_raw_input_bits() const = 0;

                virtual secure_vector<uint8_t> raw_encrypt(const uint8_t msg[], size_t len,
                                                           random_number_generator &rng)
                    = 0;

                std::unique_ptr<eme> m_eme;
            };

            class decryption_with_eme : public decryption {
            public:
                secure_vector<uint8_t> decrypt(uint8_t &valid_mask, const uint8_t msg[], size_t msg_len) override;

                ~decryption_with_eme() = default;

            protected:
                explicit decryption_with_eme(const std::string &eme);

            private:
                virtual secure_vector<uint8_t> raw_decrypt(const uint8_t msg[], size_t len) = 0;

                std::unique_ptr<eme> m_eme;
            };

            class verification_with_emsa : public verification {
            public:
                ~verification_with_emsa() = default;

                void update(const uint8_t msg[], size_t msg_len) override;

                bool is_valid_signature(const uint8_t sig[], size_t sig_len) override;

                bool do_check(const secure_vector<uint8_t> &msg, const uint8_t sig[], size_t sig_len);

                std::string hash_for_signature() {
                    return m_hash;
                }

            protected:
                explicit verification_with_emsa(const std::string &emsa);

                /**
                 * Get the maximum message size in bits supported by this public key.
                 * @return maximum message in bits
                 */
                virtual size_t max_input_bits() const = 0;

                /**
                 * @return boolean specifying if this signature scheme uses
                 * a message prefix returned by message_prefix()
                 */
                virtual bool has_prefix() {
                    return false;
                }

                /**
                 * @return the message prefix if this signature scheme uses
                 * a message prefix, signaled via has_prefix()
                 */
                virtual secure_vector<uint8_t> message_prefix() const {
                    throw Exception("No prefix");
                }

                /**
                 * @return boolean specifying if this key type supports message
                 * recovery and thus if you need to call verify() or verify_mr()
                 */
                virtual bool with_recovery() const = 0;

                /*
                 * Perform a signature check operation
                 * @param msg the message
                 * @param msg_len the length of msg in bytes
                 * @param sig the signature
                 * @param sig_len the length of sig in bytes
                 * @returns if signature is a valid one for message
                 */
                virtual bool verify(const uint8_t[], size_t, const uint8_t[], size_t) {
                    throw Invalid_State("Message recovery required");
                }

                /*
                 * Perform a signature operation (with message recovery)
                 * Only call this if with_recovery() returns true
                 * @param msg the message
                 * @param msg_len the length of msg in bytes
                 * @returns recovered message
                 */
                virtual secure_vector<uint8_t> verify_mr(const uint8_t[], size_t) {
                    throw Invalid_State("Message recovery not supported");
                }

                std::unique_ptr<emsa> clone_emsa() const {
                    return std::unique_ptr<emsa>(m_emsa->clone());
                }

            private:
                std::unique_ptr<emsa> m_emsa;
                const std::string m_hash;
                bool m_prefix_used;
            };

            class signature_with_emsa : public signature {
            public:
                void update(const uint8_t msg[], size_t msg_len) override;

                secure_vector<uint8_t> sign(random_number_generator &rng) override;

            protected:
                explicit signature_with_emsa(const std::string &emsa);

                ~signature_with_emsa() = default;

                std::string hash_for_signature() {
                    return m_hash;
                }

                /**
                 * @return boolean specifying if this signature scheme uses
                 * a message prefix returned by message_prefix()
                 */
                virtual bool has_prefix() {
                    return false;
                }

                /**
                 * @return the message prefix if this signature scheme uses
                 * a message prefix, signaled via has_prefix()
                 */
                virtual secure_vector<uint8_t> message_prefix() const {
                    throw Exception("No prefix");
                }

                std::unique_ptr<emsa> clone_emsa() const {
                    return std::unique_ptr<emsa>(m_emsa->clone());
                }

            private:
                /**
                 * Get the maximum message size in bits supported by this public key.
                 * @return maximum message in bits
                 */
                virtual size_t max_input_bits() const = 0;

                bool self_test_signature(const std::vector<uint8_t> &msg, const std::vector<uint8_t> &sig) const;

                virtual secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                                        random_number_generator &rng)
                    = 0;

                std::unique_ptr<emsa> m_emsa;
                const std::string m_hash;
                bool m_prefix_used;
            };

            class key_agreement_with_kdf : public key_agreement {
            public:
                secure_vector<uint8_t> agree(size_t key_len, const uint8_t other_key[], size_t other_key_len,
                                             const uint8_t salt[], size_t salt_len) override;

            protected:
                explicit key_agreement_with_kdf(const std::string &kdf);

                ~key_agreement_with_kdf() = default;

            private:
                virtual secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) = 0;

                std::unique_ptr<kdf> m_kdf;
            };

            class kem_encryption_with_kdf : public kem_encryption {
            public:
                void kem_encrypt(secure_vector<uint8_t> &out_encapsulated_key, secure_vector<uint8_t> &out_shared_key,
                                 size_t desired_shared_key_len, nil::crypto3::random_number_generator &rng,
                                 const uint8_t salt[], size_t salt_len) override;

            protected:
                virtual void raw_kem_encrypt(secure_vector<uint8_t> &out_encapsulated_key,
                                             secure_vector<uint8_t> &raw_shared_key,
                                             nil::crypto3::random_number_generator &rng)
                    = 0;

                explicit kem_encryption_with_kdf(const std::string &kdf);

                ~kem_encryption_with_kdf() = default;

            private:
                std::unique_ptr<kdf> m_kdf;
            };

            class kem_decryption_with_kdf : public kem_decryption {
            public:
                secure_vector<uint8_t> kem_decrypt(const uint8_t encap_key[], size_t len, size_t desired_shared_key_len,
                                                   const uint8_t salt[], size_t salt_len) override;

            protected:
                virtual secure_vector<uint8_t> raw_kem_decrypt(const uint8_t encap_key[], size_t len) = 0;

                explicit kem_decryption_with_kdf(const std::string &kdf);

                ~kem_decryption_with_kdf() = default;

            private:
                std::unique_ptr<kdf> m_kdf;
            };
        }    // namespace pk_operations
    }        // namespace crypto3
}    // namespace nil

#endif
