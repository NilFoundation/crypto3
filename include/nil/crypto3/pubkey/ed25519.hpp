#ifndef CRYPTO3_PUBKEY_ED25519_HPP
#define CRYPTO3_PUBKEY_ED25519_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            class ed25519_public_key : public virtual public_key_policy {
            public:
                /**
                 * Get the OID of the underlying public key scheme.
                 * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 3, 101, 112});
                }

                std::string algo_name() const override {
                    return "Ed25519";
                }

                size_t estimated_strength() const override {
                    return 128;
                }

                size_t key_length() const override {
                    return 255;
                }

                bool check_key(random_number_generator &rng, bool strong) const override;

                algorithm_identifier algorithm_identifier() const override;

                std::vector<uint8_t> public_key_bits() const override;

                /**
                 * Create a Ed25519 Public Key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded public key bits
                 */
                ed25519_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits);

                /**
                 * Create a Ed25519 Public Key.
                 * @param pub 32-byte raw public key
                 */
                explicit ed25519_public_key(const std::vector<uint8_t> &pub) : m_public(pub) {
                }

                /**
                 * Create a Ed25519 Public Key.
                 * @param pub 32-byte raw public key
                 */
                explicit ed25519_public_key(const secure_vector<uint8_t> &pub) : m_public(pub.begin(), pub.end()) {
                }

                std::unique_ptr<pk_operations::verification>
                    create_verification_op(const std::string &params, const std::string &provider) const override;

                const std::vector<uint8_t> &get_public_key() const {
                    return m_public;
                }

            protected:
                ed25519_public_key() = default;

                std::vector<uint8_t> m_public;
            };

            class ed25519_private_key final : public ed25519_public_key, public virtual private_key_policy {
            public:
                /**
                 * Construct a private key from the specified parameters.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits PKCS #8 structure
                 */
                ed25519_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits);

                /**
                 * Generate a private key.
                 * @param rng the RNG to use
                 */
                explicit ed25519_private_key(random_number_generator &rng);

                /**
                 * Construct a private key from the specified parameters.
                 * @param secret_key the private key
                 */
                explicit ed25519_private_key(const secure_vector<uint8_t> &secret_key);

                const secure_vector<uint8_t> &get_private_key() const {
                    return m_private;
                }

                secure_vector<uint8_t> private_key_bits() const override;

                bool check_key(random_number_generator &rng, bool strong) const override;

                std::unique_ptr<pk_operations::signature>
                    create_signature_op(random_number_generator &rng,
                                        const std::string &params,
                                        const std::string &provider) const override;

            private:
                secure_vector<uint8_t> m_private;
            };

            void ed25519_gen_keypair(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]);

            void ed25519_sign(uint8_t sig[64], const uint8_t msg[], size_t msg_len, const uint8_t sk[64]);

            bool ed25519_verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[64], const uint8_t pk[32]);

            class ed25519 {
            public:
                typedef ed25519_public_key public_key_policy;
                typedef ed25519_private_key private_key_policy;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
