#ifndef CRYPTO3_CURVE_25519_HPP
#define CRYPTO3_CURVE_25519_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>

namespace nil {
    namespace crypto3 {

        class curve25519_public_key : public virtual public_key_policy {
        public:
            /**
             * Get the OID of the underlying public key scheme.
             * @return oid_t of the public key scheme
             */
            static const oid_t oid() {
                return oid_t({1, 3, 101, 110});
            }

            std::string algo_name() const override {
                return "Curve25519";
            }

            std::size_t estimated_strength() const override {
                return 128;
            }

            std::size_t key_length() const override {
                return 255;
            }

            bool check_key(random_number_generator &rng, bool strong) const override;

            algorithm_identifier get_algorithm_identifier() const override;

            std::vector<uint8_t> public_key_bits() const override;

            std::vector<uint8_t> public_value() const {
                return m_public;
            }

            /**
             * Create a Curve25519 Public Key.
             * @param alg_id the X.509 algorithm identifier
             * @param key_bits DER encoded public key bits
             */
            curve25519_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits);

            /**
             * Create a Curve25519 Public Key.
             * @param pub 32-byte raw public key
             */
            explicit curve25519_public_key(const std::vector<uint8_t> &pub) : m_public(pub) {
            }

            /**
             * Create a Curve25519 Public Key.
             * @param pub 32-byte raw public key
             */
            explicit curve25519_public_key(const secure_vector<uint8_t> &pub) : m_public(pub.begin(), pub.end()) {
            }

        protected:
            curve25519_public_key() = default;

            std::vector<uint8_t> m_public;
        };

        class curve25519_private_key final : public curve25519_public_key,
                                             public virtual private_key_policy,
                                             public virtual pk_key_agreement_key {
        public:
            /**
             * Construct a private key from the specified parameters.
             * @param alg_id the X.509 algorithm identifier
             * @param key_bits PKCS #8 structure
             */
            curve25519_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits);

            /**
             * Generate a private key.
             * @param rng the RNG to use
             */
            explicit curve25519_private_key(random_number_generator &rng);

            /**
             * Construct a private key from the specified parameters.
             * @param secret_key the private key
             */
            explicit curve25519_private_key(const secure_vector<uint8_t> &secret_key);

            std::vector<uint8_t> public_value() const override {
                return curve25519_public_key::public_value();
            }

            secure_vector<uint8_t> agree(const uint8_t w[], size_t w_len) const;

            const secure_vector<uint8_t> &get_x() const {
                return m_private;
            }

            secure_vector<uint8_t> private_key_bits() const override;

            bool check_key(random_number_generator &rng, bool strong) const override;

            std::unique_ptr<pk_operations::key_agreement>
                create_key_agreement_op(random_number_generator &rng,
                                        const std::string &params,
                                        const std::string &provider) const override;

        private:
            secure_vector<uint8_t> m_private;
        };

        /*
         * The types above are just wrappers for curve25519_donna, plus defining
         * encodings for public and private keys.
         */
        void curve25519_donna(uint8_t mypublic[32], const uint8_t secret[32], const uint8_t basepoint[32]);

        /**
         * Exponentiate by the x25519 base point
         * @param mypublic output value
         * @param secret random scalar
         */
        void curve25519_basepoint(uint8_t mypublic[32], const uint8_t secret[32]);

        namespace pubkey {
            class curve25519 {
            public:
                typedef curve25519_public_key_policy public_key_policy;
                typedef curve25519_private_key_policy private_key_policy;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil
#endif
