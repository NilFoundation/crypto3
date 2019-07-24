#ifndef CRYPTO3_CURVE_25519_HPP
#define CRYPTO3_CURVE_25519_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                void size_check(size_t size, const char *thing) {
                    if (size != 32) {
                        throw decoding_error("Invalid size " + std::to_string(size) + " for Curve25519 " + thing);
                    }
                }

                secure_vector<uint8_t> curve25519(const secure_vector<uint8_t> &secret, const uint8_t pubval[32]) {
                    secure_vector<uint8_t> out(32);
                    curve25519_donna(out.data(), secret.data(), pubval);
                    return out;
                }

            }    // namespace detail
        }        // namespace pubkey

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

            bool check_key(random_number_generator &rng, bool strong) const override {
                return true;    // no tests possible?
            }

            algorithm_identifier get_algorithm_identifier() const override {
                // get_algorithm_identifier::USE_NULL_PARAM puts 0x05 0x00 in parameters
                // We want nothing
                std::vector<uint8_t> empty;
                return algorithm_identifier(oid(), empty);
            }

            std::vector<uint8_t> public_key_bits() const override {
                return m_public;
            }

            std::vector<uint8_t> public_value() const {
                return m_public;
            }

            /**
             * Create a Curve25519 Public Key.
             * @param alg_id the X.509 algorithm identifier
             * @param key_bits DER encoded public key bits
             */
            curve25519_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits) {
                m_public = key_bits;

                size_check(m_public.size(), "public key");
            }

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
            curve25519_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits) {
                ber_decoder(key_bits).decode(m_private, OCTET_STRING).discard_remaining();

                size_check(m_private.size(), "private key");
                m_public.resize(32);
                curve25519_basepoint(m_public.data(), m_private.data());
            }

            /**
             * Generate a private key.
             * @param rng the RNG to use
             */
            explicit curve25519_private_key(random_number_generator &rng) {
                m_private = rng.random_vec(32);
                m_public.resize(32);
                curve25519_basepoint(m_public.data(), m_private.data());
            }

            /**
             * Construct a private key from the specified parameters.
             * @param secret_key the private key
             */
            explicit curve25519_private_key(const secure_vector<uint8_t> &secret_key) {
                if (secret_key.size() != 32) {
                    throw decoding_error("Invalid size for Curve25519 private key");
                }

                m_public.resize(32);
                m_private = secret_key;
                curve25519_basepoint(m_public.data(), m_private.data());
            }

            std::vector<uint8_t> public_value() const override {
                return curve25519_public_key::public_value();
            }

            secure_vector<uint8_t> agree(const uint8_t w[], size_t w_len) const {
                size_check(w_len, "public value");
                return curve25519(m_private, w);
            }

            const secure_vector<uint8_t> &get_x() const {
                return m_private;
            }

            secure_vector<uint8_t> private_key_bits() const override {
                return der_encoder().encode(m_private, OCTET_STRING).get_contents();
            }

            bool check_key(random_number_generator &rng, bool strong) const override {
                std::vector<uint8_t> public_point(32);
                curve25519_basepoint(public_point.data(), m_private.data());
                return public_point == m_public;
            }

            std::unique_ptr<pk_operations::key_agreement>
                create_key_agreement_op(random_number_generator &rng, const std::string &params,
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
        void curve25519_basepoint(uint8_t mypublic[32], const uint8_t secret[32]) {
            const uint8_t basepoint[32] = {9};
            curve25519_donna(mypublic, secret, basepoint);
        }

        namespace pubkey {
            class curve25519 {
            public:
                typedef curve25519_public_key public_key_policy;
                typedef curve25519_private_key private_key_policy;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil
#endif
