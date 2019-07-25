#ifndef CRYPTO3_PUBKEY_RSA_HPP
#define CRYPTO3_PUBKEY_RSA_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>

#include <boost/multiprecision/number.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            /**
             * RSA Public Key
             */
            class rsa_public_key : public virtual public_key_policy {
            public:
                /**
                 * Load a public key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded public key bits
                 */
                rsa_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits);

                /**
                 * Create a public key.
                 * @arg n the modulus
                 * @arg e the exponent
                 */
                rsa_public_key(const boost::multiprecision::cpp_int &n, const boost::multiprecision::cpp_int &e) :
                    m_n(n), m_e(e) {
                }

                /**
                 * Get the OID of the underlying public key scheme.
                 * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 2, 840, 113549, 1, 1, 1});
                }

                std::string algo_name() const override {
                    return "RSA";
                }

                bool check_key(random_number_generator &rng, bool) const override;

                algorithm_identifier get_algorithm_identifier() const override;

                std::vector<uint8_t> public_key_bits() const override;

                /**
                 * @return public modulus
                 */
                const boost::multiprecision::cpp_int &get_n() const {
                    return m_n;
                }

                /**
                 * @return public exponent
                 */
                const boost::multiprecision::cpp_int &get_e() const {
                    return m_e;
                }

                size_t key_length() const override;

                size_t estimated_strength() const override;

                std::unique_ptr<pk_operations::encryption>
                    create_encryption_op(random_number_generator &rng,
                                         const std::string &params,
                                         const std::string &provider) const override;

                std::unique_ptr<pk_operations::kem_encryption>
                    create_kem_encryption_op(random_number_generator &rng,
                                             const std::string &params,
                                             const std::string &provider) const override;

                std::unique_ptr<pk_operations::verification>
                    create_verification_op(const std::string &params, const std::string &provider) const override;

            protected:
                rsa_public_key() = default;

                boost::multiprecision::cpp_int m_n, m_e;
            };

            /**
             * RSA Private Key
             */
            class rsa_private_key final : public private_key_policy, public rsa_public_key {
            public:
                /**
                 * Load a private key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits PKCS#1 RSAPrivateKey bits
                 */
                rsa_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits);

                /**
                 * Construct a private key from the specified parameters.
                 * @param p the first prime
                 * @param q the second prime
                 * @param e the exponent
                 * @param d if specified, this has to be d with
                 * exp * d = 1 mod (p - 1, q - 1). Leave it as 0 if you wish to
                 * the constructor to calculate it.
                 * @param n if specified, this must be n = p * q. Leave it as 0
                 * if you wish to the constructor to calculate it.
                 */
                rsa_private_key(const boost::multiprecision::cpp_int &p, const boost::multiprecision::cpp_int &q,
                                const boost::multiprecision::cpp_int &e, const boost::multiprecision::cpp_int &d = 0,
                                const boost::multiprecision::cpp_int &n = 0);

                /**
                 * Create a new private key with the specified bit length
                 * @param rng the random number generator to use
                 * @param bits the desired bit length of the private key
                 * @param exp the public exponent to be used
                 */
                rsa_private_key(random_number_generator &rng, size_t bits, size_t exp = 65537);

                bool check_key(random_number_generator &rng, bool) const override;

                /**
                 * Get the first prime p.
                 * @return prime p
                 */
                const boost::multiprecision::cpp_int &get_p() const {
                    return m_p;
                }

                /**
                 * Get the second prime q.
                 * @return prime q
                 */
                const boost::multiprecision::cpp_int &get_q() const {
                    return m_q;
                }

                /**
                 * Get d with exp * d = 1 mod (p - 1, q - 1).
                 * @return d
                 */
                const boost::multiprecision::cpp_int &get_d() const {
                    return m_d;
                }

                const boost::multiprecision::cpp_int &get_c() const {
                    return m_c;
                }

                const boost::multiprecision::cpp_int &get_d1() const {
                    return m_d1;
                }

                const boost::multiprecision::cpp_int &get_d2() const {
                    return m_d2;
                }

                secure_vector<uint8_t> private_key_bits() const

                    override;

                std::unique_ptr<pk_operations::decryption>
                    create_decryption_op(random_number_generator &rng,
                                         const std::string &params,
                                         const std::string &provider) const override;

                std::unique_ptr<pk_operations::kem_decryption>
                    create_kem_decryption_op(random_number_generator &rng,
                                             const std::string &params,
                                             const std::string &provider) const override;

                std::unique_ptr<pk_operations::signature>
                    create_signature_op(random_number_generator &rng,
                                        const std::string &params,
                                        const std::string &provider) const override;

            private:
                boost::multiprecision::cpp_int m_d, m_p, m_q, m_d1, m_d2, m_c;
            };

            class rsa {
            public:
                typedef rsa_public_key public_key_policy;
                typedef rsa_private_key private_key_policy;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
