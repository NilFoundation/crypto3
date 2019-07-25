#ifndef CRYPTO3_PUBKEY_SM2_KEY_HPP
#define CRYPTO3_PUBKEY_SM2_KEY_HPP

#include <nil/crypto3/pubkey/ecc_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            /**
         * This class represents SM2 Signature public keys
             */
            class sm2_signature_public_key : public virtual ec_public_key {
            public:
                /**
             * Create a public key from a given public point.
             * @param dom_par the domain parameters associated with this key
             * @param public_point the public point defining this key
                 */
                sm2_signature_public_key(const ec_group &dom_par, const point_gfp &public_point) :
                    ec_public_key(dom_par, public_point) {
                }

                /**
             * Load a public key.
             * @param alg_id the X.509 algorithm identifier
             * @param key_bits DER encoded public key bits
                 */
                sm2_signature_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits) :
                    ec_public_key(alg_id, key_bits) {
                }

                /**
             * Get the OID of the underlying public key scheme.
             * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 2, 156, 10197, 1, 301, 1});
                }

                /**
             * Get this keys algorithm name.
             * @result this keys algorithm name
                 */
                std::string algo_name() const override {
                    return "SM2_Sig";
                }

                size_t message_parts() const override {
                    return 2;
                }

                size_t message_part_size() const override {
                    return domain().get_order().bytes();
                }

                std::unique_ptr<pk_operations::verification>
                    create_verification_op(const std::string &params, const std::string &provider) const override;

            protected:
                sm2_signature_public_key() = default;
            };

            /**
         * This class represents SM2 Signature private keys
             */
            class sm2_signature_private_key final : public sm2_signature_public_key, public ec_private_key {
            public:
                /**
             * Load a private key
             * @param alg_id the X.509 algorithm identifier
             * @param key_bits ECPrivateKey bits
                 */
                sm2_signature_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits);

                /**
             * Create a private key.
             * @param rng a random number generator
             * @param domain parameters to used for this key
             * @param x the private key (if zero, generate a new random key)
                 */
                sm2_signature_private_key(random_number_generator &rng, const ec_group &domain,
                                          const boost::multiprecision::cpp_int &x = 0);

                bool check_key(random_number_generator &rng, bool) const override;

                std::unique_ptr<pk_operations::signature>
                    create_signature_op(random_number_generator &rng,
                                        const std::string &params,
                                        const std::string &provider) const override;

                const boost::multiprecision::cpp_int &get_da_inv() const {
                    return m_da_inv;
                }

            private:
                boost::multiprecision::cpp_int m_da_inv;
            };

            class HashFunction;

            std::vector<uint8_t> sm2_compute_za(HashFunction &hash, const std::string &user_id, const ec_group &domain,
                                                const point_gfp &pubkey);
        }
    }    // namespace crypto3
}    // namespace nil

#endif
