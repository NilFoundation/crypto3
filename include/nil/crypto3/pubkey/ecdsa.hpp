#ifndef CRYPTO3_ECDSA_KEY_H_
#define CRYPTO3_ECDSA_KEY_H_

#include <nil/crypto3/pubkey/ecc_key.hpp>

namespace nil {
    namespace crypto3 {
/**
* This class represents ECDSA Public Keys.
*/
        class ecdsa_public_key : public virtual ec_public_key {
        public:

            /**
            * Create a public key from a given public point.
            * @param dom_par the domain parameters associated with this key
            * @param public_point the public point defining this key
            */
            ecdsa_public_key(const ec_group &dom_par, const point_gfp &public_point) : ec_public_key(dom_par,
                    public_point) {
            }

            /**
            * Load a public key.
            * @param alg_id the X.509 algorithm identifier
            * @param key_bits DER encoded public key bits
            */
            ecdsa_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits) : ec_public_key(
                    alg_id, key_bits) {
            }

            /**
             * Get the OID of the underlying public key scheme.
             * @return oid_t of the public key scheme
             */
            static const oid_t oid() {
                return oid_t({1, 2, 840, 10045, 2, 1});
            }

            /**
            * Get this keys algorithm name.
            * @result this keys algorithm name ("ECDSA")
            */
            std::string algo_name() const override {
                return "ECDSA";
            }

            size_t message_parts() const override {
                return 2;
            }

            size_t message_part_size() const override {
                return domain().get_order().bytes();

            }

            std::unique_ptr<pk_operations::verification> create_verification_op(const std::string &params,
                                                                                const std::string &provider) const override;

        protected:

            ecdsa_public_key() = default;

        };

/**
* This class represents ECDSA Private Keys
*/
        class ecdsa_private_key final : public ecdsa_public_key, public ec_private_key {
        public:

/**
* Load a private key
* @param alg_id the X.509 algorithm identifier
* @param key_bits ECPrivateKey bits
*/
            ecdsa_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits)
                    : ec_private_key(alg_id, key_bits) {
            }

/**
* Create a private key.
* @param rng a random number generator
* @param domain parameters to used for this key
* @param x the private key (if zero, generate a new random key)
*/
            ecdsa_private_key(random_number_generator &rng, const ec_group &domain,
                              const boost::multiprecision::cpp_int &x = 0) : ec_private_key(rng, domain, x) {
            }

            bool check_key(random_number_generator &rng, bool) const override;

            std::unique_ptr<pk_operations::signature> create_signature_op(random_number_generator &rng,
                                                                          const std::string &params,
                                                                          const std::string &provider) const override;
        };

        class ecdsa {
        public:
            typedef ecdsa_public_key public_key_policy;
            typedef ecdsa_private_key private_key_policy;
        };
    }
}

#endif
