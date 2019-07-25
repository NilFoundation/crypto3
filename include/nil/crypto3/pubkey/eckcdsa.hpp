#ifndef CRYPTO3_PUBKEY_ECKCDSA_KEY_HPP
#define CRYPTO3_PUBKEY_ECKCDSA_KEY_HPP

#include <nil/crypto3/pubkey/ecc_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            /**
             * This class represents ECKCDSA public keys.
             */
            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            class eckcdsa_public_key : public virtual ec_public_key<CurveType, NumberType> {
            public:
                /**
                 * Construct a public key from a given public point.
                 * @param dom_par the domain parameters associated with this key
                 * @param public_point the public point defining this key
                 */
                eckcdsa_public_key(const ec_group<CurveType, NumberType> &dom_par,
                                   const point_gfp<CurveType> &public_point) :
                    ec_public_key<CurveType, NumberType>(dom_par, public_point) {
                }

                /**
                 * Load a public key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded public key bits
                 */
                eckcdsa_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits) :
                    ec_public_key<CurveType, NumberType>(alg_id, key_bits) {
                }

                /**
                 * Get the OID of the underlying public key scheme.
                 * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 0, 14888, 3, 0, 5});
                }

                /**
                 * Get this keys algorithm name.
                 * @result this keys algorithm name ("ECGDSA")
                 */
                std::string algo_name() const override {
                    return "ECKCDSA";
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
                eckcdsa_public_key() = default;
            };

            /**
             * This class represents ECKCDSA private keys.
             */
            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            class eckcdsa_private_key : public eckcdsa_public_key<CurveType, NumberType>,
                                        public ec_private_key<CurveType, NumberType> {
            public:
                /**
                 * Load a private key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits ECPrivateKey bits
                 */
                eckcdsa_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits) :
                    ec_private_key<CurveType, NumberType>(alg_id, key_bits, true) {
                }

                /**
                 * Create a private key.
                 * @param rng a random number generator
                 * @param domain parameters to used for this key
                 * @param x the private key (if zero, generate a new random key)
                 */
                eckcdsa_private_key(random_number_generator &rng, const ec_group<CurveType, NumberType> &domain,
                                    const boost::multiprecision::cpp_int &x = 0) :
                    ec_private_key<CurveType, NumberType>(rng, domain, x, true) {
                }

                bool check_key(random_number_generator &rng, bool) const override;

                std::unique_ptr<pk_operations::signature>
                    create_signature_op(random_number_generator &rng,
                                        const std::string &params,
                                        const std::string &provider) const override;
            };

            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            class eckcdsa {
            public:
                typedef eckcdsa_public_key<CurveType, NumberType> public_key_policy;
                typedef eckcdsa_private_key<CurveType, NumberType> private_key_policy;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
