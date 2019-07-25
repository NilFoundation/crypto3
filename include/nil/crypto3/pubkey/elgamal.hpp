#ifndef CRYPTO3_PUBKEY_ELGAMAL_HPP
#define CRYPTO3_PUBKEY_ELGAMAL_HPP

#include <nil/crypto3/pubkey/dl_group/dl_algorithm.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            /**
             * ElGamal Public Key
             */
            class el_gamal_public_key : public virtual dl_scheme_public_key {
            public:
                /**
                 * Get the OID of the underlying public key scheme.
                 * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 3, 6, 1, 4, 1, 3029, 1, 2, 1});
                }

                std::string algo_name() const override {
                    return "ElGamal";
                }

                dl_group::format group_format() const override {
                    return dl_group::ANSI_X9_42;
                }

                /**
                 * Load a public key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded public key bits
                 */
                el_gamal_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits) :
                    dl_scheme_public_key(alg_id, key_bits, dl_group::ANSI_X9_42) {
                }

                /**
                 * Create a public key.
                 * @param group the underlying DL group
                 * @param y the public value y = g^x mod p
                 */
                el_gamal_public_key(const dl_group &group, const boost::multiprecision::cpp_int &y);

                std::unique_ptr<pk_operations::encryption> create_encryption_op(random_number_generator &rng,
                                                                                const std::string &params,
                                                                                const std::string &provider) const

                    override;

            protected:
                el_gamal_public_key() = default;
            };

            /**
             * ElGamal Private Key
             */
            class el_gamal_private_key final : public el_gamal_public_key, public virtual dl_scheme_private_key {
            public:
                bool check_key(random_number_generator &rng, bool) const override;

                /**
                 * Load a private key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded key bits in ANSI X9.42 format
                 */
                el_gamal_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits);

                /**
                 * Create a private key.
                 * @param rng random number generator to use
                 * @param group the group to be used in the key
                 * @param priv_key the key's secret value (or if zero, generate a new key)
                 */
                el_gamal_private_key(random_number_generator &rng, const dl_group &group,
                                     const boost::multiprecision::cpp_int &priv_key = 0);

                std::unique_ptr<pk_operations::decryption>
                    create_decryption_op(random_number_generator &rng,
                                         const std::string &params,
                                         const std::string &provider) const override;
            };

            class el_gamal {
            public:
                typedef el_gamal_public_key public_key_policy;
                typedef el_gamal_private_key private_key_policy;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
