//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_SM2_ENC_KEY_HPP
#define CRYPTO3_PUBKEY_SM2_ENC_KEY_HPP

#include <nil/crypto3/pubkey/ecc_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            /**
             * This class represents a public key used for SM2 encryption
             */
            class sm2_encryption_public_key : public virtual ec_public_key {
            public:
                /**
                 * Create a public key from a given public point.
                 * @param dom_par the domain parameters associated with this key
                 * @param public_point the public point defining this key
                 */
                sm2_encryption_public_key(const ec_group &dom_par, const point_gfp &public_point) :
                    ec_public_key(dom_par, public_point) {
                }

                /**
                 * Load a public key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded public key bits
                 */
                sm2_encryption_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits) :
                    ec_public_key(alg_id, key_bits) {
                }

                /**
                 * Get the OID of the underlying public key scheme.
                 * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 2, 156, 10197, 1, 301, 3});
                }

                /**
                 * Get this keys algorithm name.
                 * @result this keys algorithm name
                 */
                std::string algo_name() const override {
                    return "SM2_Enc";
                }

                std::unique_ptr<pk_operations::encryption>
                    create_encryption_op(random_number_generator &rng,
                                         const std::string &params,
                                         const std::string &provider) const override;

            protected:
                sm2_encryption_public_key() = default;
            };

            /**
             * This class represents a private key used for SM2 encryption
             */
            class sm2_encryption_private_key final : public sm2_encryption_public_key, public ec_private_key {
            public:
                /**
                 * Load a private key
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits ECPrivateKey bits
                 */
                sm2_encryption_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits);

                /**
                 * Create a private key.
                 * @param rng a random number generator
                 * @param domain parameters to used for this key
                 * @param x the private key (if zero, generate a new random key)
                 */
                sm2_encryption_private_key(random_number_generator &rng, const ec_group &domain,
                                           const number<Backend, ExpressionTemplates> &x = 0);

                bool check_key(random_number_generator &rng, bool) const override;

                std::unique_ptr<pk_operations::decryption>
                    create_decryption_op(random_number_generator &rng,
                                         const std::string &params,
                                         const std::string &provider) const override;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
