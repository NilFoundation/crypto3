#ifndef CRYPTO3_PUBKEY_PK_KEY_FACTORY_HPP
#define CRYPTO3_PUBKEY_PK_KEY_FACTORY_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>
#include <nil/crypto3/asn1/alg_id.hpp>

#include <memory>

namespace nil {
    namespace crypto3 {

        std::unique_ptr<public_key_policy> load_public_key(const algorithm_identifier &alg_id,
                                                           const std::vector<uint8_t> &key_bits);

        std::unique_ptr<private_key_policy> load_private_key(const algorithm_identifier &alg_id,
                                                             const secure_vector<uint8_t> &key_bits);

        /**
         * Create a new key
         * For ECC keys, algo_params specifies EC group (eg, "secp256r1")
         * For DH/DSA/ElGamal keys, algo_params is DL group (eg, "modp/ietf/2048")
         * For RSA, algo_params is integer keylength
         * For McEliece, algo_params is n,t
         * If algo_params is left empty, suitable default parameters are chosen.
         */

        std::unique_ptr<private_key_policy> create_private_key(const std::string &algo_name,
                                                               random_number_generator &rng,
                                                               const std::string &algo_params = "",
                                                               const std::string &provider = "");

        std::vector<std::string> probe_provider_private_key(const std::string &algo_name,
                                                            const std::vector<std::string> &possible);
    }    // namespace crypto3
}    // namespace nil

#endif
