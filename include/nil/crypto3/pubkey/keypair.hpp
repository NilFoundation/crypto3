#ifndef CRYPTO3_KEYPAIR_CHECKS_HPP_
#define CRYPTO3_KEYPAIR_CHECKS_HPP_

#include <nil/crypto3/pubkey/pk_keys.hpp>

namespace nil {
    namespace crypto3 {

        namespace key_pair {

/**
* Tests whether the key is consistent for encryption; whether
* encrypting and then decrypting gives to the original plaintext.
* @param rng the rng to use
* @param private_key the key to test
* @param public_key the key to test
* @param padding the encryption padding method to use
* @return true if consistent otherwise false
*/
            bool encryption_consistency_check(random_number_generator &rng, const private_key_policy &private_key,
                                              const public_key_policy &public_key, const std::string &padding);

/**
* Tests whether the key is consistent for signatures; whether a
* signature can be created and then verified
* @param rng the rng to use
* @param private_key the key to test
* @param public_key the key to test
* @param padding the signature padding method to use
* @return true if consistent otherwise false
*/
            bool signature_consistency_check(random_number_generator &rng, const private_key_policy &private_key,
                                             const public_key_policy &public_key, const std::string &padding);

/**
* Tests whether the key is consistent for encryption; whether
* encrypting and then decrypting gives to the original plaintext.
* @param rng the rng to use
* @param key the key to test
* @param padding the encryption padding method to use
* @return true if consistent otherwise false
*/
            inline bool encryption_consistency_check(random_number_generator &rng, const private_key_policy &key,
                                                     const std::string &padding) {
                return encryption_consistency_check(rng, key, key, padding);
            }

/**
* Tests whether the key is consistent for signatures; whether a
* signature can be created and then verified
* @param rng the rng to use
* @param key the key to test
* @param padding the signature padding method to use
* @return true if consistent otherwise false
*/
            inline bool signature_consistency_check(random_number_generator &rng, const private_key_policy &key,
                                                    const std::string &padding) {
                return signature_consistency_check(rng, key, key, padding);
            }

        }
    }
}

#endif
