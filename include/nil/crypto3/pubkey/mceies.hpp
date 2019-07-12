#ifndef CRYPTO3_MCEIES_HPP_
#define CRYPTO3_MCEIES_HPP_

#include <nil/crypto3/utilities/secmem.hpp>

#include <string>

namespace nil {
    namespace crypto3 {

        class random_number_generator;

        class mc_eliece_public_key;

        class mc_eliece_private_key;

/**
* McEliece Integrated Encryption System
* Derive a shared key using MCE KEM and encrypt/authenticate the
* plaintext and AD using AES-256 in OCB mode.
*/
        secure_vector<uint8_t> mceies_encrypt(const mc_eliece_public_key &pubkey, const uint8_t pt[], size_t pt_len,
                                              const uint8_t ad[], size_t ad_len, random_number_generator &rng,
                                              const std::string &aead = "AES-256/OCB");

/**
* McEliece Integrated Encryption System
* Derive a shared key using MCE KEM and decrypt/authenticate the
* ciphertext and AD using AES-256 in OCB mode.
*/
        secure_vector<uint8_t> mceies_decrypt(const mc_eliece_private_key &privkey, const uint8_t ct[], size_t ct_len,
                                              const uint8_t ad[], size_t ad_len,
                                              const std::string &aead = "AES-256/OCB");

    }
}

#endif
