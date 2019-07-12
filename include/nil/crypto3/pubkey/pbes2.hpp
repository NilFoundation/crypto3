#ifndef CRYPTO3_PBE_PKCS_v20_HPP_
#define CRYPTO3_PBE_PKCS_v20_HPP_

#include <nil/crypto3/asn1/alg_id.hpp>

#include <chrono>

namespace nil {
    namespace crypto3 {

        class random_number_generator;

/**
 * @brief Encrypt with PBES2 from PKCS #5 v2.0
 * @param key_bits the input
 * @param passphrase the passphrase to use for encryption
 * @param msec how many milliseconds to run PBKDF2
 * @param cipher specifies the block cipher to use to encrypt
 * @param digest specifies the PRF to use with PBKDF2 (eg "HMAC(SHA-1)")
 * @param rng a random number generator
*/
        std::pair<algorithm_identifier, std::vector<uint8_t>>

        pbes2_encrypt(const secure_vector<uint8_t> &key_bits, const std::string &passphrase,
                      std::chrono::milliseconds msec, const std::string &cipher, const std::string &digest,
                      random_number_generator &rng);

/**
 * @brief Encrypt with PBES2 from PKCS #5 v2.0
 * @param key_bits the input
 * @param passphrase the passphrase to use for encryption
 * @param msec how many milliseconds to run PBKDF2
 * @param out_iterations_if_nonnull if not null, set to the number
 * of PBKDF iterations used
 * @param cipher specifies the block cipher to use to encrypt
 * @param digest specifies the PRF to use with PBKDF2 (eg "HMAC(SHA-1)")
 * @param rng a random number generator
*/
        std::pair<algorithm_identifier, std::vector<uint8_t>>

        pbes2_encrypt_msec(const secure_vector<uint8_t> &key_bits, const std::string &passphrase,
                           std::chrono::milliseconds msec, size_t *out_iterations_if_nonnull, const std::string &cipher,
                           const std::string &digest, random_number_generator &rng);

/**
 * @brief Encrypt with PBES2 from PKCS #5 v2.0
 * @param key_bits the input
 * @param passphrase the passphrase to use for encryption
 * @param iterations how many iterations to run PBKDF2
 * @param cipher specifies the block cipher to use to encrypt
 * @param digest specifies the PRF to use with PBKDF2 (eg "HMAC(SHA-1)")
 * @param rng a random number generator
*/
        std::pair<algorithm_identifier, std::vector<uint8_t>>

        pbes2_encrypt_iter(const secure_vector<uint8_t> &key_bits, const std::string &passphrase, size_t iterations,
                           const std::string &cipher, const std::string &digest, random_number_generator &rng);

/**
 * @brief Decrypt a PKCS #5 v2.0 encrypted stream
 * @param key_bits the input
 * @param passphrase the passphrase to use for decryption
 * @param params the PBES2 parameters
 */
        secure_vector<uint8_t>

        pbes2_decrypt(const secure_vector<uint8_t> &key_bits, const std::string &passphrase,
                      const std::vector<uint8_t> &params);
    }
}

#endif
