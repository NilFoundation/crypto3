#ifndef CRYPTO3_PKCS8_HPP
#define CRYPTO3_PKCS8_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>
#include <nil/crypto3/utilities/exceptions.hpp>
#include <nil/crypto3/utilities/secmem.hpp>

#include <functional>
#include <chrono>
#include <memory>

namespace nil {
    namespace crypto3 {

        class data_source;

        class random_number_generator;

        /**
         * PKCS #8 General Exception
         */
        class pkcs8_exception final : public decoding_error {
        public:
            explicit pkcs8_exception(const std::string &error) : decoding_error("PKCS #8: " + error) {
            }
        };

        /**
         * This namespace contains functions for handling PKCS #8 private keys
         */
        namespace pkcs8 {

            /**
             * BER encode a private key
             * @param key the private key to encode
             * @return BER encoded key
             */

            secure_vector<uint8_t> ber_encode(const private_key_policy &key);

            /**
             * Get a string containing a PEM encoded private key.
             * @param key the key to encode
             * @return encoded key
             */

            std::string pem_encode(const private_key_policy &key);

            /**
             * Encrypt a key using PKCS #8 encryption
             * @param key the key to encode
             * @param rng the rng to use
             * @param pass the password to use for encryption
             * @param msec number of milliseconds to run the password derivation
             * @param pbe_algo the name of the desired password-based encryption
             *        algorithm; if empty ("") a reasonable (portable/secure)
             *        default will be chosen.
             * @return encrypted key in binary BER form
             */

            std::vector<uint8_t> ber_encode(const private_key_policy &key, random_number_generator &rng,
                                            const std::string &pass,
                                            std::chrono::milliseconds msec = std::chrono::milliseconds(300),
                                            const std::string &pbe_algo = "");

            /**
             * Get a string containing a PEM encoded private key, encrypting it with a
             * password.
             * @param key the key to encode
             * @param rng the rng to use
             * @param pass the password to use for encryption
             * @param msec number of milliseconds to run the password derivation
             * @param pbe_algo the name of the desired password-based encryption
             *        algorithm; if empty ("") a reasonable (portable/secure)
             *        default will be chosen.
             * @return encrypted key in PEM form
             */

            std::string pem_encode(const private_key_policy &key, random_number_generator &rng, const std::string &pass,
                                   std::chrono::milliseconds msec = std::chrono::milliseconds(300),
                                   const std::string &pbe_algo = "");

            /**
             * Encrypt a key using PKCS #8 encryption and a fixed iteration count
             * @param key the key to encode
             * @param rng the rng to use
             * @param pass the password to use for encryption
             * @param pbkdf_iter number of interations to run PBKDF2
             * @param cipher if non-empty specifies the cipher to use. CBC and GCM modes
             *   are supported, for example "AES-128/CBC", "AES-256/GCM", "Serpent/CBC".
             *   If empty a suitable default is chosen.
             * @param pbkdf_hash if non-empty specifies the PBKDF hash function to use.
             *   For example "SHA-256" or "SHA-384". If empty a suitable default is chosen.
             * @return encrypted key in binary BER form
             */

            std::vector<uint8_t> ber_encode_encrypted_pbkdf_iter(const private_key_policy &key,
                                                                 random_number_generator &rng, const std::string &pass,
                                                                 size_t pbkdf_iter, const std::string &cipher = "",
                                                                 const std::string &pbkdf_hash = "");

            /**
             * Get a string containing a PEM encoded private key, encrypting it with a
             * password.
             * @param key the key to encode
             * @param rng the rng to use
             * @param pass the password to use for encryption
             * @param pbkdf_iter number of iterations to run PBKDF
             * @param cipher if non-empty specifies the cipher to use. CBC and GCM modes
             *   are supported, for example "AES-128/CBC", "AES-256/GCM", "Serpent/CBC".
             *   If empty a suitable default is chosen.
             * @param pbkdf_hash if non-empty specifies the PBKDF hash function to use.
             *   For example "SHA-256" or "SHA-384". If empty a suitable default is chosen.
             * @return encrypted key in PEM form
             */

            std::string pem_encode_encrypted_pbkdf_iter(const private_key_policy &key, random_number_generator &rng,
                                                        const std::string &pass, size_t pbkdf_iter,
                                                        const std::string &cipher = "",
                                                        const std::string &pbkdf_hash = "");

            /**
             * Encrypt a key using PKCS #8 encryption and a variable iteration count
             * @param key the key to encode
             * @param rng the rng to use
             * @param pass the password to use for encryption
             * @param pbkdf_msec how long to run PBKDF2
             * @param pbkdf_iterations if non-null, set to the number of iterations used
             * @param cipher if non-empty specifies the cipher to use. CBC and GCM modes
             *   are supported, for example "AES-128/CBC", "AES-256/GCM", "Serpent/CBC".
             *   If empty a suitable default is chosen.
             * @param pbkdf_hash if non-empty specifies the PBKDF hash function to use.
             *   For example "SHA-256" or "SHA-384". If empty a suitable default is chosen.
             * @return encrypted key in binary BER form
             */

            std::vector<uint8_t> ber_encode_encrypted_pbkdf_msec(const private_key_policy &key,
                                                                 random_number_generator &rng, const std::string &pass,
                                                                 std::chrono::milliseconds pbkdf_msec,
                                                                 size_t *pbkdf_iterations,
                                                                 const std::string &cipher = "",
                                                                 const std::string &pbkdf_hash = "");

            /**
             * Get a string containing a PEM encoded private key, encrypting it with a
             * password.
             * @param key the key to encode
             * @param rng the rng to use
             * @param pass the password to use for encryption
             * @param pbkdf_msec how long in milliseconds to run PBKDF2
             * @param pbkdf_iterations (output argument) number of iterations of PBKDF
             *  that ended up being used
             * @param cipher if non-empty specifies the cipher to use. CBC and GCM modes
             *   are supported, for example "AES-128/CBC", "AES-256/GCM", "Serpent/CBC".
             *   If empty a suitable default is chosen.
             * @param pbkdf_hash if non-empty specifies the PBKDF hash function to use.
             *   For example "SHA-256" or "SHA-384". If empty a suitable default is chosen.
             * @return encrypted key in PEM form
             */

            std::string pem_encode_encrypted_pbkdf_msec(const private_key_policy &key, random_number_generator &rng,
                                                        const std::string &pass, std::chrono::milliseconds pbkdf_msec,
                                                        size_t *pbkdf_iterations, const std::string &cipher = "",
                                                        const std::string &pbkdf_hash = "");

            /**
             * Load an encrypted key from a data source.
             * @param source the data source providing the encoded key
             * @param rng ignored for compatability
             * @param get_passphrase a function that returns passphrases
             * @return loaded private key object
             */

            private_key_policy *load_key(data_source &source, random_number_generator &rng,
                                         std::function<std::string()> get_passphrase);

            /** Load an encrypted key from a data source.
             * @param source the data source providing the encoded key
             * @param rng ignored for compatability
             * @param pass the passphrase to decrypt the key
             * @return loaded private key object
             */

            private_key_policy *load_key(data_source &source, random_number_generator &rng, const std::string &pass);

            /** Load an unencrypted key from a data source.
             * @param source the data source providing the encoded key
             * @param rng ignored for compatability
             * @return loaded private key object
             */

            private_key_policy *load_key(data_source &source, random_number_generator &rng);

#if defined(CRYPTO3_TARGET_OS_HAS_FILESYSTEM)
            /**
             * Load an encrypted key from a file.
             * @param filename the path to the file containing the encoded key
             * @param random ignored for compatability
             * @param get_passphrase a function that returns passphrases
             * @return loaded private key object
             */
            private_key_policy *load_key(const std::string &filename,
                                         random_number_generator &random,
                                         std::function<std::string()>
                                             get_passphrase);

            /** Load an encrypted key from a file.
             * @param filename the path to the file containing the encoded key
             * @param random ignored for compatability
             * @param pass the passphrase to isomorphic_decryption_mode the key
             * @return loaded private key object
             */
            private_key_policy *load_key(const std::string &filename, random_number_generator &random,
                                         const std::string &pass);

            /** Load an unencrypted key from a file.
             * @param filename the path to the file containing the encoded key
             * @param random ignored for compatability
             * @return loaded private key object
             */
            private_key_policy *load_key(const std::string &filename, random_number_generator &random);
#endif

            /**
             * Copy an existing encoded key object.
             * @param key the key to copy
             * @param rng ignored for compatability
             * @return new copy of the key
             */

            private_key_policy *copy_key(const private_key_policy &key, random_number_generator &rng);

            /**
             * Load an encrypted key from a data source.
             * @param source the data source providing the encoded key
             * @param get_passphrase a function that returns passphrases
             * @return loaded private key object
             */

            std::unique_ptr<private_key_policy> load_key(data_source &source,
                                                         std::function<std::string()> get_passphrase);

            /** Load an encrypted key from a data source.
             * @param source the data source providing the encoded key
             * @param pass the passphrase to decrypt the key
             * @return loaded private key object
             */

            std::unique_ptr<private_key_policy> load_key(data_source &source, const std::string &pass);

            /** Load an unencrypted key from a data source.
             * @param source the data source providing the encoded key
             * @return loaded private key object
             */

            std::unique_ptr<private_key_policy> load_key(data_source &source);

            /**
             * Copy an existing encoded key object.
             * @param key the key to copy
             * @return new copy of the key
             */
            std::unique_ptr<private_key_policy> copy_key(const private_key_policy &key);

        }    // namespace pkcs8
    }        // namespace crypto3
}    // namespace nil

#endif
