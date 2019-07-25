#ifndef CRYPTO3_PUBKEY_PK_OPERATIONS_HPP
#define CRYPTO3_PUBKEY_PK_OPERATIONS_HPP

/**
 * Ordinary applications should never need to include or use this
 * header. It is exposed only for specialized applications which want
 * to implement new versions of public key crypto without merging them
 * as changes to the library. One actual example of such usage is an
 * application which creates RSA signatures using a custom TPM library.
 * Unless you're doing something like that, you don't need anything
 * here. Instead use pubkey.h which wraps these types safely and
 * provides a stable application-oriented API.
 */

#include <nil/crypto3/pubkey/pk_keys.hpp>
#include <nil/crypto3/utilities/secmem.hpp>

namespace nil {
    namespace crypto3 {

        class random_number_generator;

        class eme;

        class KDF;

        class emsa;

        namespace pk_operations {

            /**
             * Public key encryption interface
             */
            class encryption {
            public:
                virtual secure_vector<uint8_t> encrypt(const uint8_t msg[], size_t msg_len,
                                                       random_number_generator &rng)
                    = 0;

                virtual size_t max_input_bits() const = 0;

                virtual ~encryption() = default;
            };

            /**
             * Public key decryption interface
             */
            class decryption {
            public:
                virtual secure_vector<uint8_t> decrypt(uint8_t &valid_mask, const uint8_t ciphertext[],
                                                       size_t ciphertext_len)
                    = 0;

                virtual ~decryption() = default;
            };

            /**
             * Public key signature verification interface
             */
            class verification {
            public:
                /*
                 * Add more data to the message currently being signed
                 * @param msg the message
                 * @param msg_len the length of msg in bytes
                 */
                virtual void update(const uint8_t msg[], size_t msg_len) = 0;

                /*
                 * Perform a verification operation
                 * @param random a random number generator
                 */
                virtual bool is_valid_signature(const uint8_t sig[], size_t sig_len) = 0;

                virtual ~verification() = default;
            };

            /**
             * Public key signature creation interface
             */
            class signature {
            public:
                /*
                 * Add more data to the message currently being signed
                 * @param msg the message
                 * @param msg_len the length of msg in bytes
                 */
                virtual void update(const uint8_t msg[], size_t msg_len) = 0;

                /*
                 * Perform a signature operation
                 * @param random a random number generator
                 */
                virtual secure_vector<uint8_t> sign(random_number_generator &rng) = 0;

                virtual ~signature() = default;
            };

            /**
             * A generic key agreement operation (eg DH or ECDH)
             */
            class key_agreement {
            public:
                virtual secure_vector<uint8_t> agree(size_t key_len, const uint8_t other_key[], size_t other_key_len,
                                                     const uint8_t salt[], size_t salt_len)
                    = 0;

                virtual ~key_agreement() = default;
            };

            /**
             * KEM (key encapsulation)
             */
            class kem_encryption {
            public:
                virtual void kem_encrypt(secure_vector<uint8_t> &out_encapsulated_key,
                                         secure_vector<uint8_t> &out_shared_key, size_t desired_shared_key_len,
                                         nil::crypto3::random_number_generator &rng, const uint8_t salt[],
                                         size_t salt_len)
                    = 0;

                virtual ~kem_encryption() = default;
            };

            class kem_decryption {
            public:
                virtual secure_vector<uint8_t> kem_decrypt(const uint8_t encap_key[], size_t len,
                                                           size_t desired_shared_key_len, const uint8_t salt[],
                                                           size_t salt_len)
                    = 0;

                virtual ~kem_decryption() = default;
            };
        }    // namespace pk_operations
    }        // namespace crypto3
}    // namespace nil

#endif
