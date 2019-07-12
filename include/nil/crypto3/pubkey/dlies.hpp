#ifndef CRYPTO3_DLIES_HPP_
#define CRYPTO3_DLIES_HPP_

#include <nil/crypto3/pubkey/pubkey.hpp>
#include <nil/crypto3/mac/mac.hpp>
#include <nil/crypto3/kdf/kdf.hpp>
#include <nil/crypto3/pubkey/dh.hpp>
#include <nil/crypto3/modes/cipher_mode.hpp>

namespace nil {
    namespace crypto3 {

/**
* DLIES Encryption
*/
        class dlies_encryptor final : public pk_encryptor {
        public:

            /**
            * Stream mode: use KDF to provide a stream of bytes to xor with the message
            *
            * @param own_priv_key own (ephemeral) DH private key
            * @param rng the RNG to use
            * @param kdf the KDF that should be used
            * @param mac the MAC function that should be used
            * @param mac_key_len key length of the MAC function. Default = 20 bytes
            *
            * output = (ephemeral) public key + ciphertext + tag
            */
            dlies_encryptor(const dh_private_key &own_priv_key, RandomNumberGenerator &rng, kdf *kdf,
                            MessageAuthenticationCode *mac, size_t mac_key_len = 20);

            /**
            * Block cipher mode
            *
            * @param own_priv_key own (ephemeral) DH private key
            * @param rng the RNG to use
            * @param kdf the KDF that should be used
            * @param cipher the block cipher that should be used
            * @param cipher_key_len the key length of the block cipher
            * @param mac the MAC function that should be used
            * @param mac_key_len key length of the MAC function. Default = 20 bytes
            *
            * output = (ephemeral) public key + ciphertext + tag
            */
            dlies_encryptor(const dh_private_key &own_priv_key, RandomNumberGenerator &rng, kdf *kdf,
                            cipher_mode *cipher, size_t cipher_key_len, MessageAuthenticationCode *mac,
                            size_t mac_key_len = 20);

            // Set the other parties public key
            inline void set_other_key(const std::vector<uint8_t> &other_pub_key) {
                m_other_pub_key = other_pub_key;
            }

            /// Set the initialization vector for the data encryption method
            inline void set_initialization_vector(const InitializationVector &iv) {
                m_iv = iv;
            }

        private:

            std::vector<uint8_t> enc(const uint8_t[], size_t, RandomNumberGenerator &) const override;

            size_t maximum_input_size() const override;

            std::vector<uint8_t> m_other_pub_key;
            std::vector<uint8_t> m_own_pub_key;
            pk_key_agreement m_ka;
            std::unique_ptr<kdf> m_kdf;
            std::unique_ptr<cipher_mode> m_cipher;
            const size_t m_cipher_key_len;
            std::unique_ptr<MessageAuthenticationCode> m_mac;
            const size_t m_mac_keylen;
            InitializationVector m_iv;
        };

/**
* DLIES Decryption
*/
        class DLIES_Decryptor final : public pk_decryptor {
        public:

/**
* Stream mode: use KDF to provide a stream of bytes to xor with the message
*
* @param own_priv_key own (ephemeral) DH private key
* @param rng the RNG to use
* @param kdf the KDF that should be used
* @param mac the MAC function that should be used
* @param mac_key_len key length of the MAC function. Default = 20 bytes
*
* input = (ephemeral) public key + ciphertext + tag
*/
            DLIES_Decryptor(const dh_private_key &own_priv_key, RandomNumberGenerator &rng, kdf *kdf,
                            MessageAuthenticationCode *mac, size_t mac_key_len = 20);

/**
* Block cipher mode
*
* @param own_priv_key own (ephemeral) DH private key
* @param rng the RNG to use
* @param kdf the KDF that should be used
* @param cipher the block cipher that should be used
* @param cipher_key_len the key length of the block cipher
* @param mac the MAC function that should be used
* @param mac_key_len key length of the MAC function. Default = 20 bytes
*
* input = (ephemeral) public key + ciphertext + tag
*/
            DLIES_Decryptor(const dh_private_key &own_priv_key, RandomNumberGenerator &rng, kdf *kdf,
                            cipher_mode *cipher, size_t cipher_key_len, MessageAuthenticationCode *mac,
                            size_t mac_key_len = 20);

/// Set the initialization vector for the data decryption method
            inline void set_initialization_vector(const InitializationVector &iv) {
                m_iv = iv;
            }

        private:

            secure_vector<uint8_t> do_decrypt(uint8_t &valid_mask, const uint8_t in[], size_t in_len) const

            override;

            const size_t m_pub_key_size;
            pk_key_agreement m_ka;
            std::unique_ptr<kdf> m_kdf;
            std::unique_ptr<cipher_mode> m_cipher;
            const size_t m_cipher_key_len;
            std::unique_ptr<MessageAuthenticationCode> m_mac;
            const size_t m_mac_keylen;
            InitializationVector m_iv;
        };
    }
}

#endif
