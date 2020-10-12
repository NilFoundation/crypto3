//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_DLIES_HPP
#define CRYPTO3_PUBKEY_DLIES_HPP

#include <nil/crypto3/pubkey/scheme.hpp>
#include <nil/crypto3/pubkey/dh.hpp>

#include <nil/crypto3/modes/cipher_mode.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename FieldType, typename KeyDerivationFunction, typename MessageAuthenticationCode>
            struct dlies_public_key {
                typedef FieldType field_type;
                typedef KeyDerivationFunction kdf_type;
                typedef MessageAuthenticationCode mac_type;

                typedef typename field_type::value_type value_type;
                typedef typename field_type::number_type number_type;

                constexpr static const std::size_t key_bits = field_type::field_type::modulus_bits;
                typedef typename field_type::value_type key_type;

                constexpr static const std::size_t key_schedule_bits = field_type::field_type::modulus_bits;
                typedef typename field_type::value_type key_schedule_type;

                constexpr static const std::size_t signature_bits = field_type::field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;
            };

            template<typename FieldType, typename KeyDerivationFunction, typename MessageAuthenticationCode>
            struct dlies_private_key {
                typedef FieldType field_type;
                typedef KeyDerivationFunction kdf_type;
                typedef MessageAuthenticationCode mac_type;

                typedef typename field_type::value_type value_type;
                typedef typename field_type::number_type number_type;

                typedef typename field_type::value_type key_type;

                constexpr static const std::size_t key_schedule_bits = field_type::field_type::modulus_bits;
                typedef typename field_type::value_type key_schedule_type;

                constexpr static const std::size_t signature_bits = field_type::field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;
            };

            template<typename FieldType, typename KeyDerivationFunction, typename MessageAuthenticationCode>
            struct dlies {
                typedef FieldType field_type;
                typedef KeyDerivationFunction kdf_type;
                typedef MessageAuthenticationCode mac_type;

                typedef dlies_public_key<field_type, kdf_type, mac_type> public_key_type;
                typedef dlies_private_key<field_type, kdf_type, mac_type> private_key_type;

                constexpr static const std::size_t public_key_bits = public_key_type::key_bits;
                constexpr static const std::size_t private_key_bits = private_key_type::key_bits;
            };

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
            class dlies_decryptor final : public pk_decryptor {
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
                dlies_decryptor(const dh_private_key &own_priv_key, RandomNumberGenerator &rng, kdf *kdf,
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
                dlies_decryptor(const dh_private_key &own_priv_key, RandomNumberGenerator &rng, kdf *kdf,
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

            dlies_encryptor::dlies_encryptor(const dh_private_key &own_priv_key, RandomNumberGenerator &rng, kdf *kdf,
                                             MessageAuthenticationCode *mac, size_t mac_key_length) :
                dlies_encryptor(own_priv_key, rng, kdf, nullptr, 0, mac, mac_key_length) {
            }

            dlies_encryptor::dlies_encryptor(const dh_private_key &own_priv_key, RandomNumberGenerator &rng, kdf *kdf,
                                             cipher_mode *cipher, size_t cipher_key_len, MessageAuthenticationCode *mac,
                                             size_t mac_key_length) :
                m_other_pub_key(),
                m_own_pub_key(own_priv_key.public_value()), m_ka(own_priv_key, rng, "Raw"), m_kdf(kdf),
                m_cipher(cipher), m_cipher_key_len(cipher_key_len), m_mac(mac), m_mac_keylen(mac_key_length),
                m_iv() {BOOST_ASSERT(kdf != nullptr) BOOST_ASSERT(mac != nullptr)}

                std::vector<uint8_t> dlies_encryptor::enc(const uint8_t in[], size_t length,
                                                          RandomNumberGenerator &) const {
                if (m_other_pub_key.empty()) {
                    throw Invalid_State("DLIES: The other key was never set");
                }

                // calculate secret value
                const symmetric_key secret_value = m_ka.derive_key(0, m_other_pub_key);

                // derive secret key from secret value
                const size_t required_key_length = m_cipher ? m_cipher_key_len + m_mac_keylen : length + m_mac_keylen;
                const secure_vector<uint8_t> secret_keys =
                    m_kdf->derive_key(required_key_length, secret_value.bits_of());

                if (secret_keys.size() != required_key_length) {
                    throw Encoding_Error("DLIES: kdf did not provide sufficient output");
                }

                secure_vector<uint8_t> ciphertext(in, in + length);
                const size_t cipher_key_len = m_cipher ? m_cipher_key_len : length;

                if (m_cipher) {
                    symmetric_key enc_key(secret_keys.data(), cipher_key_len);
                    m_cipher->set_key(enc_key);

                    if (m_iv.size()) {
                        m_cipher->start(m_iv.bits_of());
                    }

                    m_cipher->finish(ciphertext);
                } else {
                    xor_buf(ciphertext, secret_keys, cipher_key_len);
                }

                // calculate MAC
                m_mac->set_key(secret_keys.data() + cipher_key_len, m_mac_keylen);
                secure_vector<uint8_t> tag = m_mac->process(ciphertext);

                // out = (ephemeral) public key + ciphertext + tag
                secure_vector<uint8_t> out(m_own_pub_key.size() + ciphertext.size() + tag.size());
                buffer_insert(out, 0, m_own_pub_key);
                buffer_insert(out, 0 + m_own_pub_key.size(), ciphertext);
                buffer_insert(out, 0 + m_own_pub_key.size() + ciphertext.size(), tag);

                return unlock(out);
            }

            /**
             * Return the max size, in bytes, of a message
             * Not_Implemented if DLIES is used in XOR encryption mode
             */
            size_t dlies_encryptor::maximum_input_size() const {
                if (m_cipher) {
                    // no limit in block cipher mode
                    return std::numeric_limits<size_t>::max();
                } else {
                    // No way to determine if the kdf will output enough bits for XORing with the plaintext?!
                    throw Not_Implemented("Not implemented for XOR encryption mode");
                }
            }

            dlies_decryptor::dlies_decryptor(const dh_private_key &own_priv_key, RandomNumberGenerator &rng, kdf *kdf,
                                             cipher_mode *cipher, size_t cipher_key_len, MessageAuthenticationCode *mac,
                                             size_t mac_key_length) :
                m_pub_key_size(own_priv_key.public_value().size()),
                m_ka(own_priv_key, rng, "Raw"), m_kdf(kdf), m_cipher(cipher), m_cipher_key_len(cipher_key_len),
                m_mac(mac), m_mac_keylen(mac_key_length),
                m_iv() {BOOST_ASSERT(kdf != nullptr) BOOST_ASSERT(mac != nullptr)}

                dlies_decryptor::dlies_decryptor(const dh_private_key &own_priv_key, RandomNumberGenerator &rng,
                                                 kdf *kdf, MessageAuthenticationCode *mac, size_t mac_key_length) :
                dlies_decryptor(own_priv_key, rng, kdf, nullptr, 0, mac, mac_key_length) {
            }

            secure_vector<uint8_t> dlies_decryptor::do_decrypt(uint8_t &valid_mask, const uint8_t msg[],
                                                               size_t length) const {
                if (length < m_pub_key_size + m_mac->output_length()) {
                    throw decoding_error("DLIES decryption: ciphertext is too short");
                }

                // calculate secret value
                std::vector<uint8_t> other_pub_key(msg, msg + m_pub_key_size);
                const symmetric_key secret_value = m_ka.derive_key(0, other_pub_key);

                const size_t ciphertext_len = length - m_pub_key_size - m_mac->output_length();
                size_t cipher_key_len = m_cipher ? m_cipher_key_len : ciphertext_len;

                // derive secret key from secret value
                const size_t required_key_length = cipher_key_len + m_mac_keylen;
                secure_vector<uint8_t> secret_keys = m_kdf->derive_key(required_key_length, secret_value.bits_of());

                if (secret_keys.size() != required_key_length) {
                    throw Encoding_Error("DLIES: kdf did not provide sufficient output");
                }

                secure_vector<uint8_t> ciphertext(msg + m_pub_key_size, msg + m_pub_key_size + ciphertext_len);

                // calculate MAC
                m_mac->set_key(secret_keys.data() + cipher_key_len, m_mac_keylen);
                secure_vector<uint8_t> calculated_tag = m_mac->process(ciphertext);

                // calculated tag == received tag ?
                secure_vector<uint8_t> tag(msg + m_pub_key_size + ciphertext_len,
                                           msg + m_pub_key_size + ciphertext_len + m_mac->output_length());

                valid_mask =
                    CT::expand_mask<uint8_t>(constant_time_compare(tag.data(), calculated_tag.data(), tag.size()));

                // isomorphic_decryption_mode
                if (m_cipher) {
                    if (valid_mask) {
                        symmetric_key dec_key(secret_keys.data(), cipher_key_len);
                        m_cipher->set_key(dec_key);

                        try {
                            // the decryption can fail:
                            // e.g. integrity_failure is thrown if GCM is used and the message does not have a valid tag

                            if (m_iv.size()) {
                                m_cipher->start(m_iv.bits_of());
                            }

                            m_cipher->finish(ciphertext);
                        } catch (...) {
                            valid_mask = 0;
                        }

                    } else {
                        return secure_vector<uint8_t>();
                    }
                } else {
                    xor_buf(ciphertext, secret_keys.data(), cipher_key_len);
                }

                return ciphertext;
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
