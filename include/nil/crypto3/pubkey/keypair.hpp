#ifndef CRYPTO3_PUBKEY_KEYPAIR_CHECKS_HPP
#define CRYPTO3_PUBKEY_KEYPAIR_CHECKS_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace keypair {
                /**
                 * Tests whether the key is consistent for encryption; whether
                 * encrypting and then decrypting gives to the original plaintext.
                 * @param rng the rng to use
                 * @param private_key the key to test
                 * @param public_key the key to test
                 * @param padding the encryption padding method to use
                 * @return true if consistent otherwise false
                 */
                template<typename UniformRandomGenerator>
                bool encryption_consistency_check(UniformRandomGenerator &rng, const private_key_policy &private_key,
                                                  const public_key_policy &public_key, const std::string &padding) {
                    pk_encryptor_eme encryptor(public_key, rng, padding);
                    pk_decryptor_eme decryptor(private_key, rng, padding);

                    /*
                    Weird corner case, if the key is too small to encipher anything at
                    all. This can happen with very small RSA keys with PSS
                    */
                    if (encryptor.maximum_input_size() == 0) {
                        return true;
                    }

                    std::vector<uint8_t> plaintext = unlock(rng.random_vec(encryptor.maximum_input_size() - 1));

                    std::vector<uint8_t> ciphertext = encryptor.encrypt(plaintext, rng);
                    if (ciphertext == plaintext) {
                        return false;
                    }

                    std::vector<uint8_t> decrypted = unlock(decryptor.decrypt(ciphertext));

                    return (plaintext == decrypted);
                }

                /**
                 * Tests whether the key is consistent for encryption; whether
                 * encrypting and then decrypting gives to the original plaintext.
                 * @param rng the rng to use
                 * @param key the key to test
                 * @param padding the encryption padding method to use
                 * @return true if consistent otherwise false
                 */
                template<typename UniformRandomGenerator>
                inline bool encryption_consistency_check(UniformRandomGenerator &rng, const private_key_policy &key,
                                                         const std::string &padding) {
                    return encryption_consistency_check(rng, key, key, padding);
                }

                /**
                 * Tests whether the key is consistent for signatures; whether a
                 * signature can be created and then verified
                 * @param rng the rng to use
                 * @param private_key the key to test
                 * @param public_key the key to test
                 * @param padding the signature padding method to use
                 * @return true if consistent otherwise false
                 */
                template<typename UniformRandomGenerator>
                bool signature_consistency_check(UniformRandomGenerator &rng, const private_key_policy &private_key,
                                                 const public_key_policy &public_key, const std::string &padding) {
                    pk_signer signer(private_key, rng, padding);
                    pk_verifier verifier(public_key, padding);

                    std::vector<uint8_t> message(32);
                    rng.randomize(message.data(), message.size());

                    std::vector<uint8_t> signature;

                    try {
                        signature = signer.sign_message(message, rng);
                    } catch (Encoding_Error &) {
                        return false;
                    }

                    if (!verifier.verify_message(message, signature)) {
                        return false;
                    }

                    // Now try to check a corrupt signature, ensure it does not succeed
                    ++signature[0];

                    if (verifier.verify_message(message, signature)) {
                        return false;
                    }

                    return true;
                }

                /**
                 * Tests whether the key is consistent for signatures; whether a
                 * signature can be created and then verified
                 * @param rng the rng to use
                 * @param key the key to test
                 * @param padding the signature padding method to use
                 * @return true if consistent otherwise false
                 */
                template<typename UniformRandomGenerator>
                inline bool signature_consistency_check(UniformRandomGenerator &rng, const private_key_policy &key,
                                                        const std::string &padding) {
                    return signature_consistency_check(rng, key, key, padding);
                }

            }    // namespace keypair
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif
