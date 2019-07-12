#include <nil/crypto3/pubkey/keypair.hpp>
#include <nil/crypto3/random/random.hpp>

namespace nil {
    namespace crypto3 {
        namespace key_pair {

/*
* Check an encryption key pair for consistency
*/
            bool encryption_consistency_check(random_number_generator &rng, const private_key_policy &private_key,
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

/*
* Check a signature key pair for consistency
*/
            bool signature_consistency_check(random_number_generator &rng, const private_key_policy &private_key,
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
        }
    }
}
