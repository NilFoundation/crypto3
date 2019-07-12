#include <nil/crypto3/pubkey/mceies.hpp>
#include <nil/crypto3/modes/aead/aead.hpp>
#include <nil/crypto3/random/random.hpp>
#include <nil/crypto3/pubkey/mceliece.hpp>
#include <nil/crypto3/pubkey/pubkey.hpp>

namespace nil {
    namespace crypto3 {

        namespace {

            secure_vector<uint8_t> aead_key(const secure_vector<uint8_t> &mk, const aead_mode &aead) {
                // Fold the key as required for the AEAD mode in use
                if (aead.valid_keylength(mk.size())) {
                    return mk;
                }

                secure_vector<uint8_t> r(aead.key_spec().maximum_keylength());
                for (size_t i = 0; i != mk.size(); ++i) {
                    r[i % r.size()] ^= mk[i];
                }
                return r;
            }

        }

        secure_vector<uint8_t> mceies_encrypt(const mc_eliece_public_key &pubkey, const uint8_t pt[], size_t pt_len,
                                              const uint8_t ad[], size_t ad_len, random_number_generator &rng,
                                              const std::string &algo) {
            pk_kem_encryptor kem_op(pubkey, rng, "KDF1(SHA-512)");

            secure_vector<uint8_t> mce_ciphertext, mce_key;
            kem_op.encrypt(mce_ciphertext, mce_key, 64, rng);

            const size_t mce_code_bytes = (pubkey.get_code_length() + 7) / 8;

            BOOST_ASSERT_MSG(mce_ciphertext.size() == mce_code_bytes, "Unexpected size");

            std::unique_ptr<aead_mode> aead = aead_mode::create_or_throw(algo, ENCRYPTION);

            const size_t nonce_len = aead->default_nonce_length();

            aead->set_key(aead_key(mce_key, *aead));
            aead->set_associated_data(ad, ad_len);

            const secure_vector<uint8_t> nonce = rng.random_vec(nonce_len);

            secure_vector<uint8_t> msg(mce_ciphertext.size() + nonce.size() + pt_len);
            copy_mem(msg.data(), mce_ciphertext.data(), mce_ciphertext.size());
            copy_mem(msg.data() + mce_ciphertext.size(), nonce.data(), nonce.size());
            copy_mem(msg.data() + mce_ciphertext.size() + nonce.size(), pt, pt_len);

            aead->start(nonce);
            aead->finish(msg, mce_ciphertext.size() + nonce.size());
            return msg;
        }

        secure_vector<uint8_t> mceies_decrypt(const mc_eliece_private_key &privkey, const uint8_t ct[], size_t ct_len,
                                              const uint8_t ad[], size_t ad_len, const std::string &algo) {
            try {
                Null_RNG null_rng;
                pk_kem_decryptor kem_op(privkey, null_rng, "KDF1(SHA-512)");

                const size_t mce_code_bytes = (privkey.get_code_length() + 7) / 8;

                std::unique_ptr<aead_mode> aead = aead_mode::create_or_throw(algo, DECRYPTION);

                const size_t nonce_len = aead->default_nonce_length();

                if (ct_len < mce_code_bytes + nonce_len + aead->tag_size()) {
                    throw Exception("Input message too small to be valid");
                }

                const secure_vector <uint8_t> mce_key = kem_op.decrypt(ct, mce_code_bytes, 64);

                aead->set_key(aead_key(mce_key, *aead));
                aead->set_associated_data(ad, ad_len);

                secure_vector <uint8_t> pt(ct + mce_code_bytes + nonce_len, ct + ct_len);

                aead->start(&ct[mce_code_bytes], nonce_len);
                aead->finish(pt, 0);
                return pt;
            } catch (Integrity_Failure &) {
                throw;
            } catch (std::exception &e) {
                throw Exception("mce_decrypt failed: " + std::string(e.what()));
            }
        }
    }
}
