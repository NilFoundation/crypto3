#include <nil/crypto3/pubkey/pk_ops_impl.hpp>
#include <nil/crypto3/utilities/bit_ops.hpp>
#include <nil/crypto3/random/random.hpp>

namespace nil {
    namespace crypto3 {

        pk_operations::encryption_with_eme::encryption_with_eme(const std::string &eme) {
            m_eme.reset(get_eme(eme));
            if (!m_eme.get()) {
                throw Algorithm_Not_Found(eme);
            }
        }

        size_t pk_operations::encryption_with_eme::max_input_bits() const {
            return 8 * m_eme->maximum_input_size(max_raw_input_bits());
        }

        secure_vector <uint8_t> pk_operations::encryption_with_eme::encrypt(const uint8_t msg[], size_t msg_len,
                                                                     random_number_generator &rng) {
            const size_t max_raw = max_raw_input_bits();
            const std::vector<uint8_t> encoded = unlock(m_eme->encode(msg, msg_len, max_raw, rng));
            return raw_encrypt(encoded.data(), encoded.size(), rng);
        }

        pk_operations::decryption_with_eme::decryption_with_eme(const std::string &eme) {
            m_eme.reset(get_eme(eme));
            if (!m_eme.get()) {
                throw Algorithm_Not_Found(eme);
            }
        }

        secure_vector <uint8_t> pk_operations::decryption_with_eme::decrypt(uint8_t &valid_mask, const uint8_t ciphertext[],
                                                                     size_t ciphertext_len) {
            const secure_vector <uint8_t> raw = raw_decrypt(ciphertext, ciphertext_len);
            return m_eme->unpad(valid_mask, raw.data(), raw.size());
        }

        pk_operations::key_agreement_with_kdf::key_agreement_with_kdf(const std::string &kdf) {
            if (kdf != "Raw") {
                m_kdf.reset(get_kdf(kdf));
            }
        }

        secure_vector <uint8_t> pk_operations::key_agreement_with_kdf::agree(size_t key_len, const uint8_t w[], size_t w_len,
                                                                      const uint8_t salt[], size_t salt_len) {
            secure_vector <uint8_t> z = raw_agree(w, w_len);
            if (m_kdf) {
                return m_kdf->derive_key(key_len, z, salt, salt_len);
            }
            return z;
        }

        pk_operations::signature_with_emsa::signature_with_emsa(const std::string &emsa)
                : signature(), m_emsa(get_emsa(emsa)), m_hash(hash_for_emsa(emsa)), m_prefix_used(false) {
            if (!m_emsa) {
                throw Algorithm_Not_Found(emsa);
            }
        }

        void pk_operations::signature_with_emsa::update(const uint8_t msg[], size_t msg_len) {
            if (has_prefix() && !m_prefix_used) {
                m_prefix_used = true;
                secure_vector <uint8_t> prefix = message_prefix();
                m_emsa->update(prefix.data(), prefix.size());
            }
            m_emsa->update(msg, msg_len);
        }

        secure_vector <uint8_t> pk_operations::signature_with_emsa::sign(random_number_generator &rng) {
            m_prefix_used = false;
            const secure_vector <uint8_t> msg = m_emsa->raw_data();
            const auto padded = m_emsa->encoding_of(msg, this->max_input_bits(), rng);
            return raw_sign(padded.data(), padded.size(), rng);
        }

        pk_operations::verification_with_emsa::verification_with_emsa(const std::string &emsa)
                : verification(), m_emsa(get_emsa(emsa)), m_hash(hash_for_emsa(emsa)), m_prefix_used(false) {
            if (!m_emsa) {
                throw Algorithm_Not_Found(emsa);
            }
        }

        void pk_operations::verification_with_emsa::update(const uint8_t msg[], size_t msg_len) {
            if (has_prefix() && !m_prefix_used) {
                m_prefix_used = true;
                secure_vector <uint8_t> prefix = message_prefix();
                m_emsa->update(prefix.data(), prefix.size());
            }
            m_emsa->update(msg, msg_len);
        }

        bool pk_operations::verification_with_emsa::is_valid_signature(const uint8_t sig[], size_t sig_len) {
            m_prefix_used = false;
            const secure_vector <uint8_t> msg = m_emsa->raw_data();

            if (with_recovery()) {
                secure_vector <uint8_t> output_of_key = verify_mr(sig, sig_len);
                return m_emsa->verify(output_of_key, msg, max_input_bits());
            } else {
                Null_RNG rng;
                secure_vector <uint8_t> encoded = m_emsa->encoding_of(msg, max_input_bits(), rng);
                return verify(encoded.data(), encoded.size(), sig, sig_len);
            }
        }

        void pk_operations::kem_encryption_with_kdf::kem_encrypt(secure_vector <uint8_t> &out_encapsulated_key,
                                                          secure_vector <uint8_t> &out_shared_key,
                                                          size_t desired_shared_key_len,
                                                          nil::crypto3::random_number_generator &rng, const uint8_t salt[],
                                                          size_t salt_len) {
            secure_vector <uint8_t> raw_shared;
            this->raw_kem_encrypt(out_encapsulated_key, raw_shared, rng);

            out_shared_key = m_kdf->derive_key(desired_shared_key_len, raw_shared.data(), raw_shared.size(), salt,
                                               salt_len);
        }

        pk_operations::kem_encryption_with_kdf::kem_encryption_with_kdf(const std::string &kdf) {
            m_kdf.reset(get_kdf(kdf));
        }

        secure_vector <uint8_t> pk_operations::kem_decryption_with_kdf::kem_decrypt(const uint8_t encap_key[], size_t len,
                                                                             size_t desired_shared_key_len,
                                                                             const uint8_t salt[], size_t salt_len) {
            secure_vector <uint8_t> raw_shared = this->raw_kem_decrypt(encap_key, len);

            return m_kdf->derive_key(desired_shared_key_len, raw_shared.data(), raw_shared.size(), salt, salt_len);
        }

        pk_operations::kem_decryption_with_kdf::kem_decryption_with_kdf(const std::string &kdf) {
            m_kdf.reset(get_kdf(kdf));
        }
    }
}