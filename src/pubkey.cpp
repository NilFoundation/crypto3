#include <nil/crypto3/pubkey/pubkey.hpp>
#include <nil/crypto3/asn1/der_enc.hpp>
#include <nil/crypto3/asn1/ber_dec.hpp>
#include <nil/crypto3/multiprecision/bigint/bigint.hpp>
#include <nil/crypto3/pubkey/pk_operations.hpp>
#include <nil/crypto3/utilities/ct_utils.hpp>
#include <nil/crypto3/random/random.hpp>

namespace nil {
    namespace crypto3 {

        secure_vector<uint8_t> pk_decryptor::decrypt(const uint8_t in[], size_t length) const {
            uint8_t valid_mask = 0;

            secure_vector<uint8_t> decoded = do_decrypt(valid_mask, in, length);

            if (!valid_mask) {
                throw decoding_error("Invalid public key ciphertext, cannot isomorphic_decryption_mode");
            }

            return decoded;
        }

        secure_vector<uint8_t> pk_decryptor::decrypt_or_random(const uint8_t in[], size_t length,
                                                               size_t expected_pt_len, random_number_generator &rng,
                                                               const uint8_t required_content_bytes[],
                                                               const uint8_t required_content_offsets[],
                                                               size_t required_contents_length) const {
            const secure_vector<uint8_t> fake_pms = rng.random_vec(expected_pt_len);

            uint8_t valid_mask = 0;
            secure_vector<uint8_t> decoded = do_decrypt(valid_mask, in, length);

            valid_mask &= ct::is_equal(decoded.size(), expected_pt_len);

            decoded.resize(expected_pt_len);

            for (size_t i = 0; i != required_contents_length; ++i) {
                /*
                These values are chosen by the application and for TLS are constants,
                so this early failure via assert is fine since we know 0,1 < 48

                If there is a protocol that has content checks on the key where
                the expected offsets are controllable by the attacker this could
                still leak.

                Alternately could always reduce the offset modulo the length?
                */

                const uint8_t exp = required_content_bytes[i];
                const uint8_t off = required_content_offsets[i];

                BOOST_ASSERT_MSG(off < expected_pt_len, "Offset in range of plaintext");

                valid_mask &= ct::is_equal(decoded[off], exp);
            }

            ct::conditional_copy_mem(valid_mask,
                    /*output*/decoded.data(),
                    /*from0*/decoded.data(),
                    /*from1*/fake_pms.data(), expected_pt_len);

            return decoded;
        }

        secure_vector<uint8_t> pk_decryptor::decrypt_or_random(const uint8_t in[], size_t length,
                                                               size_t expected_pt_len,
                                                               random_number_generator &rng) const {
            return decrypt_or_random(in, length, expected_pt_len, rng, nullptr, nullptr, 0);
        }

        pk_encryptor_eme::pk_encryptor_eme(const public_key_policy &key, random_number_generator &rng,
                                           const std::string &padding, const std::string &provider) {
            m_op = key.create_encryption_op(rng, padding, provider);
            if (!m_op) {
                throw std::invalid_argument("Key type " + key.algo_name() + " does not support encryption");
            }
        }

        pk_encryptor_eme::~pk_encryptor_eme() { /* for unique_ptr */ }

        size_t pk_encryptor_eme::ciphertext_length(size_t ptext_len) const {
            return m_op->ciphertext_length(ptext_len);
        }

        std::vector<uint8_t> pk_encryptor_eme::enc(const uint8_t in[], size_t length,
                                                   random_number_generator &rng) const {
            return unlock(m_op->encrypt(in, length, rng));
        }

        size_t pk_encryptor_eme::maximum_input_size() const {
            return m_op->max_input_bits() / 8;
        }

        pk_decryptor_eme::pk_decryptor_eme(const private_key_policy &key, random_number_generator &rng,
                                           const std::string &padding, const std::string &provider) {
            m_op = key.create_decryption_op(rng, padding, provider);
            if (!m_op) {
                throw std::invalid_argument("Key type " + key.algo_name() + " does not support decryption");
            }
        }

        pk_decryptor_eme::~pk_decryptor_eme() { /* for unique_ptr */ }

        size_t pk_decryptor_eme::plaintext_length(size_t ctext_len) const {
            return m_op->plaintext_length(ctext_len);
        }

        secure_vector<uint8_t> pk_decryptor_eme::do_decrypt(uint8_t &valid_mask, const uint8_t in[],
                                                            size_t in_len) const {
            return m_op->decrypt(valid_mask, in, in_len);
        }

        pk_kem_encryptor::pk_kem_encryptor(const public_key_policy &key, random_number_generator &rng, const std::string &param,
                                           const std::string &provider) {
            m_op = key.create_kem_encryption_op(rng, param, provider);
            if (!m_op) {
                throw std::invalid_argument("Key type " + key.algo_name() + " does not support KEM encryption");
            }
        }

        pk_kem_encryptor::~pk_kem_encryptor() { /* for unique_ptr */ }

        void pk_kem_encryptor::encrypt(secure_vector<uint8_t> &out_encapsulated_key,
                                       secure_vector<uint8_t> &out_shared_key, size_t desired_shared_key_len,
                                       nil::crypto3::random_number_generator &rng, const uint8_t salt[], size_t salt_len) {
            m_op->kem_encrypt(out_encapsulated_key, out_shared_key, desired_shared_key_len, rng, salt, salt_len);
        }

        pk_kem_decryptor::pk_kem_decryptor(const private_key_policy &key, random_number_generator &rng, const std::string &param,
                                           const std::string &provider) {
            m_op = key.create_kem_decryption_op(rng, param, provider);
            if (!m_op) {
                throw std::invalid_argument("Key type " + key.algo_name() + " does not support KEM decryption");
            }
        }

        pk_kem_decryptor::~pk_kem_decryptor() { /* for unique_ptr */ }

        secure_vector<uint8_t> pk_kem_decryptor::decrypt(const uint8_t encap_key[], size_t encap_key_len,
                                                         size_t desired_shared_key_len, const uint8_t salt[],
                                                         size_t salt_len) {
            return m_op->kem_decrypt(encap_key, encap_key_len, desired_shared_key_len, salt, salt_len);
        }

        pk_key_agreement::pk_key_agreement(const private_key_policy &key, random_number_generator &rng, const std::string &kdf,
                                           const std::string &provider) {
            m_op = key.create_key_agreement_op(rng, kdf, provider);
            if (!m_op) {
                throw std::invalid_argument("Key type " + key.algo_name() + " does not support key agreement");
            }
        }

        pk_key_agreement::~pk_key_agreement() { /* for unique_ptr */ }

        pk_key_agreement &pk_key_agreement::operator=(pk_key_agreement &&other) {
            if (this != &other) {
                m_op = std::move(other.m_op);
            }
            return (*this);
        }

        pk_key_agreement::pk_key_agreement(pk_key_agreement &&other) : m_op(std::move(other.m_op)) {
        }

        size_t pk_key_agreement::agreed_value_size() const {
            return m_op->agreed_value_size();
        }

        symmetric_key pk_key_agreement::derive_key(size_t key_len, const uint8_t in[], size_t in_len,
                                                  const uint8_t salt[], size_t salt_len) const {
            return m_op->agree(key_len, in, in_len, salt, salt_len);
        }

        pk_signer::pk_signer(const private_key_policy &key, random_number_generator &rng, const std::string &emsa,
                             signature_format format, const std::string &provider) {
            m_op = key.create_signature_op(rng, emsa, provider);
            if (!m_op) {
                throw std::invalid_argument("Key type " + key.algo_name() + " does not support signature generation");
            }
            m_sig_format = format;
            m_parts = key.message_parts();
            m_part_size = key.message_part_size();
        }

        pk_signer::~pk_signer() { /* for unique_ptr */ }

        void pk_signer::update(const uint8_t in[], size_t length) {
            m_op->update(in, length);
        }

        namespace {

            std::vector<uint8_t> der_encode_signature(const std::vector<uint8_t> &sig, size_t parts, size_t part_size) {
                if (sig.size() % parts != 0 || sig.size() != parts * part_size) {
                    throw encoding_error("Unexpected size for DER signature");
                }

                std::vector<boost::multiprecision::number<Backend, ExpressionTemplates>> sig_parts(parts);
                for (size_t i = 0; i != sig_parts.size(); ++i) {
                    sig_parts[i].binary_decode(&sig[part_size * i], part_size);
                }

                std::vector<uint8_t> output;
                der_encoder(output).start_cons(SEQUENCE).encode_list(sig_parts).end_cons();
                return output;
            }

        }

        size_t pk_signer::signature_length() const {
            if (m_sig_format == IEEE_1363) {
                return m_op->signature_length();
            } else if (m_sig_format == DER_SEQUENCE) {
                // This is a large over-estimate but its easier than computing
                // the exact value
                return m_op->signature_length() + (8 + 4 * m_parts);
            } else {
                throw internal_error("pk_signer: Invalid signature format enum");
            }
        }

        std::vector<uint8_t> pk_signer::signature(random_number_generator &rng) {
            const std::vector<uint8_t> sig = unlock(m_op->sign(rng));

            if (m_sig_format == IEEE_1363) {
                return sig;
            } else if (m_sig_format == DER_SEQUENCE) {
                return der_encode_signature(sig, m_parts, m_part_size);
            } else {
                throw internal_error("pk_signer: Invalid signature format enum");
            }
        }

        pk_verifier::pk_verifier(const public_key_policy &key, const std::string &emsa, signature_format format,
                                 const std::string &provider) {
            m_op = key.create_verification_op(emsa, provider);
            if (!m_op) {
                throw std::invalid_argument("Key type " + key.algo_name() + " does not support signature verification");
            }
            m_sig_format = format;
            m_parts = key.message_parts();
            m_part_size = key.message_part_size();
        }

        pk_verifier::~pk_verifier() { /* for unique_ptr */ }

        void pk_verifier::set_input_format(signature_format format) {
            if (format != IEEE_1363 && m_parts == 1) {
                throw std::invalid_argument("pk_verifier: This algorithm does not support DER encoding");
            }
            m_sig_format = format;
        }

        bool pk_verifier::verify_message(const uint8_t msg[], size_t msg_length, const uint8_t sig[],
                                         size_t sig_length) {
            update(msg, msg_length);
            return check_signature(sig, sig_length);
        }

        void pk_verifier::update(const uint8_t in[], size_t length) {
            m_op->update(in, length);
        }

        bool pk_verifier::check_signature(const uint8_t sig[], size_t length) {
            try {
                if (m_sig_format == IEEE_1363) {
                    return m_op->is_valid_signature(sig, length);
                } else if (m_sig_format == DER_SEQUENCE) {
                    std::vector<uint8_t> real_sig;
                    ber_decoder decoder(sig, length);
                    ber_decoder ber_sig = decoder.start_cons(SEQUENCE);

                    BOOST_ASSERT(m_parts != 0 && m_part_size != 0);

                    size_t count = 0;

                    while (ber_sig.more_items()) {
                        boost::multiprecision::number<Backend, ExpressionTemplates> sig_part;
                        ber_sig.decode(sig_part);
                        real_sig += boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(sig_part, m_part_size);
                        ++count;
                    }

                    if (count != m_parts) {
                        throw decoding_error("pk_verifier: signature size invalid");
                    }

                    const std::vector<uint8_t> reencoded = der_encode_signature(real_sig, m_parts, m_part_size);

                    if (reencoded.size() != length || same_mem(reencoded.data(), sig, reencoded.size()) == false) {
                        throw decoding_error("pk_verifier: signature is not the canonical DER encoding");
                    }

                    return m_op->is_valid_signature(real_sig.data(), real_sig.size());
                } else {
                    throw internal_error("pk_verifier: Invalid signature format enum");
                }
            } catch (std::invalid_argument &) {
                return false;
            }
        }
    }
}