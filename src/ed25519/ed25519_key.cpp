#include <nil/crypto3/pubkey/ed25519.hpp>
#include <nil/crypto3/pubkey/pk_ops_impl.hpp>
#include <nil/crypto3/asn1/ber_dec.hpp>
#include <nil/crypto3/asn1/der_enc.hpp>
#include <nil/crypto3/random/random.hpp>

namespace nil {
    namespace crypto3 {

        algorithm_identifier Ed25519_PublicKey::algorithm_identifier() const {
            // algorithm_identifier::USE_NULL_PARAM puts 0x05 0x00 in parameters
            // We want nothing
            std::vector<uint8_t> empty;
            return algorithm_identifier(get_oid(), empty);
        }

        bool Ed25519_PublicKey::check_key(RandomNumberGenerator &, bool) const {
            return true; // no tests possible?
            // TODO could check cofactor
        }

        Ed25519_PublicKey::ed25519_public_key(const algorithm_identifier &, const std::vector<uint8_t> &key_bits) {
            m_public = key_bits;

            if (m_public.size() != 32) {
                throw decoding_error("Invalid size for Ed25519 public key");
            }
        }

        std::vector<uint8_t> Ed25519_PublicKey::public_key_bits() const {
            return m_public;
        }

        Ed25519_PrivateKey::ed25519_private_key(const secure_vector <uint8_t> &secret_key) {
            if (secret_key.size() == 64) {
                m_private = secret_key;
                m_public.assign(&m_private[32], &m_private[64]);
            } else if (secret_key.size() == 32) {
                m_public.resize(32);
                m_private.resize(64);
                ed25519_gen_keypair(m_public.data(), m_private.data(), secret_key.data());
            } else {
                throw decoding_error("Invalid size for Ed25519 private key");
            }
        }

        Ed25519_PrivateKey::ed25519_private_key(RandomNumberGenerator &rng) {
            const secure_vector <uint8_t> seed = rng.random_vec(32);
            m_public.resize(32);
            m_private.resize(64);
            ed25519_gen_keypair(m_public.data(), m_private.data(), seed.data());
        }

        Ed25519_PrivateKey::ed25519_private_key(const algorithm_identifier &, const secure_vector <uint8_t> &key_bits) {
            secure_vector <uint8_t> bits;
            ber_decoder(key_bits).decode(bits, OCTET_STRING).discard_remaining();

            if (bits.size() != 32) {
                throw decoding_error("Invalid size for Ed25519 private key");
            }
            m_public.resize(32);
            m_private.resize(64);
            ed25519_gen_keypair(m_public.data(), m_private.data(), bits.data());
        }

        secure_vector <uint8_t> Ed25519_PrivateKey::private_key_bits() const {
            secure_vector <uint8_t> bits(&m_private[0], &m_private[32]);
            return der_encoder().encode(bits, OCTET_STRING).get_contents();
        }

        bool Ed25519_PrivateKey::check_key(RandomNumberGenerator &, bool) const {
            return true; // ???
        }

        namespace {

/**
* Ed25519 verifying operation
*/
            class Ed25519_Pure_Verify_Operation final : public pk_operations::verification {
            public:
                Ed25519_Pure_Verify_Operation(const Ed25519_PublicKey &key) : m_key(key) {
                }

                void update(const uint8_t msg[], size_t msg_len) override {
                    m_msg.insert(m_msg.end(), msg, msg + msg_len);
                }

                bool is_valid_signature(const uint8_t sig[], size_t sig_len) override {
                    if (sig_len != 64) {
                        return false;
                    }
                    const bool ok = ed25519_verify(m_msg.data(), m_msg.size(), sig, m_key.get_public_key().data());
                    m_msg.clear();
                    return ok;
                }

            private:
                std::vector<uint8_t> m_msg;
                const Ed25519_PublicKey &m_key;
            };

/**
* Ed25519 verifying operation with pre-hash
*/
            class Ed25519_Hashed_Verify_Operation final : public pk_operations::verification {
            public:
                Ed25519_Hashed_Verify_Operation(const Ed25519_PublicKey &key, const std::string &hash) : m_key(key) {
                    m_hash = HashFunction::create_or_throw(hash);
                }

                void update(const uint8_t msg[], size_t msg_len) override {
                    m_hash->update(msg, msg_len);
                }

                bool is_valid_signature(const uint8_t sig[], size_t sig_len) override {
                    if (sig_len != 64) {
                        return false;
                    }
                    std::vector<uint8_t> msg_hash(m_hash->output_length());
                    m_hash->final(msg_hash.data());
                    return ed25519_verify(msg_hash.data(), msg_hash.size(), sig, m_key.get_public_key().data());
                }

            private:
                std::unique_ptr<HashFunction> m_hash;
                const Ed25519_PublicKey &m_key;
            };

/**
* Ed25519 signing operation ('pure' - signs message directly)
*/
            class Ed25519_Pure_Sign_Operation final : public pk_operations::signature {
            public:
                Ed25519_Pure_Sign_Operation(const Ed25519_PrivateKey &key) : m_key(key) {
                }

                void update(const uint8_t msg[], size_t msg_len) override {
                    m_msg.insert(m_msg.end(), msg, msg + msg_len);
                }

                secure_vector <uint8_t> sign(RandomNumberGenerator &) override {
                    secure_vector <uint8_t> sig(64);
                    ed25519_sign(sig.data(), m_msg.data(), m_msg.size(), m_key.get_private_key().data());
                    m_msg.clear();
                    return sig;
                }

            private:
                std::vector<uint8_t> m_msg;
                const Ed25519_PrivateKey &m_key;
            };

/**
* Ed25519 signing operation with pre-hash
*/
            class Ed25519_Hashed_Sign_Operation final : public pk_operations::signature {
            public:
                Ed25519_Hashed_Sign_Operation(const Ed25519_PrivateKey &key, const std::string &hash) : m_key(key) {
                    m_hash = HashFunction::create_or_throw(hash);
                }

                void update(const uint8_t msg[], size_t msg_len) override {
                    m_hash->update(msg, msg_len);
                }

                secure_vector <uint8_t> sign(RandomNumberGenerator &) override {
                    secure_vector <uint8_t> sig(64);
                    std::vector<uint8_t> msg_hash(m_hash->output_length());
                    m_hash->final(msg_hash.data());
                    ed25519_sign(sig.data(), msg_hash.data(), msg_hash.size(), m_key.get_private_key().data());
                    return sig;
                }

            private:
                std::unique_ptr<HashFunction> m_hash;
                const Ed25519_PrivateKey &m_key;
            };

        }

        std::unique_ptr<pk_operations::verification> Ed25519_PublicKey::create_verification_op(const std::string &params,
                                                                                        const std::string &provider) const {
            if (provider == "core" || provider.empty()) {
                if (params == "" || params == "Identity" || params == "Pure") {
                    return std::unique_ptr<pk_operations::verification>(new Ed25519_Pure_Verify_Operation(*this));
                } else {
                    return std::unique_ptr<pk_operations::verification>(new Ed25519_Hashed_Verify_Operation(*this, params));
                }
            }
            throw Provider_Not_Found(algo_name(), provider);
        }

        std::unique_ptr<pk_operations::signature> Ed25519_PrivateKey::create_signature_op(RandomNumberGenerator &,
                                                                                   const std::string &params,
                                                                                   const std::string &provider) const {
            if (provider == "core" || provider.empty()) {
                if (params == "" || params == "Identity" || params == "Pure") {
                    return std::unique_ptr<pk_operations::signature>(new Ed25519_Pure_Sign_Operation(*this));
                } else {
                    return std::unique_ptr<pk_operations::signature>(new Ed25519_Hashed_Sign_Operation(*this, params));
                }
            }
            throw Provider_Not_Found(algo_name(), provider);
        }
    }
}
