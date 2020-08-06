//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_ED25519_HPP
#define CRYPTO3_PUBKEY_ED25519_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>

#include <nil/crypto3/pubkey/detail/ed25519/ed25519_fe.hpp>
#include <nil/crypto3/pubkey/detail/ed25519/ed25519_internal.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            void ed25519_gen_keypair(uint8_t *pk, uint8_t *sk, const uint8_t seed[32]) {
                uint8_t az[64];

                SHA_512 sha;
                sha.update(seed, 32);
                sha.final(az);
                az[0] &= 248;
                az[31] &= 63;
                az[31] |= 64;

                ge_scalarmult_base(pk, az);

                // todo copy_mem
                memmove(sk, seed, 32);
                memmove(sk + 32, pk, 32);
            }

            void ed25519_sign(uint8_t sig[64], const uint8_t *m, size_t mlen, const uint8_t *sk) {
                uint8_t az[64];
                uint8_t nonce[64];
                uint8_t hram[64];

                SHA_512 sha;

                sha.update(sk, 32);
                sha.final(az);
                az[0] &= 248;
                az[31] &= 63;
                az[31] |= 64;

                sha.update(az + 32, 32);
                sha.update(m, mlen);
                sha.final(nonce);

                sc_reduce(nonce);
                ge_scalarmult_base(sig, nonce);

                sha.update(sig, 32);
                sha.update(sk + 32, 32);
                sha.update(m, mlen);
                sha.final(hram);

                sc_reduce(hram);
                sc_muladd(sig + 32, hram, az, nonce);
            }

            bool ed25519_verify(const uint8_t *m, size_t mlen, const uint8_t sig[64], const uint8_t *pk) {
                uint8_t h[64];
                uint8_t rcheck[32];
                ge_p3 A;
                SHA_512 sha;

                if (sig[63] & 224) {
                    return false;
                }
                if (ge_frombytes_negate_vartime(&A, pk) != 0) {
                    return false;
                }

                sha.update(sig, 32);
                sha.update(pk, 32);
                sha.update(m, mlen);
                sha.final(h);
                sc_reduce(h);

                ge_double_scalarmult_vartime(rcheck, h, &A, sig + 32);

                return constant_time_compare(rcheck, sig, 32);
            }

            template<typename CurveType>
            struct ed25519_public_key {
                typedef CurveType curve_type;
            };

            template<typename CurveType>
            struct ed25519_private_key {
                typedef CurveType curve_type;
            };

            template<typename CurveType>
            struct ed25519 {
                typedef ed25519_public_key<CurveType> public_key_policy;
                typedef ed25519_private_key<CurveType> private_key_policy;
            };

            class ed25519_public_key : public virtual public_key_policy {
            public:
                /**
                 * Get the OID of the underlying public key scheme.
                 * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 3, 101, 112});
                }

                std::string algo_name() const override {
                    return "Ed25519";
                }

                size_t estimated_strength() const override {
                    return 128;
                }

                size_t key_length() const override {
                    return 255;
                }

                bool check_key(random_number_generator &rng, bool strong) const override;

                algorithm_identifier algorithm_identifier() const override;

                std::vector<uint8_t> public_key_bits() const override;

                /**
                 * Create a Ed25519 Public Key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded public key bits
                 */
                ed25519_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits);

                /**
                 * Create a Ed25519 Public Key.
                 * @param pub 32-byte raw public key
                 */
                explicit ed25519_public_key(const std::vector<uint8_t> &pub) : m_public(pub) {
                }

                /**
                 * Create a Ed25519 Public Key.
                 * @param pub 32-byte raw public key
                 */
                explicit ed25519_public_key(const secure_vector<uint8_t> &pub) : m_public(pub.begin(), pub.end()) {
                }

                std::unique_ptr<pk_operations::verification>
                    create_verification_op(const std::string &params, const std::string &provider) const override;

                const std::vector<uint8_t> &get_public_key() const {
                    return m_public;
                }

            protected:
                ed25519_public_key() = default;

                std::vector<uint8_t> m_public;
            };

            class ed25519_private_key final : public ed25519_public_key, public virtual private_key_policy {
            public:
                /**
                 * Construct a private key from the specified parameters.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits PKCS #8 structure
                 */
                ed25519_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits);

                /**
                 * Generate a private key.
                 * @param rng the RNG to use
                 */
                explicit ed25519_private_key(random_number_generator &rng);

                /**
                 * Construct a private key from the specified parameters.
                 * @param secret_key the private key
                 */
                explicit ed25519_private_key(const secure_vector<uint8_t> &secret_key);

                const secure_vector<uint8_t> &get_private_key() const {
                    return m_private;
                }

                secure_vector<uint8_t> private_key_bits() const override;

                bool check_key(random_number_generator &rng, bool strong) const override;

                std::unique_ptr<pk_operations::signature>
                    create_signature_op(random_number_generator &rng,
                                        const std::string &params,
                                        const std::string &provider) const override;

            private:
                secure_vector<uint8_t> m_private;
            };

            algorithm_identifier ed25519_public_key::algorithm_identifier() const {
                // algorithm_identifier::USE_NULL_PARAM puts 0x05 0x00 in parameters
                // We want nothing
                std::vector<uint8_t> empty;
                return algorithm_identifier(get_oid(), empty);
            }

            bool ed25519_public_key::check_key(RandomNumberGenerator &, bool) const {
                return true;    // no tests possible?
                // TODO could check cofactor
            }

            ed25519_public_key::ed25519_public_key(const algorithm_identifier &, const std::vector<uint8_t> &key_bits) {
                m_public = key_bits;

                if (m_public.size() != 32) {
                    throw decoding_error("Invalid size for Ed25519 public key");
                }
            }

            std::vector<uint8_t> ed25519_public_key::public_key_bits() const {
                return m_public;
            }

            ed25519_private_key::ed25519_private_key(const secure_vector<uint8_t> &secret_key) {
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

            ed25519_private_key::ed25519_private_key(RandomNumberGenerator &rng) {
                const secure_vector<uint8_t> seed = rng.random_vec(32);
                m_public.resize(32);
                m_private.resize(64);
                ed25519_gen_keypair(m_public.data(), m_private.data(), seed.data());
            }

            ed25519_private_key::ed25519_private_key(const algorithm_identifier &,
                                                     const secure_vector<uint8_t> &key_bits) {
                secure_vector<uint8_t> bits;
                ber_decoder(key_bits).decode(bits, OCTET_STRING).discard_remaining();

                if (bits.size() != 32) {
                    throw decoding_error("Invalid size for Ed25519 private key");
                }
                m_public.resize(32);
                m_private.resize(64);
                ed25519_gen_keypair(m_public.data(), m_private.data(), bits.data());
            }

            secure_vector<uint8_t> ed25519_private_key::private_key_bits() const {
                secure_vector<uint8_t> bits(&m_private[0], &m_private[32]);
                return der_encoder().encode(bits, OCTET_STRING).get_contents();
            }

            bool ed25519_private_key::check_key(RandomNumberGenerator &, bool) const {
                return true;    // ???
            }

            namespace {

                /**
                 * Ed25519 verifying operation
                 */
                class Ed25519_Pure_Verify_Operation final : public pk_operations::verification {
                public:
                    Ed25519_Pure_Verify_Operation(const ed25519_public_key &key) : m_key(key) {
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
                    const ed25519_public_key &m_key;
                };

                /**
                 * Ed25519 verifying operation with pre-hash
                 */
                class Ed25519_Hashed_Verify_Operation final : public pk_operations::verification {
                public:
                    Ed25519_Hashed_Verify_Operation(const ed25519_public_key &key, const std::string &hash) :
                        m_key(key) {
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
                    const ed25519_public_key &m_key;
                };

                /**
                 * Ed25519 signing operation ('pure' - signs message directly)
                 */
                class Ed25519_Pure_Sign_Operation final : public pk_operations::signature {
                public:
                    Ed25519_Pure_Sign_Operation(const ed25519_private_key &key) : m_key(key) {
                    }

                    void update(const uint8_t msg[], size_t msg_len) override {
                        m_msg.insert(m_msg.end(), msg, msg + msg_len);
                    }

                    secure_vector<uint8_t> sign(RandomNumberGenerator &) override {
                        secure_vector<uint8_t> sig(64);
                        ed25519_sign(sig.data(), m_msg.data(), m_msg.size(), m_key.get_private_key().data());
                        m_msg.clear();
                        return sig;
                    }

                private:
                    std::vector<uint8_t> m_msg;
                    const ed25519_private_key &m_key;
                };

                /**
                 * Ed25519 signing operation with pre-hash
                 */
                class Ed25519_Hashed_Sign_Operation final : public pk_operations::signature {
                public:
                    Ed25519_Hashed_Sign_Operation(const ed25519_private_key &key, const std::string &hash) :
                        m_key(key) {
                        m_hash = HashFunction::create_or_throw(hash);
                    }

                    void update(const uint8_t msg[], size_t msg_len) override {
                        m_hash->update(msg, msg_len);
                    }

                    secure_vector<uint8_t> sign(RandomNumberGenerator &) override {
                        secure_vector<uint8_t> sig(64);
                        std::vector<uint8_t> msg_hash(m_hash->output_length());
                        m_hash->final(msg_hash.data());
                        ed25519_sign(sig.data(), msg_hash.data(), msg_hash.size(), m_key.get_private_key().data());
                        return sig;
                    }

                private:
                    std::unique_ptr<HashFunction> m_hash;
                    const ed25519_private_key &m_key;
                };

            }    // namespace

            std::unique_ptr<pk_operations::verification>
                ed25519_public_key::create_verification_op(const std::string &params,
                                                           const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    if (params == "" || params == "Identity" || params == "Pure") {
                        return std::unique_ptr<pk_operations::verification>(new Ed25519_Pure_Verify_Operation(*this));
                    } else {
                        return std::unique_ptr<pk_operations::verification>(
                            new Ed25519_Hashed_Verify_Operation(*this, params));
                    }
                }
                throw Provider_Not_Found(algo_name(), provider);
            }

            std::unique_ptr<pk_operations::signature>
                ed25519_private_key::create_signature_op(RandomNumberGenerator &,
                                                         const std::string &params,
                                                         const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    if (params == "" || params == "Identity" || params == "Pure") {
                        return std::unique_ptr<pk_operations::signature>(new Ed25519_Pure_Sign_Operation(*this));
                    } else {
                        return std::unique_ptr<pk_operations::signature>(
                            new Ed25519_Hashed_Sign_Operation(*this, params));
                    }
                }
                throw Provider_Not_Found(algo_name(), provider);
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
