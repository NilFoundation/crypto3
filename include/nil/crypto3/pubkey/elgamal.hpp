//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_ELGAMAL_HPP
#define CRYPTO3_PUBKEY_ELGAMAL_HPP

#include <nil/crypto3/pubkey/dl_algorithm.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            /**
             * ElGamal Public Key
             */
            class el_gamal_public_key : public virtual dl_scheme_public_key {
            public:
                /**
                 * Get the OID of the underlying public key scheme.
                 * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 3, 6, 1, 4, 1, 3029, 1, 2, 1});
                }

                std::string algo_name() const override {
                    return "ElGamal";
                }

                dl_group::format group_format() const override {
                    return dl_group::ANSI_X9_42;
                }

                /**
                 * Load a public key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded public key bits
                 */
                el_gamal_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits) :
                    dl_scheme_public_key(alg_id, key_bits, dl_group::ANSI_X9_42) {
                }

                /**
                 * Create a public key.
                 * @param group the underlying DL group
                 * @param y the public value y = g^x mod p
                 */
                el_gamal_public_key(const dl_group &group, const number<Backend, ExpressionTemplates> &y);

                std::unique_ptr<pk_operations::encryption> create_encryption_op(random_number_generator &rng,
                                                                                const std::string &params,
                                                                                const std::string &provider) const

                    override;

            protected:
                el_gamal_public_key() = default;
            };

            /**
             * ElGamal Private Key
             */
            class el_gamal_private_key final : public el_gamal_public_key, public virtual dl_scheme_private_key {
            public:
                bool check_key(random_number_generator &rng, bool) const override;

                /**
                 * Load a private key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded key bits in ANSI X9.42 format
                 */
                el_gamal_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits);

                /**
                 * Create a private key.
                 * @param rng random number generator to use
                 * @param group the group to be used in the key
                 * @param priv_key the key's secret value (or if zero, generate a new key)
                 */
                el_gamal_private_key(random_number_generator &rng, const dl_group &group,
                                     const number<Backend, ExpressionTemplates> &priv_key = 0);

                std::unique_ptr<pk_operations::decryption>
                    create_decryption_op(random_number_generator &rng,
                                         const std::string &params,
                                         const std::string &provider) const override;
            };

            class el_gamal {
            public:
                typedef el_gamal_public_key public_key_policy;
                typedef el_gamal_private_key private_key_policy;
            };

            /*
             * el_gamal_public_key Constructor
             */
            el_gamal_public_key::el_gamal_public_key(const dl_group &group,
                                                     const number<Backend, ExpressionTemplates> &y) :
                dl_scheme_public_key(group, y) {
            }

            /*
             * el_gamal_private_key Constructor
             */
            el_gamal_private_key::el_gamal_private_key(random_number_generator &rng, const dl_group &group,
                                                       const number<Backend, ExpressionTemplates> &x) {
                m_x = x;
                m_group = group;

                if (m_x.is_zero()) {
                    m_x.randomize(rng, group.exponent_bits());
                }

                m_y = m_group.power_g_p(m_x);
            }

            el_gamal_private_key::el_gamal_private_key(const algorithm_identifier &alg_id,
                                                       const secure_vector<uint8_t> &key_bits) :
                dl_scheme_private_key(alg_id, key_bits, dl_group::ANSI_X9_42) {
                m_y = m_group.power_g_p(m_x);
            }

            /*
             * Check Private ElGamal Parameters
             */
            bool el_gamal_private_key::check_key(random_number_generator &rng, bool strong) const {
                if (!dl_scheme_private_key::check_key(rng, strong)) {
                    return false;
                }

                if (!strong) {
                    return true;
                }

                return keypair::encryption_consistency_check(rng, *this, "EME1(SHA-256)");
            }

            namespace {

                /**
                 * ElGamal encryption operation
                 */
                class el_gamal_encryption_operation final : public pk_operations::encryption_with_eme {
                public:
                    size_t max_raw_input_bits() const override {
                        return m_group.p_bits() - 1;
                    }

                    el_gamal_encryption_operation(const el_gamal_public_key &key, const std::string &eme);

                    secure_vector<uint8_t> raw_encrypt(const uint8_t msg[], size_t msg_len,
                                                       random_number_generator &rng) override;

                private:
                    const dl_group m_group;
                    fixed_base_power_mod m_powermod_y_p;
                };

                el_gamal_encryption_operation::el_gamal_encryption_operation(const el_gamal_public_key &key,
                                                                             const std::string &eme) :
                    pk_operations::encryption_with_eme(eme),
                    m_group(key.get_group()), m_powermod_y_p(key.get_y(), m_group.get_p()) {
                }

                secure_vector<uint8_t> el_gamal_encryption_operation::raw_encrypt(const uint8_t msg[], size_t msg_len,
                                                                                  random_number_generator &rng) {
                    number<Backend, ExpressionTemplates> m(msg, msg_len);

                    if (m >= m_group.get_p()) {
                        throw std::invalid_argument("ElGamal encryption: Input is too large");
                    }

                    const size_t k_bits = m_group.exponent_bits();
                    const number<Backend, ExpressionTemplates> k(rng, k_bits);

                    const number<Backend, ExpressionTemplates> a = m_group.power_g_p(k);
                    const number<Backend, ExpressionTemplates> b = m_group.multiply_mod_p(m, m_powermod_y_p(k));

                    return number<Backend, ExpressionTemplates>::encode_fixed_length_int_pair(a, b, m_group.p_bytes());
                }

                /**
                 * ElGamal decryption operation
                 */
                class el_gamal_decryption_operation final : public pk_operations::decryption_with_eme {
                public:
                    el_gamal_decryption_operation(const el_gamal_private_key &key, const std::string &eme,
                                                  random_number_generator &rng);

                    secure_vector<uint8_t> raw_decrypt(const uint8_t msg[], size_t msg_len) override;

                private:
                    const dl_group m_group;
                    fixed_exponent_power_mod m_powermod_x_p;
                    blinder m_blinder;
                };

                el_gamal_decryption_operation::el_gamal_decryption_operation(const el_gamal_private_key &key,
                                                                             const std::string &eme,
                                                                             random_number_generator &rng) :
                    pk_operations::decryption_with_eme(eme),
                    m_group(key.get_group()), m_powermod_x_p(key.get_x(), m_group.get_p()),
                    m_blinder(
                        m_group.p(), rng, [](const number<Backend, ExpressionTemplates> &k) { return k; },
                        [this](const number<Backend, ExpressionTemplates> &k) { return m_powermod_x_p(k); }) {
                }

                secure_vector<uint8_t> el_gamal_decryption_operation::raw_decrypt(const uint8_t msg[], size_t msg_len) {
                    const size_t p_bytes = m_group.p_bytes();

                    if (msg_len != 2 * p_bytes) {
                        throw std::invalid_argument("ElGamal decryption: Invalid message");
                    }

                    number<Backend, ExpressionTemplates> a(msg, p_bytes);
                    const number<Backend, ExpressionTemplates> b(msg + p_bytes, p_bytes);

                    if (a >= m_group.p() || b >= m_group.get_p()) {
                        throw std::invalid_argument("ElGamal decryption: Invalid message");
                    }

                    a = m_blinder.blind(a);

                    const number<Backend, ExpressionTemplates> r =
                        m_group.multiply_mod_p(m_group.inverse_mod_p(m_powermod_x_p(a)), b);

                    return number<Backend, ExpressionTemplates>::encode_1363(m_blinder.unblind(r), p_bytes);
                }

            }    // namespace

            std::unique_ptr<pk_operations::encryption> el_gamal_public_key::create_encryption_op(
                random_number_generator & /*random*/, const std::string &params, const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::encryption>(new el_gamal_encryption_operation(*this, params));
                }
                throw provider_not_found(algo_name(), provider);
            }

            std::unique_ptr<pk_operations::decryption>
                el_gamal_private_key::create_decryption_op(random_number_generator &rng, const std::string &params,
                                                           const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::decryption>(
                        new el_gamal_decryption_operation(*this, params, rng));
                }
                throw provider_not_found(algo_name(), provider);
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
