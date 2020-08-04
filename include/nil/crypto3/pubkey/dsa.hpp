//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_DSA_HPP
#define CRYPTO3_PUBKEY_DSA_HPP

#include <nil/crypto3/pubkey/dl_algorithm.hpp>
#include <nil/crypto3/pubkey/dl_group/dl_group.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            template<typename FieldType>
            struct dsa_public_key {

            };

            template<typename FieldType>
            struct dsa_private_key {

            };

            template<typename FieldType>
            struct dsa {
                typedef FieldType field_type;

                typedef dsa_public_key<FieldType> public_key_type;
                typedef dsa_private_key<FieldType> private_key_type;
            };

            /**
             * DSA Public Key
             */
            class dsa_public_key_policy : public virtual dl_scheme_public_key {
            public:
                /**
                 * Get the OID of the underlying public key scheme.
                 * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 2, 840, 10040, 4, 1});
                }

                std::string algo_name() const override {
                    return "DSA";
                }

                dl_group::format group_format() const override {
                    return dl_group::ANSI_X9_57;
                }

                size_t message_parts() const override {
                    return 2;
                }

                size_t message_part_size() const override {
                    return group_q().bytes();
                }

                /**
                 * Load a public key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded public key bits
                 */
                dsa_public_key_policy(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits) :
                    dl_scheme_public_key(alg_id, key_bits, dl_group::ANSI_X9_57) {
                }

                /**
                 * Create a public key.
                 * @param group the underlying DL group
                 * @param y the public value y = g^x mod p
                 */
                template<typename Backend, expression_template_option ExpressionTemplates>
                dsa_public_key_policy(const dl_group<number<Backend, ExpressionTemplates>> &group,
                                      const number<Backend, ExpressionTemplates> &y) :
                    m_group(group),
                    m_y(y) {
                }

                std::unique_ptr<pk_operations::verification>
                    create_verification_op(const std::string &params, const std::string &provider) const override;

            protected:
                dsa_public_key_policy() = default;
            };

            /**
             * DSA Private Key
             */
            class dsa_private_key_policy final : public dsa_public_key_policy, public virtual dl_scheme_private_key {
            public:
                /**
                 * Load a private key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded key bits in ANSI X9.57 format
                 */
                dsa_private_key_policy(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits);

                /**
                 * Create a private key.
                 * @param rng the RNG to use
                 * @param group the underlying DL group
                 * @param private_key the private key (if zero, a new random key is generated)
                 */
                dsa_private_key_policy(random_number_generator &rng, const dl_group &group,
                                       const number<Backend, ExpressionTemplates> &private_key = 0);

                bool check_key(random_number_generator &rng, bool strong) const override;

                std::unique_ptr<pk_operations::signature>
                    create_signature_op(random_number_generator &rng,
                                        const std::string &params,
                                        const std::string &provider) const override;
            };

            /*
             * dsa_public_key_policy Constructor
             */
            dsa_public_key_policy::dsa_public_key_policy(const dl_group &grp,
                                                         const number<Backend, ExpressionTemplates> &y1) {
                m_group = grp;
                m_y = y1;
            }

            /*
             * Create a DSA private key
             */
            dsa_private_key_policy::dsa_private_key_policy(random_number_generator &rng, const dl_group &grp,
                                                           const number<Backend, ExpressionTemplates> &x_arg) {
                m_group = grp;

                if (x_arg == 0) {
                    m_x = number<Backend, ExpressionTemplates>::random_integer(rng, 2, group_q());
                } else {
                    m_x = x_arg;
                }

                m_y = m_group.power_g_p(m_x);
            }

            dsa_private_key_policy::dsa_private_key_policy(const algorithm_identifier &alg_id,
                                                           const secure_vector<uint8_t> &key_bits) :
                dl_scheme_private_key(alg_id, key_bits, dl_group::ANSI_X9_57) {
                m_y = m_group.power_g_p(m_x);
            }

            /*
             * Check Private DSA Parameters
             */
            bool dsa_private_key_policy::check_key(random_number_generator &rng, bool strong) const {
                if (!dl_scheme_private_key::check_key(rng, strong) || m_x >= group_q()) {
                    return false;
                }

                if (!strong) {
                    return true;
                }

                return keypair::signature_consistency_check(rng, *this, "EMSA1(SHA-256)");
            }

            namespace {

                /**
                 * Object that can create a DSA signature
                 */
                class dsa_signature_operation final : public pk_operations::signature_with_emsa {
                public:
                    dsa_signature_operation(const dsa_private_key_policy &dsa, const std::string &emsa) :
                        pk_operations::signature_with_emsa(emsa), m_group(dsa.get_group()), m_x(dsa.get_x()),
                        m_mod_q(dsa.group_q()) {
#if defined(CRYPTO3_HAS_RFC6979)
                        m_rfc6979_hash = hash_for_emsa(emsa);
#endif
                    }

                    size_t max_input_bits() const override {
                        return m_group.get_q().bits();
                    }

                    secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                                    random_number_generator &rng) override;

                private:
                    const dl_group m_group;
                    const number<Backend, ExpressionTemplates> &m_x;
                    modular_reducer m_mod_q;
#if defined(CRYPTO3_HAS_RFC6979)
                    std::string m_rfc6979_hash;
#endif
                };

                secure_vector<uint8_t> dsa_signature_operation::raw_sign(const uint8_t msg[], size_t msg_len,
                                                                         random_number_generator &rng) {
                    const number<Backend, ExpressionTemplates> &q = m_group.get_q();

                    number<Backend, ExpressionTemplates> i(msg, msg_len, q.bits());

                    while (i >= q) {
                        i -= q;
                    }

#if defined(CRYPTO3_HAS_RFC6979)
                    CRYPTO3_UNUSED(random);
                    const number<Backend, ExpressionTemplates> k = generate_rfc6979_nonce(m_x, q, i, m_rfc6979_hash);
#else
                    const number<Backend, ExpressionTemplates> k =
                        number<Backend, ExpressionTemplates>::random_integer(rng, 1, q);
#endif

                    number<Backend, ExpressionTemplates> s = inverse_mod(k, q);
                    const number<Backend, ExpressionTemplates> r = m_mod_q.reduce(m_group.power_g_p(k));

                    s = m_mod_q.multiply(s, m_x * r + i);

                    // With overwhelming probability, a bug rather than actual zero r/s
                    if (r == 0 || s == 0) {
                        throw internal_error("Computed zero r/s during DSA signature");
                    }

                    return number<Backend, ExpressionTemplates>::encode_fixed_length_int_pair(r, s, q.bytes());
                }

                /**
                 * Object that can verify a DSA signature
                 */
                class dsa_verification_operation final : public pk_operations::verification_with_emsa {
                public:
                    dsa_verification_operation(const dsa_public_key_policy &dsa, const std::string &emsa) :
                        pk_operations::verification_with_emsa(emsa), m_group(dsa.get_group()), m_y(dsa.get_y()),
                        m_mod_q(dsa.group_q()) {
                    }

                    size_t max_input_bits() const override {
                        return m_group.get_q().bits();
                    }

                    bool with_recovery() const override {
                        return false;
                    }

                    bool verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[], size_t sig_len) override;

                private:
                    const dl_group m_group;
                    const number<Backend, ExpressionTemplates> &m_y;

                    modular_reducer m_mod_q;
                };

                bool dsa_verification_operation::verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[],
                                                        size_t sig_len) {
                    const number<Backend, ExpressionTemplates> &q = m_group.get_q();
                    const size_t q_bytes = q.bytes();

                    if (sig_len != 2 * q_bytes || msg_len > q_bytes) {
                        return false;
                    }

                    number<Backend, ExpressionTemplates> r(sig, q_bytes);
                    number<Backend, ExpressionTemplates> s(sig + q_bytes, q_bytes);
                    number<Backend, ExpressionTemplates> i(msg, msg_len, q.bits());

                    if (r <= 0 || r >= q || s <= 0 || s >= q) {
                        return false;
                    }

                    s = inverse_mod(s, q);

                    const number<Backend, ExpressionTemplates> sr = m_mod_q.multiply(s, r);
                    const number<Backend, ExpressionTemplates> si = m_mod_q.multiply(s, i);

                    s = m_group.multi_exponentiate(si, m_y, sr);

                    return (m_mod_q.reduce(s) == r);
                }

            }    // namespace

            std::unique_ptr<pk_operations::verification>
                dsa_public_key_policy::create_verification_op(const std::string &params,
                                                              const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::verification>(new dsa_verification_operation(*this, params));
                }
                throw Provider_Not_Found(algo_name(), provider);
            }

            std::unique_ptr<pk_operations::signature> dsa_private_key_policy::create_signature_op(
                random_number_generator & /*random*/, const std::string &params, const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::signature>(new dsa_signature_operation(*this, params));
                }
                throw Provider_Not_Found(algo_name(), provider);
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
