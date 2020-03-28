//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_ECGDSA_KEY_HPP
#define CRYPTO3_PUBKEY_ECGDSA_KEY_HPP

#include <nil/crypto3/pubkey/ecc_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            /**
             * This class represents ECGDSA public keys.
             */
            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            class ecgdsa_public_key : public ec_public_key<CurveType, NumberType> {
            public:
                /**
                 * Construct a public key from a given public point.
                 * @param dom_par the domain parameters associated with this key
                 * @param public_point the public point defining this key
                 */
                ecgdsa_public_key(const ec_group<CurveType, NumberType> &dom_par,
                                  const point_gfp<CurveType> &public_point) :
                    ec_public_key<CurveType, NumberType>(dom_par, public_point) {
                }

                /**
                 * Load a public key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded public key bits
                 */
                ecgdsa_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits) :
                    ec_public_key<CurveType, NumberType>(alg_id, key_bits) {
                }

                /**
                 * Get the OID of the underlying public key scheme.
                 * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 3, 36, 3, 3, 2, 5, 2, 1});
                }

                /**
                 * Get this keys algorithm name.
                 * @result this keys algorithm name ("ECGDSA")
                 */
                std::string algo_name() const override {
                    return "ECGDSA";
                }

                size_t message_parts() const override {
                    return 2;
                }

                size_t message_part_size() const override {
                    return domain().get_order().bytes();
                }

                std::unique_ptr<pk_operations::verification>
                    create_verification_op(const std::string &params, const std::string &provider) const override;

            protected:
                ecgdsa_public_key() = default;
            };

            /**
             * This class represents ECGDSA private keys.
             */
            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            class ecgdsa_private_key final : public ecgdsa_public_key<CurveType, NumberType>,
                                             public ec_private_key<CurveType, NumberType> {
            public:
                /**
                 * Load a private key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits ECPrivateKey bits
                 */
                ecgdsa_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits) :
                    ec_private_key<CurveType, NumberType>(alg_id, key_bits, true) {
                }

                /**
                 * Generate a new private key.
                 * @param rng a random number generator
                 * @param domain parameters to used for this key
                 * @param x the private key (if zero, generate a new random key)
                 */
                template<typename UniformRandomGenerator, typename Backend,
                         expression_template_option ExpressionTemplates>
                ecgdsa_private_key(UniformRandomGenerator &rng, const ec_group<CurveType, NumberType> &domain,
                                   const number<Backend, ExpressionTemplates> &x = 0) :
                    ec_private_key<CurveType, NumberType>(rng, domain, x, true) {
                }

                template<typename UniformRandomGenerator>
                bool check_key(UniformRandomGenerator &rng, bool) const override {
                    if (!public_point().on_the_curve()) {
                        return false;
                    }

                    if (!strong) {
                        return true;
                    }

                    return key_pair::signature_consistency_check(rng, *this, "EMSA1(SHA-256)");
                }

                std::unique_ptr<pk_operations::signature>
                    create_signature_op(random_number_generator &rng,
                                        const std::string &params,
                                        const std::string &provider) const override;
            };

            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            class ecgdsa {
            public:
                typedef ecgdsa_public_key<CurveType, NumberType> public_key_policy;
                typedef ecgdsa_private_key<CurveType, NumberType> private_key_policy;
            };

            namespace {

                /**
                 * ECGDSA signature operation
                 */
                class ecgdsa_signature_operation final : public pk_operations::signature_with_emsa {
                public:
                    ecgdsa_signature_operation(const ecgdsa_private_key &ecgdsa, const std::string &emsa) :
                        pk_operations::signature_with_emsa(emsa), m_group(ecgdsa.domain()),
                        m_x(ecgdsa.private_value()) {
                    }

                    secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                                    random_number_generator &rng) override;

                    size_t max_input_bits() const override {
                        return m_group.get_order_bits();
                    }

                private:
                    const ec_group m_group;
                    const boost::multiprecision::number<Backend, ExpressionTemplates> &m_x;
                    std::vector<boost::multiprecision::number<Backend, ExpressionTemplates>> m_ws;
                };

                secure_vector<uint8_t> ecgdsa_signature_operation::raw_sign(const uint8_t msg[], size_t msg_len,
                                                                            random_number_generator &rng) {
                    const boost::multiprecision::number<Backend, ExpressionTemplates> m(msg, msg_len,
                                                                                        m_group.get_order_bits());

                    const boost::multiprecision::number<Backend, ExpressionTemplates> k = m_group.random_scalar(rng);

                    const boost::multiprecision::number<Backend, ExpressionTemplates> r =
                        m_group.mod_order(m_group.blinded_base_point_multiply_x(k, rng, m_ws));

                    const boost::multiprecision::number<Backend, ExpressionTemplates> kr =
                        m_group.multiply_mod_order(k, r);

                    const boost::multiprecision::number<Backend, ExpressionTemplates> s =
                        m_group.multiply_mod_order(m_x, kr - m);

                    // With overwhelming probability, a bug rather than actual zero r/s
                    if (r.is_zero() || s.is_zero()) {
                        throw internal_error("During ECGDSA signature generated zero r/s");
                    }

                    return boost::multiprecision::number<Backend, ExpressionTemplates>::encode_fixed_length_int_pair(
                        r, s, m_group.get_order_bytes());
                }

                /**
                 * ECGDSA verification operation
                 */
                class ecgdsa_verification_operation final : public pk_operations::verification_with_emsa {
                public:
                    ecgdsa_verification_operation(const ecgdsa_public_key &ecgdsa, const std::string &emsa) :
                        pk_operations::verification_with_emsa(emsa), m_group(ecgdsa.domain()),
                        m_public_point(ecgdsa.public_point()) {
                    }

                    size_t max_input_bits() const override {
                        return m_group.get_order_bits();
                    }

                    bool with_recovery() const override {
                        return false;
                    }

                    bool verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[], size_t sig_len) override;

                private:
                    const ec_group m_group;
                    const point_gfp &m_public_point;
                };

                bool ecgdsa_verification_operation::verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[],
                                                           size_t sig_len) {
                    if (sig_len != m_group.get_order_bytes() * 2) {
                        return false;
                    }

                    const boost::multiprecision::number<Backend, ExpressionTemplates> e(msg, msg_len,
                                                                                        m_group.get_order_bits());

                    const boost::multiprecision::number<Backend, ExpressionTemplates> r(sig, sig_len / 2);
                    const boost::multiprecision::number<Backend, ExpressionTemplates> s(sig + sig_len / 2, sig_len / 2);

                    if (r <= 0 || r >= m_group.get_order() || s <= 0 || s >= m_group.get_order()) {
                        return false;
                    }

                    const boost::multiprecision::number<Backend, ExpressionTemplates> w =
                        inverse_mod(r, m_group.get_order());

                    const boost::multiprecision::number<Backend, ExpressionTemplates> u1 =
                        m_group.multiply_mod_order(e, w);
                    const boost::multiprecision::number<Backend, ExpressionTemplates> u2 =
                        m_group.multiply_mod_order(s, w);
                    const point_gfp R = m_group.point_multiply(u1, m_public_point, u2);

                    if (R.is_zero()) {
                        return false;
                    }

                    const boost::multiprecision::number<Backend, ExpressionTemplates> v =
                        m_group.mod_order(R.get_affine_x());
                    return (v == r);
                }

            }    // namespace

            std::unique_ptr<pk_operations::verification>
                ecgdsa_public_key::create_verification_op(const std::string &params,
                                                          const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::verification>(
                        new ecgdsa_verification_operation(*this, params));
                }
                throw Provider_Not_Found(algo_name(), provider);
            }

            std::unique_ptr<pk_operations::signature>
                ecgdsa_private_key::create_signature_op(random_number_generator & /*random*/, const std::string &params,
                                                        const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::signature>(new ecgdsa_signature_operation(*this, params));
                }
                throw Provider_Not_Found(algo_name(), provider);
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
