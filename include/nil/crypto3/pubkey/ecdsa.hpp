//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_ECDSA_KEY_HPP
#define CRYPTO3_PUBKEY_ECDSA_KEY_HPP

#include <boost/multiprecision/number.hpp>

#include <nil/crypto3/pubkey/ecc_key.hpp>
#include <nil/crypto3/pubkey/detail/consistency.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename CurveType>
            struct ecdsa_public_key {
                typedef CurveType curve_type;

                typedef typename curve_type::value_type value_type;
                typedef typename curve_type::number_type number_type;

                constexpr static const std::size_t key_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_type;

                constexpr static const std::size_t key_schedule_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;

                inline static bool verify(const signature_type &val, const key_schedule_type &key) {
                    if(sig_len != m_group.get_order_bytes() * 2)
                        return false;

                    const BigInt e(msg, msg_len, m_group.get_order_bits());

                    const BigInt r(sig, sig_len / 2);
                    const BigInt s(sig + sig_len / 2, sig_len / 2);

                    if(r <= 0 || r >= m_group.get_order() || s <= 0 || s >= m_group.get_order())
                        return false;

                    const BigInt w = inverse_mod(s, m_group.get_order());

                    const BigInt u1 = m_group.multiply_mod_order(e, w);
                    const BigInt u2 = m_group.multiply_mod_order(r, w);
                    const PointGFp R = m_gy_mul.multi_exp(u1, u2);

                    if(R.is_zero())
                        return false;

                    const BigInt v = m_group.mod_order(R.get_affine_x());
                    return (v == r);

                }
            };

            template<typename CurveType>
            struct ecdsa_private_key {
                typedef CurveType curve_type;

                typedef typename curve_type::value_type value_type;
                typedef typename curve_type::number_type number_type;

                constexpr static const std::size_t key_bits = curve_type::field_type::modulus_bits;
                typedef typename CurveType::value_type key_type;

                constexpr static const std::size_t key_schedule_bits = curve_type::field_type::modulus_bits;
                typedef typename CurveType::value_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;

                template<typename Hash>
                inline static bool sign(signature_type &res, const number_type &val, const key_schedule_type &key) {
                    BigInt m(msg, msg_len, m_group.get_order_bits());

                    const BigInt k = generate_rfc6979_nonce(m_x, m_group.get_order(), m, m_rfc6979_hash);

                    const BigInt k_inv = inverse_mod(k, m_group.get_order());
                    const BigInt r = m_group.mod_order(
                        m_group.blinded_base_point_multiply_x(k, rng, m_ws));

                    const BigInt xrm = m_group.mod_order(m_group.multiply_mod_order(m_x, r) + m);
                    const BigInt s = m_group.multiply_mod_order(k_inv, xrm);

                    // With overwhelming probability, a bug rather than actual zero r/s
                    if(r.is_zero() || s.is_zero())
                        throw Internal_Error("During ECDSA signature generated zero r/s");

//                    return BigInt::encode_fixed_length_int_pair(r, s, m_group.get_order_bytes());
                    res = std::make_tuple(r, s);
                }
            };

            template<typename CurveType>
            struct ecdsa {
                typedef ecdsa_public_key<CurveType> public_key_type;
                typedef ecdsa_private_key<CurveType> private_key_type;

                constexpr static const std::size_t public_key_bits = public_key_type::key_bits;
                constexpr static const std::size_t private_key_bits = private_key_type::key_bits;
            };


            /**
             * This class represents ECDSA Public Keys.
             */
            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            class ecdsa_public_key : public ec_public_key<CurveType, NumberType> {
            public:
                /**
                 * Create a public key from a given public point.
                 * @param dom_par the domain parameters associated with this key
                 * @param public_point the public point defining this key
                 */
                ecdsa_public_key(const ec_group<CurveType, NumberType> &dom_par,
                                 const point_gfp<CurveType> &public_point) :
                    ec_public_key<CurveType, NumberType>(dom_par, public_point) {
                }

                /**
                 * Load a public key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded public key bits
                 */
                ecdsa_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits) :
                    ec_public_key<CurveType, NumberType>(alg_id, key_bits) {
                }

                /**
                 * Get the OID of the underlying public key scheme.
                 * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 2, 840, 10045, 2, 1});
                }

                /**
                 * Get this keys algorithm name.
                 * @result this keys algorithm name ("ECDSA")
                 */
                std::string algo_name() const override {
                    return "ECDSA";
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
                ecdsa_public_key() = default;
            };

            /**
             * This class represents ECDSA Private Keys
             */
            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            class ecdsa_private_key final : public ecdsa_public_key<CurveType, NumberType>,
                                            public ec_private_key<CurveType, NumberType> {
            public:
                /**
                 * Load a private key
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits ECPrivateKey bits
                 */
                ecdsa_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits) :
                    ec_private_key<CurveType, NumberType>(alg_id, key_bits) {
                }

                /**
                 * Create a private key.
                 * @param rng a random number generator
                 * @param domain parameters to used for this key
                 * @param x the private key (if zero, generate a new random key)
                 */
                template<typename UniformRandomGenerator, typename Backend,
                         expression_template_option ExpressionTemplates>
                ecdsa_private_key(UniformRandomGenerator &rng, const ec_group<CurveType, NumberType> &domain,
                                  const number<Backend, ExpressionTemplates> &x = 0) :
                    ec_private_key<CurveType, NumberType>(rng, domain, x) {
                }

                template<typename UniformRandonGenerator>
                bool check_key(UniformRandonGenerator &rng, bool) const {
                    if (!public_point().on_the_curve()) {
                        return false;
                    }

                    if (!strong) {
                        return true;
                    }

                    return keypair::signature_consistency_check(rng, *this, "EMSA1(SHA-256)");
                }

                std::unique_ptr<pk_operations::signature>
                    create_signature_op(random_number_generator &rng,
                                        const std::string &params,
                                        const std::string &provider) const override;
            };

            namespace {

                /**
                 * ECDSA signature operation
                 */
                class ecdsa_signature_operation final : public pk_operations::signature_with_emsa {
                public:
                    ecdsa_signature_operation(const ecdsa_private_key &ecdsa, const std::string &emsa) :
                        pk_operations::signature_with_emsa(emsa), m_group(ecdsa.domain()), m_x(ecdsa.private_value()) {
#if defined(CRYPTO3_HAS_RFC6979)
                        m_rfc6979_hash = hash_for_emsa(emsa);
#endif
                    }

                    size_t max_input_bits() const override {
                        return m_group.get_order_bits();
                    }

                    secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                                    random_number_generator &rng) override;

                private:
                    const ec_group m_group;
                    const boost::multiprecision::number<Backend, ExpressionTemplates> &m_x;

#if defined(CRYPTO3_HAS_RFC6979)
                    std::string m_rfc6979_hash;
#endif

                    std::vector<boost::multiprecision::number<Backend, ExpressionTemplates>> m_ws;
                };

                secure_vector<uint8_t> ecdsa_signature_operation::raw_sign(const uint8_t msg[], size_t msg_len,
                                                                           random_number_generator &rng) {
                    boost::multiprecision::number<Backend, ExpressionTemplates> m(msg, msg_len,
                                                                                  m_group.get_order_bits());

#if defined(CRYPTO3_HAS_RFC6979)
                    const boost::multiprecision::number<Backend, ExpressionTemplates> k =
                        generate_rfc6979_nonce(m_x, m_group.get_order(), m, m_rfc6979_hash);
#else
                    const boost::multiprecision::number<Backend, ExpressionTemplates> k = m_group.random_scalar(rng);
#endif

                    const boost::multiprecision::number<Backend, ExpressionTemplates> k_inv =
                        inverse_mod(k, m_group.get_order());
                    const boost::multiprecision::number<Backend, ExpressionTemplates> r =
                        m_group.mod_order(m_group.blinded_base_point_multiply_x(k, rng, m_ws));

                    const boost::multiprecision::number<Backend, ExpressionTemplates> xrm =
                        m_group.mod_order(m_group.multiply_mod_order(m_x, r) + m);
                    const boost::multiprecision::number<Backend, ExpressionTemplates> s =
                        m_group.multiply_mod_order(k_inv, xrm);

                    // With overwhelming probability, a bug rather than actual zero r/s
                    if (r.is_zero() || s.is_zero()) {
                        throw internal_error("During ECDSA signature generated zero r/s");
                    }

                    return boost::multiprecision::number<Backend, ExpressionTemplates>::encode_fixed_length_int_pair(
                        r, s, m_group.get_order_bytes());
                }

                /**
                 * ECDSA verification operation
                 */
                class ecdsa_verification_operation final : public pk_operations::verification_with_emsa {
                public:
                    ecdsa_verification_operation(const ecdsa_public_key &ecdsa, const std::string &emsa) :
                        pk_operations::verification_with_emsa(emsa), m_group(ecdsa.domain()),
                        m_gy_mul(m_group.get_base_point(), ecdsa.public_point()) {
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
                    const point_gfp_multi_point_precompute m_gy_mul;
                };

                bool ecdsa_verification_operation::verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[],
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
                        inverse_mod(s, m_group.get_order());

                    const boost::multiprecision::number<Backend, ExpressionTemplates> u1 =
                        m_group.multiply_mod_order(e, w);
                    const boost::multiprecision::number<Backend, ExpressionTemplates> u2 =
                        m_group.multiply_mod_order(r, w);
                    const point_gfp R = m_gy_mul.multi_exp(u1, u2);

                    if (R.is_zero()) {
                        return false;
                    }

                    const boost::multiprecision::number<Backend, ExpressionTemplates> v =
                        m_group.mod_order(R.get_affine_x());
                    return (v == r);
                }

            }    // namespace

            std::unique_ptr<pk_operations::verification>
                ecdsa_public_key::create_verification_op(const std::string &params, const std::string &provider) const {
#if defined(CRYPTO3_HAS_BEARSSL)
                if (provider == "bearssl" || provider.empty()) {
                    try {
                        return make_bearssl_ecdsa_ver_op(*this, params);
                    } catch (lookup_error &e) {
                        if (provider == "bearssl")
                            throw;
                    }
                }
#endif

#if defined(CRYPTO3_HAS_OPENSSL)
                if (provider == "openssl" || provider.empty()) {
                    try {
                        return make_openssl_ecdsa_ver_op(*this, params);
                    } catch (lookup_error &e) {
                        if (provider == "openssl")
                            throw;
                    }
                }
#endif

                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::verification>(
                        new ecdsa_verification_operation(*this, params));
                }

                throw Provider_Not_Found(algo_name(), provider);
            }

            std::unique_ptr<pk_operations::signature>
                ecdsa_private_key::create_signature_op(random_number_generator & /*random*/, const std::string &params,
                                                       const std::string &provider) const {
#if defined(CRYPTO3_HAS_BEARSSL)
                if (provider == "bearssl" || provider.empty()) {
                    try {
                        return make_bearssl_ecdsa_sig_op(*this, params);
                    } catch (lookup_error &e) {
                        if (provider == "bearssl")
                            throw;
                    }
                }
#endif

#if defined(CRYPTO3_HAS_OPENSSL)
                if (provider == "openssl" || provider.empty()) {
                    try {
                        return make_openssl_ecdsa_sig_op(*this, params);
                    } catch (lookup_error &e) {
                        if (provider == "openssl")
                            throw;
                    }
                }
#endif

                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::signature>(new ecdsa_signature_operation(*this, params));
                }

                throw Provider_Not_Found(algo_name(), provider);
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
