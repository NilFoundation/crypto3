//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_ECDH_KEY_HPP
#define CRYPTO3_PUBKEY_ECDH_KEY_HPP

#include <nil/crypto3/pubkey/ecc_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            /**
             * This class represents ECDH Public Keys.
             */
            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            class ecdh_public_key : public virtual ec_public_key<CurveType, NumberType> {
            public:
                /**
                 * Create an ECDH public key.
                 * @param alg_id algorithm identifier
                 * @param key_bits DER encoded public key bits
                 */
                ecdh_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits) :
                    ec_public_key(alg_id, key_bits) {
                }

                /**
                 * Construct a public key from a given public point.
                 * @param dom_par the domain parameters associated with this key
                 * @param public_point the public point defining this key
                 */
                ecdh_public_key(const ec_group &dom_par, const point_gfp &public_point) :
                    ec_public_key(dom_par, public_point) {
                }

                /**
                 * Get the OID of the underlying public key scheme.
                 * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 3, 132, 1, 12});
                }

                /**
                 * Get this keys algorithm name.
                 * @return this keys algorithm name
                 */
                std::string algo_name() const override {
                    return "ECDH";
                }

                /**
                 * @return public point value
                 */
                std::vector<uint8_t> public_value() const {
                    return public_point().encode(point_gfp::UNCOMPRESSED);
                }

                /**
                 * @return public point value
                 */
                std::vector<uint8_t> public_value(point_gfp::compression_type format) const {
                    return public_point().encode(format);
                }

            protected:
                ecdh_public_key() = default;
            };

            /**
             * This class represents ECDH Private Keys.
             */
            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            class ecdh_private_key : public ecdh_public_key<CurveType, NumberType>,
                                     public ec_private_key<CurveType, NumberType>,
                                     public pk_key_agreement_key {
            public:
                /**
                 * Load a private key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits ECPrivateKey bits
                 */
                ecdh_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits) :
                    ec_private_key(alg_id, key_bits) {
                }

                /**
                 * Generate a new private key
                 * @param rng a random number generator
                 * @param domain parameters to used for this key
                 * @param x the private key; if zero, a new random key is generated
                 */
                ecdh_private_key(random_number_generator &rng, const ec_group &domain,
                                 const number<Backend, ExpressionTemplates> &x = 0) :
                    ec_private_key(rng, domain, x) {
                }

                std::vector<uint8_t> public_value() const

                    override {
                    return ecdh_public_key::public_value(point_gfp::UNCOMPRESSED);
                }

                std::vector<uint8_t> public_value(point_gfp::compression_type type) const {
                    return ecdh_public_key::public_value(type);
                }

                std::unique_ptr<pk_operations::key_agreement>
                    create_key_agreement_op(random_number_generator &rng,
                                            const std::string &params,
                                            const std::string &provider) const override;
            };

            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            class ecdh {
            public:
                typedef ecdh_public_key<CurveType, NumberType> public_key_policy;
                typedef ecdh_private_key<CurveType, NumberType> private_key_policy;
            };

            namespace {

                /**
                 * ECDH operation
                 */
                class ecdh_ka_operation final : public pk_operations::key_agreement_with_kdf {
                public:
                    ecdh_ka_operation(const ecdh_private_key &key, const std::string &kdf,
                                      random_number_generator &rng) :
                        pk_operations::key_agreement_with_kdf(kdf),
                        m_group(key.domain()), m_rng(rng) {
                        m_l_times_priv = inverse_mod(m_group.get_cofactor(), m_group.get_order()) * key.private_value();
                    }

                    secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override {
                        point_gfp input_point = m_group.get_cofactor() * m_group.os2ecp(w, w_len);
                        input_point.randomize_repr(m_rng);

                        const point_gfp S =
                            m_group.blinded_var_point_multiply(input_point, m_l_times_priv, m_rng, m_ws);

                        if (!S.on_the_curve()) {
                            throw internal_error("ECDH agreed value was not on the curve");
                        }
                        return boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(
                            S.get_affine_x(), m_group.get_p_bytes());
                    }

                private:
                    const ec_group m_group;
                    boost::multiprecision::number<Backend, ExpressionTemplates> m_l_times_priv;
                    random_number_generator &m_rng;
                    std::vector<boost::multiprecision::number<Backend, ExpressionTemplates>> m_ws;
                };

            }    // namespace

            std::unique_ptr<pk_operations::key_agreement>
                ecdh_private_key::create_key_agreement_op(random_number_generator &rng, const std::string &params,
                                                          const std::string &provider) const {
                return std::unique_ptr<pk_operations::key_agreement>(new ecdh_ka_operation(*this, params, rng));

                throw provider_not_found(algo_name(), provider);
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
