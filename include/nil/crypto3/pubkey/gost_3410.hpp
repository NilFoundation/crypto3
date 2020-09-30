//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_GOST_3410_KEY_HPP
#define CRYPTO3_PUBKEY_GOST_3410_KEY_HPP

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                template<typename Scheme, typename Hash>
                struct emsa1;
            }
            template<typename CurveType>
            struct gost_3410_public_key {
                typedef CurveType curve_type;
            };

            template<typename CurveType>
            struct gost_3410_private_key {
                typedef CurveType curve_type;
            };

            template<typename CurveType>
            struct gost_3410 {
                typedef CurveType curve_type;

                typedef gost_3410_public_key<CurveType> public_key_type;
                typedef gost_3410_private_key<CurveType> private_key_type;

                template<typename Hash>
                using padding_types = std::tuple<padding::emsa1<gost_3410<CurveType>, Hash>>;
            };
            /**
             * GOST-34.10 Public Key
             */
            class gost_3410_public_key : public virtual ec_public_key {
            public:
                /**
                 * Construct a public key from a given public point.
                 * @param dom_par the domain parameters associated with this key
                 * @param public_point the public point defining this key
                 */
                gost_3410_public_key(const ec_group &dom_par, const point_gfp &public_point) :
                    ec_public_key(dom_par, public_point) {
                }

                /**
                 * Load a public key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded public key bits
                 */
                gost_3410_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits);

                /**
                 * Get the OID of the underlying public key scheme.
                 * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 2, 643, 2, 2, 19});
                }

                /**
                 * Get this keys algorithm name.
                 * @result this keys algorithm name
                 */
                std::string algo_name() const override {
                    return "GOST-34.10";
                }

                algorithm_identifier get_algorithm_identifier() const override;

                std::vector<uint8_t> public_key_bits() const override;

                size_t message_parts() const override {
                    return 2;
                }

                size_t message_part_size() const override {
                    return domain().get_order().bytes();
                }

                std::unique_ptr<pk_operations::verification> create_verification_op(const std::string &params,
                                                                                    const std::string &provider) const

                    override;

            protected:
                gost_3410_public_key() = default;
            };

            /**
             * GOST-34.10 Private Key
             */
            class gost_3410_private_key final : public gost_3410_public_key, public ec_private_key {
            public:
                /**
                 * Load a private key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits ECPrivateKey bits
                 */
                gost_3410_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits) :
                    ec_private_key(alg_id, key_bits) {
                }

                /**
                 * Generate a new private key
                 * @param rng a random number generator
                 * @param domain parameters to used for this key
                 * @param x the private key; if zero, a new random key is generated
                 */
                gost_3410_private_key(random_number_generator &rng,
                                      const ec_group &domain,
                                      const number<Backend, ExpressionTemplates> &x = 0) :
                    ec_private_key(rng, domain, x) {
                }

                algorithm_identifier pkcs8_algorithm_identifier() const override {
                    return ec_public_key::get_algorithm_identifier();
                }

                std::unique_ptr<pk_operations::signature>
                    create_signature_op(random_number_generator &rng,
                                        const std::string &params,
                                        const std::string &provider) const override;
            };

            std::vector<uint8_t> gost_3410_public_key::public_key_bits() const {
                const boost::multiprecision::number<Backend, ExpressionTemplates> x = public_point().get_affine_x();
                const boost::multiprecision::number<Backend, ExpressionTemplates> y = public_point().get_affine_y();

                size_t part_size = std::max(x.bytes(), y.bytes());

                std::vector<uint8_t> bits(2 * part_size);

                x.binary_encode(&bits[part_size - x.bytes()]);
                y.binary_encode(&bits[2 * part_size - y.bytes()]);

                // Keys are stored in little endian format (WTF)
                for (size_t i = 0; i != part_size / 2; ++i) {
                    std::swap(bits[i], bits[part_size - 1 - i]);
                    std::swap(bits[part_size + i], bits[2 * part_size - 1 - i]);
                }

                return der_encoder().encode(bits, OCTET_STRING).get_contents_unlocked();
            }

            algorithm_identifier gost_3410_public_key::get_algorithm_identifier() const {
                std::vector<uint8_t> params = der_encoder()
                                                  .start_cons(SEQUENCE)
                                                  .encode(domain().get_curve_oid())
                                                  .end_cons()
                                                  .get_contents_unlocked();

                return get_algorithm_identifier(oid(), params);
            }

            gost_3410_public_key::gost_3410_public_key(const algorithm_identifier &alg_id,
                                                       const std::vector<uint8_t> &key_bits) {
                oid_t ecc_param_id;

                // The parameters also includes hash and cipher OIDs
                ber_decoder(alg_id.get_parameters()).start_cons(SEQUENCE).decode(ecc_param_id);

                m_domain_params = ec_group(ecc_param_id);

                secure_vector<uint8_t> bits;
                ber_decoder(key_bits).decode(bits, OCTET_STRING);

                const size_t part_size = bits.size() / 2;

                // Keys are stored in little endian format (WTF)
                for (size_t i = 0; i != part_size / 2; ++i) {
                    std::swap(bits[i], bits[part_size - 1 - i]);
                    std::swap(bits[part_size + i], bits[2 * part_size - 1 - i]);
                }

                boost::multiprecision::number<Backend, ExpressionTemplates> x(bits.data(), part_size);
                boost::multiprecision::number<Backend, ExpressionTemplates> y(&bits[part_size], part_size);

                m_public_key = domain().point(x, y);

                BOOST_ASSERT_MSG(m_public_key.on_the_curve(), "Loaded GOST 34.10 public key is on the curve");
            }

            namespace {

                boost::multiprecision::number<Backend, ExpressionTemplates> decode_le(const uint8_t msg[],
                                                                                      size_t msg_len) {
                    secure_vector<uint8_t> msg_le(msg, msg + msg_len);

                    for (size_t i = 0; i != msg_le.size() / 2; ++i) {
                        std::swap(msg_le[i], msg_le[msg_le.size() - 1 - i]);
                    }

                    return boost::multiprecision::number<Backend, ExpressionTemplates>(msg_le.data(), msg_le.size());
                }

                /**
                 * GOST-34.10 signature operation
                 */
                class GOST_3410_Signature_Operation final : public pk_operations::signature_with_emsa {
                public:
                    GOST_3410_Signature_Operation(const gost_3410_private_key &gost_3410, const std::string &emsa) :
                        pk_operations::signature_with_emsa(emsa), m_group(gost_3410.domain()),
                        m_x(gost_3410.private_value()) {
                    }

                    size_t max_input_bits() const override {
                        return m_group.get_order_bits();
                    }

                    secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                                    random_number_generator &rng) override;

                private:
                    const ec_group m_group;
                    const boost::multiprecision::number<Backend, ExpressionTemplates> &m_x;
                    std::vector<boost::multiprecision::number<Backend, ExpressionTemplates>> m_ws;
                };

                secure_vector<uint8_t> GOST_3410_Signature_Operation::raw_sign(const uint8_t msg[], size_t msg_len,
                                                                               random_number_generator &rng) {
                    const boost::multiprecision::number<Backend, ExpressionTemplates> k = m_group.random_scalar(rng);

                    boost::multiprecision::number<Backend, ExpressionTemplates> e = decode_le(msg, msg_len);

                    e = m_group.mod_order(e);
                    if (e == 0) {
                        e = 1;
                    }

                    const boost::multiprecision::number<Backend, ExpressionTemplates> r =
                        m_group.mod_order(m_group.blinded_base_point_multiply_x(k, rng, m_ws));

                    const boost::multiprecision::number<Backend, ExpressionTemplates> s =
                        m_group.mod_order(m_group.multiply_mod_order(r, m_x) + m_group.multiply_mod_order(k, e));

                    if (r == 0 || s == 0) {
                        throw internal_error("GOST 34.10 signature generation failed, r/s equal to zero");
                    }

                    return boost::multiprecision::number<Backend, ExpressionTemplates>::encode_fixed_length_int_pair(
                        s, r, m_group.get_order_bytes());
                }

                /**
                 * GOST-34.10 verification operation
                 */
                class GOST_3410_Verification_Operation final : public pk_operations::verification_with_emsa {
                public:
                    GOST_3410_Verification_Operation(const gost_3410_public_key &gost, const std::string &emsa) :
                        pk_operations::verification_with_emsa(emsa), m_group(gost.domain()),
                        m_public_point(gost.public_point()) {
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

                bool GOST_3410_Verification_Operation::verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[],
                                                              size_t sig_len) {
                    if (sig_len != m_group.get_order_bytes() * 2) {
                        return false;
                    }

                    const boost::multiprecision::number<Backend, ExpressionTemplates> s(sig, sig_len / 2);
                    const boost::multiprecision::number<Backend, ExpressionTemplates> r(sig + sig_len / 2, sig_len / 2);

                    const boost::multiprecision::number<Backend, ExpressionTemplates> &order = m_group.get_order();

                    if (r <= 0 || r >= order || s <= 0 || s >= order) {
                        return false;
                    }

                    boost::multiprecision::number<Backend, ExpressionTemplates> e = decode_le(msg, msg_len);
                    e = m_group.mod_order(e);
                    if (e == 0) {
                        e = 1;
                    }

                    const boost::multiprecision::number<Backend, ExpressionTemplates> v = inverse_mod(e, order);

                    const boost::multiprecision::number<Backend, ExpressionTemplates> z1 =
                        m_group.multiply_mod_order(s, v);
                    const boost::multiprecision::number<Backend, ExpressionTemplates> z2 =
                        m_group.multiply_mod_order(-r, v);

                    const point_gfp R = m_group.point_multiply(z1, m_public_point, z2);

                    if (R.is_zero()) {
                        return false;
                    }

                    return (R.get_affine_x() == r);
                }

            }    // namespace

            std::unique_ptr<pk_operations::verification>
                gost_3410_public_key::create_verification_op(const std::string &params,
                                                             const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::verification>(
                        new GOST_3410_Verification_Operation(*this, params));
                }
                throw provider_not_found(algo_name(), provider);
            }

            std::unique_ptr<pk_operations::signature>
                gost_3410_private_key::create_signature_op(random_number_generator & /*random*/,
                                                           const std::string &params,
                                                           const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::signature>(new GOST_3410_Signature_Operation(*this, params));
                }
                throw provider_not_found(algo_name(), provider);
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
