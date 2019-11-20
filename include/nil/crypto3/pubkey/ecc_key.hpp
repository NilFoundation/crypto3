#ifndef CRYPTO3_PUBKEY_ECC_PUBLIC_KEY_BASE_HPP
#define CRYPTO3_PUBKEY_ECC_PUBLIC_KEY_BASE_HPP

#include <nil/crypto3/pubkey/ec_group/ec_group.hpp>
#include <nil/crypto3/pubkey/pk_keys.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            /**
             * This class represents abstract ECC public keys. When encoding a key
             * via an encoder that can be accessed via the corresponding member
             * functions, the key will decide upon its internally stored encoding
             * information whether to encode itself with or without domain
             * parameters, or using the domain parameter oid. Furthermore, a public
             * key without domain parameters can be decoded. In that case, it
             * cannot be used for verification until its domain parameters are set
             * by calling the corresponding member function.
             */
            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            class ec_public_key : public virtual public_key_policy {
            public:
                typedef NumberType number_type;
                typedef CurveType curve_type;
                /**
                 * Create a public key.
                 * @param dom_par EC domain parameters
                 * @param pub_point public point on the curve
                 */
                ec_public_key(const ec_group<CurveType> &dom_par, const point_gfp<NumberType> &pub_point) :
                    m_domain_params(dom_par), m_public_key(pub_point) {
                    if (!dom_par.get_curve_oid().empty()) {
                        m_domain_encoding = EC_DOMPAR_ENC_OID;
                    } else {
                        m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
                    }

#if 0
                    if(domain().get_curve() != public_point().get_curve())
               throw std::invalid_argument("ec_public_key: curve mismatch in constructor");
#endif
                }

                /**
                 * Load a public key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded public key bits
                 */
                ec_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits) :
                    m_domain_params {ec_group(alg_id.get_parameters())}, m_public_key {domain().OS2ECP(key_bits)} {
                    if (!domain().get_curve_oid().empty()) {
                        m_domain_encoding = EC_DOMPAR_ENC_OID;
                    } else {
                        m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
                    }
                }

                ec_public_key(const ec_public_key &other) = default;

                ec_public_key &operator=(const ec_public_key &other) = default;

                virtual ~ec_public_key() = default;

                /**
                 * Get the public point of this key.
                 * @throw Invalid_State is thrown if the
                 * domain parameters of this point are not set
                 * @result the public point of this key
                 */
                const point_gfp<NumberType> &public_point() const {
                    return m_public_key;
                }

                algorithm_identifier get_algorithm_identifier() const override {
                    return algorithm_identifier(oid_t(), der_domain());
                }

                std::vector<uint8_t> public_key_bits() const override {
                    return public_point().encode(point_encoding());
                }

                template<typename UniformRandomGenerator>
                bool check_key(UniformRandomGenerator &rng, bool strong) const override {
                    return m_domain_params.verify_group(rng) && m_domain_params.verify_public_element(public_point());
                }

                /**
                 * Get the domain parameters of this key.
                 * @throw Invalid_State is thrown if the
                 * domain parameters of this point are not set
                 * @result the domain parameters of this key
                 */
                const ec_group<CurveType> &domain() const {
                    return m_domain_params;
                }

                /**
                 * Set the domain parameter encoding to be used when encoding this key.
                 * @param enc the encoding to use
                 */
                void set_parameter_encoding(ec_group_encoding enc) {
                    if (form != EC_DOMPAR_ENC_EXPLICIT && form != EC_DOMPAR_ENC_IMPLICITCA &&
                        form != EC_DOMPAR_ENC_OID) {
                        throw std::invalid_argument("Invalid encoding form for EC-key object specified");
                    }

                    if ((form == EC_DOMPAR_ENC_OID) && (m_domain_params.get_curve_oid().empty())) {
                        throw std::invalid_argument(
                            "Invalid encoding form oid_t specified for "
                            "EC-key object whose corresponding domain "
                            "parameters are without oid_t");
                    }

                    m_domain_encoding = form;
                }

                /**
                 * Set the point encoding method to be used when encoding this key.
                 * @param enc the encoding to use
                 */
                void set_point_encoding(typename point_gfp<NumberType>::compression_type enc) {
                    if (enc != point_gfp::COMPRESSED && enc != point_gfp::UNCOMPRESSED && enc != point_gfp::HYBRID) {
                        throw std::invalid_argument("Invalid point encoding for ec_public_key");
                    }

                    m_point_encoding = enc;
                }

                /**
                 * Return the DER encoding of this keys domain in whatever format
                 * is preset for this particular key
                 */
                std::vector<uint8_t> der_domain() const {
                    return domain().der_encode(domain_format());
                }

                /**
                 * Get the domain parameter encoding to be used when encoding this key.
                 * @result the encoding to use
                 */
                ec_group_encoding domain_format() const {
                    return m_domain_encoding;
                }

                /**
                 * Get the point encoding method to be used when encoding this key.
                 * @result the encoding to use
                 */
                typename point_gfp<NumberType>::compression_type point_encoding() const {
                    return m_point_encoding;
                }

                size_t key_length() const override {
                    return domain().get_p_bits();
                }

                size_t estimated_strength() const override {
                    return ecp_work_factor(key_length());
                }

            protected:
                ec_public_key() : m_domain_params {}, m_public_key {}, m_domain_encoding(EC_DOMPAR_ENC_EXPLICIT) {
                }

                ec_group<CurveType> m_domain_params;
                point_gfp<NumberType> m_public_key;
                ec_group_encoding m_domain_encoding;
                typename point_gfp<NumberType>::compression_type m_point_encoding =
                    typename point_gfp<NumberType>::UNCOMPRESSED;
            };

            /**
             * This abstract class represents ECC private keys
             */
            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            class ec_private_key : public ec_public_key<CurveType, NumberType>, public private_key_policy {
            public:
                typedef typename ec_public_key<CurveType, NumberType>::curve_type curve_type;
                typedef typename ec_public_key<CurveType, NumberType>::number_type number_type;
                /*
                 * If x=0, creates a new private key in the domain
                 * using the given random. If with_modular_inverse is set,
                 * the public key will be calculated by multiplying
                 * the core point with the modular inverse of
                 * x (as in ECGDSA and ECKCDSA), otherwise by
                 * multiplying directly with x (as in ECDSA).
                 */
                template<typename UniformRandomGenerator, typename Backend,
                         expression_template_option ExpressionTemplates>
                ec_private_key(UniformRandomGenerator &rng, const ec_group<CurveType, NumberType> &domain,
                               const number<Backend, ExpressionTemplates> &x, bool with_modular_inverse = false) {
                    m_domain_params = ec_group;
                    if (!ec_group.get_curve_oid().empty()) {
                        m_domain_encoding = EC_DOMPAR_ENC_OID;
                    } else {
                        m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
                    }

                    const typename ec_group<CurveType>::number_type &order = m_domain_params.get_order();

                    m_private_key = x;

                    // Can't use random here because ffi load functions use null_rng
                    if (with_modular_inverse) {
                        // ECKCDSA
                        m_public_key = domain().get_base_point() * inverse_mod(m_private_key, order);
                    } else {
                        m_public_key = domain().get_base_point() * m_private_key;
                    }

                    BOOST_ASSERT_MSG(m_public_key.on_the_curve(), "Generated public key point was on the curve");
                }

                /*
                 * Creates a new private key object from the
                 * ECPrivateKey structure given in key_bits.
                 * If with_modular_inverse is set,
                 * the public key will be calculated by multiplying
                 * the core point with the modular inverse of
                 * x (as in ECGDSA and ECKCDSA), otherwise by
                 * multiplying directly with x (as in ECDSA).
                 */
                ec_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits,
                               bool with_modular_inverse = false) {
                    m_domain_params = ec_group(alg_id.get_parameters());
                    m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;

                    if (!domain().get_curve_oid().empty()) {
                        m_domain_encoding = EC_DOMPAR_ENC_OID;
                    } else {
                        m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
                    }

                    oid_t key_parameters;
                    secure_vector<uint8_t> public_key_bits;

                    ber_decoder(key_bits)
                        .start_cons(SEQUENCE)
                        .decode_and_check<size_t>(1, "Unknown version code for ECC key")
                        .decode_octet_string_bigint(m_private_key)
                        .decode_optional(key_parameters, asn1_tag(0), PRIVATE)
                        .decode_optional_string(public_key_bits, BIT_STRING, 1, PRIVATE)
                        .end_cons();

                    if (public_key_bits.empty()) {
                        if (with_modular_inverse) {
                            // ECKCDSA
                            const typename ec_group<CurveType>::number_type &order = m_domain_params.get_order();
                            m_public_key = domain().get_base_point() * inverse_mod(m_private_key, order);
                        } else {
                            m_public_key = domain().get_base_point() * m_private_key;
                        }

                        BOOST_ASSERT_MSG(m_public_key.on_the_curve(),
                                         "Public point derived from loaded key was on the curve");
                    } else {
                        m_public_key = domain().OS2ECP(public_key_bits);
                        // os2ecp verifies that the point is on the curve
                    }
                }

                secure_vector<uint8_t> private_key_bits() const override {
                    return der_encoder()
                        .start_cons(SEQUENCE)
                        .encode(static_cast<size_t>(1))
                        .encode(number<Backend, ExpressionTemplates>::encode_1363(m_private_key, m_private_key.bytes()),
                                OCTET_STRING)
                        .end_cons()
                        .get_contents();
                }

                /**
                 * Get the private key value of this key object.
                 * @result the private key value of this key object
                 */
                const number_type &private_value() const {
                    if (m_private_key == 0) {
                        throw invalid_state("ec_private_key::private_value - uninitialized");
                    }

                    return m_private_key;
                }

                ec_private_key(const ec_private_key &other) = default;

                ec_private_key &operator=(const ec_private_key &other) = default;

                ~ec_private_key() = default;

            protected:
                ec_private_key() = default;

                number_type m_private_key;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
