#include <nil/crypto3/pubkey/ecc_key.hpp>
#include <nil/crypto3/pubkey/workfactor.hpp>

#include <nil/crypto3/multiprecision/prime.hpp>

#include <nil/crypto3/asn1/der_enc.hpp>
#include <nil/crypto3/asn1/ber_dec.hpp>
#include <nil/crypto3/multiprecision/modular_inverse.hpp>

namespace nil {
    namespace crypto3 {

        size_t ec_public_key::key_length() const {
            return domain().get_p_bits();
        }

        size_t ec_public_key::estimated_strength() const {
            return ecp_work_factor(key_length());
        }

        ec_public_key::ec_public_key(const ec_group &dom_par, const point_gfp &pub_point) : m_domain_params(dom_par),
                m_public_key(pub_point) {
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

        ec_public_key::ec_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits)
                : m_domain_params{ec_group(alg_id.get_parameters())}, m_public_key{domain().OS2ECP(key_bits)} {
            if (!domain().get_curve_oid().empty()) {
                m_domain_encoding = EC_DOMPAR_ENC_OID;
            } else {
                m_domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
            }
        }

        bool ec_public_key::check_key(random_number_generator &rng, bool) const {
            return m_domain_params.verify_group(rng) && m_domain_params.verify_public_element(public_point());
        }


        algorithm_identifier ec_public_key::get_algorithm_identifier() const {
            return algorithm_identifier(oid_t(), der_domain());
        }

        std::vector<uint8_t> ec_public_key::public_key_bits() const {
            return public_point().encode(point_encoding());
        }

        void ec_public_key::set_point_encoding(point_gfp::compression_type enc) {
            if (enc != point_gfp::COMPRESSED && enc != point_gfp::UNCOMPRESSED && enc != point_gfp::HYBRID) {
                throw std::invalid_argument("Invalid point encoding for ec_public_key");
            }

            m_point_encoding = enc;
        }

        void ec_public_key::set_parameter_encoding(ec_group_encoding form) {
            if (form != EC_DOMPAR_ENC_EXPLICIT && form != EC_DOMPAR_ENC_IMPLICITCA && form != EC_DOMPAR_ENC_OID) {
                throw std::invalid_argument("Invalid encoding form for EC-key object specified");
            }

            if ((form == EC_DOMPAR_ENC_OID) && (m_domain_params.get_curve_oid().empty())) {
                throw std::invalid_argument("Invalid encoding form oid_t specified for "
                                            "EC-key object whose corresponding domain "
                                            "parameters are without oid_t");
            }

            m_domain_encoding = form;
        }

        const boost::multiprecision::cpp_int &ec_private_key::private_value() const {
            if (m_private_key == 0) {
                throw Invalid_State("ec_private_key::private_value - uninitialized");
            }

            return m_private_key;
        }
    }
}
