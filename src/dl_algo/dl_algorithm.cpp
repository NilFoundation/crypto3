#include <nil/crypto3/pubkey/dl_group/dl_group.hpp>
#include <nil/crypto3/pubkey/dl_group/dl_algorithm.hpp>

#include <nil/crypto3/asn1/der_enc.hpp>
#include <nil/crypto3/asn1/ber_dec.hpp>

namespace nil {
    namespace crypto3 {

        size_t dl_scheme_public_key::key_length() const {
            return m_group.p_bits();
        }

        size_t dl_scheme_public_key::estimated_strength() const {
            return m_group.estimated_strength();
        }

        algorithm_identifier dl_scheme_public_key::get_algorithm_identifier() const {
            return algorithm_identifier(oid(), m_group.der_encode(group_format()));
        }

        std::vector<uint8_t> dl_scheme_public_key::public_key_bits() const {
            return der_encoder().encode(m_y).get_contents_unlocked();
        }

        dl_scheme_public_key::dl_scheme_public_key(const dl_group &group, const boost::multiprecision::cpp_int &y) : m_y(y), m_group(group) {
        }

        dl_scheme_public_key::dl_scheme_public_key(const algorithm_identifier &alg_id,
                                                   const std::vector<uint8_t> &key_bits, dl_group::format format)
                : m_group(alg_id.get_parameters(), format) {
            ber_decoder(key_bits).decode(m_y);
        }

        secure_vector<uint8_t> dl_scheme_private_key::private_key_bits() const {
            return der_encoder().encode(m_x).get_contents();
        }

        dl_scheme_private_key::dl_scheme_private_key(const algorithm_identifier &alg_id,
                                                     const secure_vector<uint8_t> &key_bits, dl_group::format format) {
            m_group.ber_decode(alg_id.get_parameters(), format);

            ber_decoder(key_bits).decode(m_x);
        }

/*
* Check Public DL Parameters
*/
        bool dl_scheme_public_key::check_key(random_number_generator &rng, bool strong) const {
            return m_group.verify_group(rng, strong) && m_group.verify_public_element(m_y);
        }

/*
* Check DL Scheme Private Parameters
*/
        bool dl_scheme_private_key::check_key(random_number_generator &rng, bool strong) const {
            return m_group.verify_group(rng, strong) && m_group.verify_element_pair(m_y, m_x);
        }
    }
}
