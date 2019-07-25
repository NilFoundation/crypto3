#include <nil/crypto3/pubkey/ecdh.hpp>
#include <nil/crypto3/pubkey/pk_ops_impl.hpp>

#include <boost/multiprecision/prime.hpp>
#include <boost/multiprecision/modular_inverse.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
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

                        const point_gfp S
                            = m_group.blinded_var_point_multiply(input_point, m_l_times_priv, m_rng, m_ws);

                        if (!S.on_the_curve()) {
                            throw Internal_Error("ECDH agreed value was not on the curve");
                        }
                        return boost::multiprecision::cpp_int::encode_1363(S.get_affine_x(), m_group.get_p_bytes());
                    }

                private:
                    const ec_group m_group;
                    boost::multiprecision::cpp_int m_l_times_priv;
                    random_number_generator &m_rng;
                    std::vector<boost::multiprecision::cpp_int> m_ws;
                };

            }    // namespace

            std::unique_ptr<pk_operations::key_agreement>
                ecdh_private_key::create_key_agreement_op(random_number_generator &rng, const std::string &params,
                                                          const std::string &provider) const {
                return std::unique_ptr<pk_operations::key_agreement>(new ecdh_ka_operation(*this, params, rng));

                throw Provider_Not_Found(algo_name(), provider);
            }
        }    // namespace pubkey
    }        // namespace crypto3
}