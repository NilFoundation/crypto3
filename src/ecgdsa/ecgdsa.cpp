#include <nil/crypto3/pubkey/ecgdsa.hpp>
#include <nil/crypto3/pubkey/pk_ops_impl.hpp>
#include <nil/crypto3/pubkey/keypair.hpp>

#include <boost/multiprecision/modular_inverse.hpp>
#include <boost/multiprecision/montgomery_int/modular_reduce.hpp>

namespace nil {
    namespace crypto3 {
        namespace {

/**
* ECGDSA signature operation
*/
            class ecgdsa_signature_operation final : public pk_operations::signature_with_emsa {
            public:

                ecgdsa_signature_operation(const ecgdsa_private_key &ecgdsa, const std::string &emsa)
                        : pk_operations::signature_with_emsa(emsa), m_group(ecgdsa.domain()),
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
                const boost::multiprecision::number<Backend, ExpressionTemplates> m(msg, msg_len, m_group.get_order_bits());

                const boost::multiprecision::number<Backend, ExpressionTemplates> k = m_group.random_scalar(rng);

                const boost::multiprecision::number<Backend, ExpressionTemplates> r = m_group.mod_order(m_group.blinded_base_point_multiply_x(k, rng, m_ws));

                const boost::multiprecision::number<Backend, ExpressionTemplates> kr = m_group.multiply_mod_order(k, r);

                const boost::multiprecision::number<Backend, ExpressionTemplates> s = m_group.multiply_mod_order(m_x, kr - m);

                // With overwhelming probability, a bug rather than actual zero r/s
                if (r.is_zero() || s.is_zero()) {
                    throw internal_error("During ECGDSA signature generated zero r/s");
                }

                return boost::multiprecision::number<Backend, ExpressionTemplates>::encode_fixed_length_int_pair(r, s, m_group.get_order_bytes());
            }

/**
* ECGDSA verification operation
*/
            class ecgdsa_verification_operation final : public pk_operations::verification_with_emsa {
            public:

                ecgdsa_verification_operation(const ecgdsa_public_key &ecgdsa, const std::string &emsa)
                        : pk_operations::verification_with_emsa(emsa), m_group(ecgdsa.domain()),
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

                const boost::multiprecision::number<Backend, ExpressionTemplates> e(msg, msg_len, m_group.get_order_bits());

                const boost::multiprecision::number<Backend, ExpressionTemplates> r(sig, sig_len / 2);
                const boost::multiprecision::number<Backend, ExpressionTemplates> s(sig + sig_len / 2, sig_len / 2);

                if (r <= 0 || r >= m_group.get_order() || s <= 0 || s >= m_group.get_order()) {
                    return false;
                }

                const boost::multiprecision::number<Backend, ExpressionTemplates> w = inverse_mod(r, m_group.get_order());

                const boost::multiprecision::number<Backend, ExpressionTemplates> u1 = m_group.multiply_mod_order(e, w);
                const boost::multiprecision::number<Backend, ExpressionTemplates> u2 = m_group.multiply_mod_order(s, w);
                const point_gfp R = m_group.point_multiply(u1, m_public_point, u2);

                if (R.is_zero()) {
                    return false;
                }

                const boost::multiprecision::number<Backend, ExpressionTemplates> v = m_group.mod_order(R.get_affine_x());
                return (v == r);
            }

        }

        std::unique_ptr<pk_operations::verification> ecgdsa_public_key::create_verification_op(
                const std::string &params, const std::string &provider) const {
            if (provider == "core" || provider.empty()) {
                return std::unique_ptr<pk_operations::verification>(new ecgdsa_verification_operation(*this, params));
            }
            throw Provider_Not_Found(algo_name(), provider);
        }

        std::unique_ptr<pk_operations::signature> ecgdsa_private_key::create_signature_op(
                random_number_generator & /*random*/, const std::string &params, const std::string &provider) const {
            if (provider == "core" || provider.empty()) {
                return std::unique_ptr<pk_operations::signature>(new ecgdsa_signature_operation(*this, params));
            }
            throw Provider_Not_Found(algo_name(), provider);
        }
    }
}
