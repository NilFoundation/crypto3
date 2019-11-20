#include <nil/crypto3/pubkey/dh.hpp>
#include <nil/crypto3/pubkey/pk_ops_impl.hpp>
#include <nil/crypto3/multiprecision/pow_mod.hpp>
#include <nil/crypto3/pubkey/blinding.hpp>
#include <nil/crypto3/multiprecision/modular_inverse.hpp>

namespace nil {
    namespace crypto3 {
        namespace {

/**
* DH operation
*/
            class dh_ka_operation final : public pk_operations::key_agreement_with_kdf {
            public:

                dh_ka_operation(const dh_private_key &key, const std::string &kdf, random_number_generator &rng)
                        : pk_operations::key_agreement_with_kdf(kdf), m_p(key.group_p()),
                        m_powermod_x_p(key.get_x(), m_p), m_blinder(m_p, rng, [](const boost::multiprecision::number<Backend, ExpressionTemplates> &k) {
                            return k;
                        }, [this](const boost::multiprecision::number<Backend, ExpressionTemplates> &k) {
                            return m_powermod_x_p(inverse_mod(k, m_p));
                        }) {
                }

                secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override;

            private:
                const boost::multiprecision::number<Backend, ExpressionTemplates> &m_p;

                fixed_exponent_power_mod m_powermod_x_p;
                blinder m_blinder;
            };

            secure_vector<uint8_t> dh_ka_operation::raw_agree(const uint8_t w[], size_t w_len) {
                boost::multiprecision::number<Backend, ExpressionTemplates> x = boost::multiprecision::number<Backend, ExpressionTemplates>::decode(w, w_len);

                if (x <= 1 || x >= m_p - 1) {
                    throw std::invalid_argument("DH agreement - invalid key provided");
                }

                x = m_blinder.blind(x);
                x = m_powermod_x_p(x);
                x = m_blinder.unblind(x);

                return boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(x, m_p.bytes());
            }

        }

        std::unique_ptr<pk_operations::key_agreement> dh_private_key::create_key_agreement_op(
                random_number_generator &rng, const std::string &params, const std::string &provider) const {
            if (provider == "core" || provider.empty()) {
                return std::unique_ptr<pk_operations::key_agreement>(new dh_ka_operation(*this, params, rng));
            }
            throw Provider_Not_Found(algo_name(), provider);
        }
    }
}
