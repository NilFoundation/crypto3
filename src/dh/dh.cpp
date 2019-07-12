#include <nil/crypto3/pubkey/dh.hpp>
#include <nil/crypto3/pubkey/pk_ops_impl.hpp>
#include <nil/crypto3/multiprecision/pow_mod.hpp>
#include <nil/crypto3/pubkey/blinding.hpp>
#include <nil/crypto3/multiprecision/modular_inverse.hpp>

namespace nil {
    namespace crypto3 {

/*
* dh_public_key Constructor
*/
        dh_public_key::dh_public_key(const dl_group &grp, const boost::multiprecision::cpp_int &y1) {
            m_group = grp;
            m_y = y1;
        }

/*
* Return the public value for key agreement
*/
        std::vector<uint8_t> dh_public_key::public_value() const {
            return unlock(boost::multiprecision::cpp_int::encode_1363(m_y, group_p().bytes()));
        }

/*
* Create a DH private key
*/
        dh_private_key::dh_private_key(random_number_generator &rng, const dl_group &grp, const boost::multiprecision::cpp_int &x_arg) {
            m_group = grp;

            if (x_arg == 0) {
                m_x.randomize(rng, grp.exponent_bits());
            } else {
                m_x = x_arg;
            }

            if (m_y == 0) {
                m_y = m_group.power_g_p(m_x);
            }
        }

/*
* Load a DH private key
*/
        dh_private_key::dh_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits)
                : dl_scheme_private_key(alg_id, key_bits, dl_group::ANSI_X9_42) {
            if (m_y == 0) {
                m_y = m_group.power_g_p(m_x);
            }
        }

/*
* Return the public value for key agreement
*/
        std::vector<uint8_t> dh_private_key::public_value() const {
            return dh_public_key::public_value();
        }

        namespace {

/**
* DH operation
*/
            class dh_ka_operation final : public pk_operations::key_agreement_with_kdf {
            public:

                dh_ka_operation(const dh_private_key &key, const std::string &kdf, random_number_generator &rng)
                        : pk_operations::key_agreement_with_kdf(kdf), m_p(key.group_p()),
                        m_powermod_x_p(key.get_x(), m_p), m_blinder(m_p, rng, [](const boost::multiprecision::cpp_int &k) {
                            return k;
                        }, [this](const boost::multiprecision::cpp_int &k) {
                            return m_powermod_x_p(inverse_mod(k, m_p));
                        }) {
                }

                secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override;

            private:
                const boost::multiprecision::cpp_int &m_p;

                fixed_exponent_power_mod m_powermod_x_p;
                blinder m_blinder;
            };

            secure_vector<uint8_t> dh_ka_operation::raw_agree(const uint8_t w[], size_t w_len) {
                boost::multiprecision::cpp_int x = boost::multiprecision::cpp_int::decode(w, w_len);

                if (x <= 1 || x >= m_p - 1) {
                    throw std::invalid_argument("DH agreement - invalid key provided");
                }

                x = m_blinder.blind(x);
                x = m_powermod_x_p(x);
                x = m_blinder.unblind(x);

                return boost::multiprecision::cpp_int::encode_1363(x, m_p.bytes());
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
