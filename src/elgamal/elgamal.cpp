#include <nil/crypto3/pubkey/elgamal.hpp>
#include <nil/crypto3/pubkey/pk_ops_impl.hpp>
#include <nil/crypto3/pubkey/blinding.hpp>
#include <nil/crypto3/pubkey/keypair.hpp>

namespace nil {
    namespace crypto3 {

/*
* el_gamal_public_key Constructor
*/
        el_gamal_public_key::el_gamal_public_key(const dl_group &group, const cpp_int &y) : dl_scheme_public_key(group,
                y) {
        }

/*
* el_gamal_private_key Constructor
*/
        el_gamal_private_key::el_gamal_private_key(random_number_generator &rng, const dl_group &group,
                                                   const cpp_int &x) {
            m_x = x;
            m_group = group;

            if (m_x.is_zero()) {
                m_x.randomize(rng, group.exponent_bits());
            }

            m_y = m_group.power_g_p(m_x);
        }

        el_gamal_private_key::el_gamal_private_key(const algorithm_identifier &alg_id,
                                                   const secure_vector<uint8_t> &key_bits) : dl_scheme_private_key(
                alg_id, key_bits, dl_group::ANSI_X9_42) {
            m_y = m_group.power_g_p(m_x);
        }

/*
* Check Private ElGamal Parameters
*/
        bool el_gamal_private_key::check_key(random_number_generator &rng, bool strong) const {
            if (!dl_scheme_private_key::check_key(rng, strong)) {
                return false;
            }

            if (!strong) {
                return true;
            }

            return key_pair::encryption_consistency_check(rng, *this, "EME1(SHA-256)");
        }

        namespace {

/**
* ElGamal encryption operation
*/
            class el_gamal_encryption_operation final : public pk_operations::encryption_with_eme {
            public:

                size_t max_raw_input_bits() const override {
                    return m_group.p_bits() - 1;
                }

                el_gamal_encryption_operation(const el_gamal_public_key &key, const std::string &eme);

                secure_vector<uint8_t> raw_encrypt(const uint8_t msg[], size_t msg_len,
                                                   random_number_generator &rng) override;

            private:
                const dl_group m_group;
                fixed_base_power_mod m_powermod_y_p;
            };

            el_gamal_encryption_operation::el_gamal_encryption_operation(const el_gamal_public_key &key,
                                                                         const std::string &eme)
                    : pk_operations::encryption_with_eme(eme), m_group(key.get_group()),
                    m_powermod_y_p(key.get_y(), m_group.get_p()) {
            }

            secure_vector<uint8_t> el_gamal_encryption_operation::raw_encrypt(const uint8_t msg[], size_t msg_len,
                                                                              random_number_generator &rng) {
                cpp_int m(msg, msg_len);

                if (m >= m_group.get_p()) {
                    throw std::invalid_argument("ElGamal encryption: Input is too large");
                }

                const size_t k_bits = m_group.exponent_bits();
                const cpp_int k(rng, k_bits);

                const cpp_int a = m_group.power_g_p(k);
                const cpp_int b = m_group.multiply_mod_p(m, m_powermod_y_p(k));

                return cpp_int::encode_fixed_length_int_pair(a, b, m_group.p_bytes());
            }

/**
* ElGamal decryption operation
*/
            class el_gamal_decryption_operation final : public pk_operations::decryption_with_eme {
            public:

                el_gamal_decryption_operation(const el_gamal_private_key &key, const std::string &eme,
                                              random_number_generator &rng);

                secure_vector<uint8_t> raw_decrypt(const uint8_t msg[], size_t msg_len) override;

            private:
                const dl_group m_group;
                fixed_exponent_power_mod m_powermod_x_p;
                blinder m_blinder;
            };

            el_gamal_decryption_operation::el_gamal_decryption_operation(const el_gamal_private_key &key,
                                                                         const std::string &eme,
                                                                         random_number_generator &rng)
                    : pk_operations::decryption_with_eme(eme), m_group(key.get_group()),
                    m_powermod_x_p(key.get_x(), m_group.get_p()), m_blinder(m_group.get_p(), rng, [](const cpp_int &k) {
                        return k;
                    }, [this](const cpp_int &k) {
                        return m_powermod_x_p(k);
                    }) {
            }

            secure_vector<uint8_t> el_gamal_decryption_operation::raw_decrypt(const uint8_t msg[], size_t msg_len) {
                const size_t p_bytes = m_group.p_bytes();

                if (msg_len != 2 * p_bytes) {
                    throw std::invalid_argument("ElGamal decryption: Invalid message");
                }

                cpp_int a(msg, p_bytes);
                const cpp_int b(msg + p_bytes, p_bytes);

                if (a >= m_group.get_p() || b >= m_group.get_p()) {
                    throw std::invalid_argument("ElGamal decryption: Invalid message");
                }

                a = m_blinder.blind(a);

                const cpp_int r = m_group.multiply_mod_p(m_group.inverse_mod_p(m_powermod_x_p(a)), b);

                return cpp_int::encode_1363(m_blinder.unblind(r), p_bytes);
            }

        }

        std::unique_ptr<pk_operations::encryption> el_gamal_public_key::create_encryption_op(
                random_number_generator & /*random*/, const std::string &params, const std::string &provider) const {
            if (provider == "core" || provider.empty()) {
                return std::unique_ptr<pk_operations::encryption>(new el_gamal_encryption_operation(*this, params));
            }
            throw Provider_Not_Found(algo_name(), provider);
        }

        std::unique_ptr<pk_operations::decryption> el_gamal_private_key::create_decryption_op(
                random_number_generator &rng, const std::string &params, const std::string &provider) const {
            if (provider == "core" || provider.empty()) {
                return std::unique_ptr<pk_operations::decryption>(
                        new el_gamal_decryption_operation(*this, params, rng));
            }
            throw Provider_Not_Found(algo_name(), provider);
        }
    }
}
