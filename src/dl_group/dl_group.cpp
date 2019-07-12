#include <nil/crypto3/pubkey/dl_group.hpp>

#include <nil/crypto3/multiprecision/modular_inverse.hpp>
#include <nil/crypto3/multiprecision/modular_reduce.hpp>
#include <nil/crypto3/multiprecision/monty.hpp>

#include <nil/crypto3/asn1/der_enc.hpp>
#include <nil/crypto3/pubkey/pem.hpp>
#include <nil/crypto3/pubkey/workfactor.hpp>
#include <nil/crypto3/pubkey/dl_group/dl_group.hpp>

namespace nil {
    namespace crypto3 {

        class dl_group_data final {
        public:
            dl_group_data(const cpp_int &p, const cpp_int &q, const cpp_int &g) : m_p(p), m_q(q), m_g(g), m_mod_p(p),
                    m_monty_params(std::make_shared<montgomery_params>(m_p, m_mod_p)),
                    m_monty(monty_precompute(m_monty_params, m_g, /*window bits=*/4)), m_p_bits(p.bits()),
                    m_estimated_strength(dl_work_factor(m_p_bits)), m_exponent_bits(dl_exponent_size(m_p_bits)) {
            }

            ~dl_group_data() = default;

            dl_group_data(const dl_group_data &other) = delete;

            dl_group_data &operator=(const dl_group_data &other) = delete;

            const cpp_int &p() const {
                return m_p;
            }

            const cpp_int &q() const {
                return m_q;
            }

            const cpp_int &g() const {
                return m_g;
            }

            cpp_int mod_p(const cpp_int &x) const {
                return m_mod_p.reduce(x);
            }

            cpp_int multiply_mod_p(const cpp_int &x, const cpp_int &y) const {
                return m_mod_p.multiply(x, y);
            }

            std::shared_ptr<const montgomery_params> monty_params_p() const {
                return m_monty_params;
            }

            size_t p_bits() const {
                return m_p_bits;
            }

            size_t p_bytes() const {
                return (m_p_bits + 7) / 8;
            }

            size_t estimated_strength() const {
                return m_estimated_strength;
            }

            size_t exponent_bits() const {
                return m_exponent_bits;
            }

            cpp_int power_g_p(const cpp_int &k) const {
                return monty_execute(*m_monty, k);
            }

        private:
            cpp_int m_p;
            cpp_int m_q;
            cpp_int m_g;
            modular_reducer m_mod_p;
            std::shared_ptr<const montgomery_params> m_monty_params;
            std::shared_ptr<const montgomery_exponentation_state> m_monty;
            size_t m_p_bits;
            size_t m_estimated_strength;
            size_t m_exponent_bits;
        };

//static
        std::shared_ptr<dl_group_data> dl_group::ber_decode_dl_group(const uint8_t *data, size_t data_len,
                                                                     dl_group::format format) {
            cpp_int p, q, g;

            ber_decoder decoder(data, data_len);
            ber_decoder ber = decoder.start_cons(SEQUENCE);

            if (format == dl_group::ANSI_X9_57) {
                ber.decode(p).decode(q).decode(g).verify_end();
            } else if (format == dl_group::ANSI_X9_42) {
                ber.decode(p).decode(g).decode(q).discard_remaining();
            } else if (format == dl_group::PKCS_3) {
                // q is left as zero
                ber.decode(p).decode(g).discard_remaining();
            } else {
                throw std::invalid_argument("Unknown dl_group encoding " + std::to_string(format));
            }

            return std::make_shared<dl_group_data>(p, q, g);
        }

        namespace {

            dl_group::format pem_label_to_dl_format(const std::string &label) {
                if (label == "DH PARAMETERS") {
                    return dl_group::PKCS_3;
                } else if (label == "DSA PARAMETERS") {
                    return dl_group::ANSI_X9_57;
                } else if (label == "X942 DH PARAMETERS" || label == "X9.42 DH PARAMETERS") {
                    return dl_group::ANSI_X9_42;
                } else {
                    throw decoding_error("dl_group: Invalid PEM label " + label);
                }
            }

        }

        namespace {

/*
* Create generator of the q-sized subgroup (DSA style generator)
*/
            cpp_int make_dsa_generator(const cpp_int &p, const cpp_int &q) {
                const cpp_int e = (p - 1) / q;

                if (e == 0 || (p - 1) % q > 0) {
                    throw std::invalid_argument("make_dsa_generator q does not divide p-1");
                }

                for (size_t i = 0; i != PRIME_TABLE_SIZE; ++i) {
                    // TODO precompute!
                    cpp_int g = power_mod(PRIMES[i], e, p);
                    if (g > 1) {
                        return g;
                    }
                }

                throw Internal_Error("dl_group: Couldn't create a suitable generator");
            }

        }

        const dl_group_data &dl_group::data() const {
            if (m_data) {
                return *m_data;
            }

            throw Invalid_State("dl_group uninitialized");
        }

        bool dl_group::verify_element_pair(const cpp_int &y, const cpp_int &x) const {
            const cpp_int &p = get_p();

            if (y <= 1 || y >= p || x <= 1 || x >= p) {
                return false;
            }

            if (y != power_g_p(x)) {
                return false;
            }

            return true;
        }

        std::shared_ptr<const montgomery_params> dl_group::monty_params_p() const {
            return data().monty_params_p();
        }

        size_t dl_group::p_bits() const {
            return data().p_bits();
        }

        size_t dl_group::p_bytes() const {
            return data().p_bytes();
        }

        size_t dl_group::estimated_strength() const {
            return data().estimated_strength();
        }

        size_t dl_group::exponent_bits() const {
            return data().exponent_bits();
        }

        cpp_int dl_group::inverse_mod_p(const cpp_int &x) const {
            // precompute??
            return inverse_mod(x, get_p());
        }

        cpp_int dl_group::mod_p(const cpp_int &x) const {
            return data().mod_p(x);
        }

        cpp_int dl_group::multiply_mod_p(const cpp_int &x, const cpp_int &y) const {
            return data().multiply_mod_p(x, y);
        }

        cpp_int dl_group::multi_exponentiate(const cpp_int &x, const cpp_int &y, const cpp_int &z) const {
            return monty_multi_exp(data().monty_params_p(), get_g(), x, y, z);
        }

        cpp_int dl_group::power_g_p(const cpp_int &x) const {
            return data().power_g_p(x);
        }

/*
* DER encode the parameters
*/
        std::vector<uint8_t> dl_group::der_encode(format format) const {
            if (get_q() == 0 && (format == ANSI_X9_57 || format == ANSI_X9_42)) {
                throw Encoding_Error("Cannot encode dl_group in ANSI formats when q param is missing");
            }

            if (format == ANSI_X9_57) {
                return der_encoder().start_cons(SEQUENCE).encode(get_p()).encode(get_q()).encode(
                        get_g()).end_cons().get_contents_unlocked();
            } else if (format == ANSI_X9_42) {
                return der_encoder().start_cons(SEQUENCE).encode(get_p()).encode(get_g()).encode(
                        get_q()).end_cons().get_contents_unlocked();
            } else if (format == PKCS_3) {
                return der_encoder().start_cons(SEQUENCE).encode(get_p()).encode(
                        get_g()).end_cons().get_contents_unlocked();
            }

            throw std::invalid_argument("Unknown dl_group encoding " + std::to_string(format));
        }

/*
* PEM encode the parameters
*/
        std::string dl_group::pem_encode(format format) const {
            const std::vector<uint8_t> encoding = der_encode(format);

            if (format == PKCS_3) {
                return pem_code::encode(encoding, "DH PARAMETERS");
            } else if (format == ANSI_X9_57) {
                return pem_code::encode(encoding, "DSA PARAMETERS");
            } else if (format == ANSI_X9_42) {
                return pem_code::encode(encoding, "X9.42 DH PARAMETERS");
            } else {
                throw std::invalid_argument("Unknown dl_group encoding " + std::to_string(format));
            }
        }

        void dl_group::ber_decode(const std::vector<uint8_t> &ber, format format) {
            m_data = ber_decode_dl_group(ber.data(), ber.size(), format);
        }

/*
* Decode PEM encoded parameters
*/
        void dl_group::pem_decode(const std::string &pem) {
            std::string label;
            const std::vector<uint8_t> ber = unlock(pem_code::decode(pem, label));
            format format = pem_label_to_dl_format(label);

            m_data = ber_decode_dl_group(ber.data(), ber.size(), format);
        }

    }
}
