#include <nil/crypto3/pubkey/curve25519.hpp>
#include <nil/crypto3/pubkey/pk_ops_impl.hpp>

#include <nil/crypto3/asn1/der_enc.hpp>
#include <nil/crypto3/asn1/ber_dec.hpp>

#include <nil/crypto3/random/random.hpp>

namespace nil {
    namespace crypto3 {
        secure_vector<uint8_t> curve25519_private_key::private_key_bits() const {
            return der_encoder().encode(m_private, OCTET_STRING).get_contents();
        }

        bool curve25519_private_key::check_key(random_number_generator &, bool) const {
            std::vector<uint8_t> public_point(32);
            curve25519_basepoint(public_point.data(), m_private.data());
            return public_point == m_public;
        }

        secure_vector<uint8_t> curve25519_private_key::agree(const uint8_t w[], size_t w_len) const {
            size_check(w_len, "public value");
            return curve25519(m_private, w);
        }

        namespace {

/**
* Curve25519 operation
*/
            class curve25519_ka_operation final : public pk_operations::key_agreement_with_kdf {
            public:

                curve25519_ka_operation(const curve25519_private_key &key, const std::string &kdf)
                        : pk_operations::key_agreement_with_kdf(kdf), m_key(key) {
                }

                secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override {
                    return m_key.agree(w, w_len);
                }

            private:
                const curve25519_private_key &m_key;
            };

        }

        std::unique_ptr<pk_operations::key_agreement> curve25519_private_key::create_key_agreement_op(
                random_number_generator & /*random*/, const std::string &params, const std::string &provider) const {
            if (provider == "core" || provider.empty()) {
                return std::unique_ptr<pk_operations::key_agreement>(new curve25519_ka_operation(*this, params));
            }
            throw Provider_Not_Found(algo_name(), provider);
        }
    }
}