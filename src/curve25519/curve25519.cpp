#include <nil/crypto3/pubkey/curve25519.hpp>
#include <nil/crypto3/pubkey/pk_ops_impl.hpp>

#include <nil/crypto3/asn1/der_enc.hpp>
#include <nil/crypto3/asn1/ber_dec.hpp>

#include <nil/crypto3/random/random.hpp>

namespace nil {
    namespace crypto3 {
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