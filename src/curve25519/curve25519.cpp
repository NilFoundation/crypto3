#include <nil/crypto3/pubkey/curve25519.hpp>
#include <nil/crypto3/pubkey/pk_ops_impl.hpp>

#include <nil/crypto3/asn1/der_enc.hpp>
#include <nil/crypto3/asn1/ber_dec.hpp>

#include <nil/crypto3/random/random.hpp>

namespace nil {
    namespace crypto3 {

        void curve25519_basepoint(uint8_t mypublic[32], const uint8_t secret[32]) {
            const uint8_t basepoint[32] = {9};
            curve25519_donna(mypublic, secret, basepoint);
        }

        namespace {

            void size_check(size_t size, const char *thing) {
                if (size != 32) {
                    throw decoding_error("Invalid size " + std::to_string(size) + " for Curve25519 " + thing);
                }
            }

            secure_vector<uint8_t> curve25519(const secure_vector<uint8_t> &secret, const uint8_t pubval[32]) {
                secure_vector<uint8_t> out(32);
                curve25519_donna(out.data(), secret.data(), pubval);
                return out;
            }

        }

        algorithm_identifier curve25519_public_key::get_algorithm_identifier() const {
            // get_algorithm_identifier::USE_NULL_PARAM puts 0x05 0x00 in parameters
            // We want nothing
            std::vector<uint8_t> empty;
            return algorithm_identifier(oid(), empty);
        }

        bool curve25519_public_key::check_key(random_number_generator &, bool) const {
            return true; // no tests possible?
        }

        curve25519_public_key::curve25519_public_key(const algorithm_identifier &,
                                                     const std::vector<uint8_t> &key_bits) {
            m_public = key_bits;

            size_check(m_public.size(), "public key");
        }

        std::vector<uint8_t> curve25519_public_key::public_key_bits() const {
            return m_public;
        }

        curve25519_private_key::curve25519_private_key(const secure_vector<uint8_t> &secret_key) {
            if (secret_key.size() != 32) {
                throw decoding_error("Invalid size for Curve25519 private key");
            }

            m_public.resize(32);
            m_private = secret_key;
            curve25519_basepoint(m_public.data(), m_private.data());
        }

        curve25519_private_key::curve25519_private_key(random_number_generator &rng) {
            m_private = rng.random_vec(32);
            m_public.resize(32);
            curve25519_basepoint(m_public.data(), m_private.data());
        }

        curve25519_private_key::curve25519_private_key(const algorithm_identifier &,
                                                       const secure_vector<uint8_t> &key_bits) {
            ber_decoder(key_bits).decode(m_private, OCTET_STRING).discard_remaining();

            size_check(m_private.size(), "private key");
            m_public.resize(32);
            curve25519_basepoint(m_public.data(), m_private.data());
        }

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