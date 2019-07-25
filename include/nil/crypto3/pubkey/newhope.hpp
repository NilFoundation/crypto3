#ifndef CRYPTO3_PUBKEY_NEWHOPE_HPP
#define CRYPTO3_PUBKEY_NEWHOPE_HPP

#include <nil/crypto3/utilities/memory_operations.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            class random_number_generator;

            /*
             * WARNING: This API is preliminary and will change
             * Currently pubkey.h does not support a 2-phase KEM scheme of
             * the sort NEWHOPE exports.
             */

            // TODO: change to just a secure_vector
            class newhope_poly final {
            public:
                uint16_t coeffs[1024];

                ~newhope_poly() {
                    secure_scrub_memory(coeffs, sizeof(coeffs));
                }
            };

            enum newhope_params {
                NEWHOPE_SENDABYTES = 1824,
                NEWHOPE_SENDBBYTES = 2048,

                NEWHOPE_OFFER_BYTES = 1824,
                NEWHOPE_ACCEPT_BYTES = 2048,
                NEWHOPE_SHARED_KEY_BYTES = 32,

                NEWHOPE_SEED_BYTES = 32,
                NEWHOPE_POLY_BYTES = 1792,

                CECPQ1_OFFER_BYTES = NEWHOPE_OFFER_BYTES + 32,
                CECPQ1_ACCEPT_BYTES = NEWHOPE_ACCEPT_BYTES + 32,
                CECPQ1_SHARED_KEY_BYTES = NEWHOPE_SHARED_KEY_BYTES + 32
            };

            /**
             * This chooses the XOF + hash for NewHope
             * The official NewHope specification and reference implementation use
             * SHA-3 and SHAKE-128. BoringSSL instead uses SHA-256 and AES-128 in
             * CTR mode. CECPQ1 (x25519+NewHope) always uses BoringSSL's mode
             */
            enum class newhope_mode { SHA3, BoringSSL };

            // offer
            void newhope_keygen(uint8_t send[NEWHOPE_SENDABYTES], newhope_poly *sk, random_number_generator &rng,
                                newhope_mode = newhope_mode::SHA3);

            // accept
            void newhope_sharedb(uint8_t sharedkey[NEWHOPE_SHARED_KEY_BYTES], uint8_t send[], const uint8_t *received,
                                 random_number_generator &rng, newhope_mode mode = newhope_mode::SHA3);

            // finish
            void newhope_shareda(uint8_t sharedkey[NEWHOPE_SHARED_KEY_BYTES], const newhope_poly *ska,
                                 const uint8_t *received, newhope_mode mode = newhope_mode::SHA3);
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
