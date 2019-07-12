#include <nil/crypto3/pubkey/ceccpq1/cecpq1.hpp>
#include <nil/crypto3/pubkey/newhope/newhope.hpp>
#include <nil/crypto3/pubkey/curve25519/curve25519.hpp>

#include <nil/crypto3/random/random.hpp>

namespace nil {
    namespace crypto3 {

        void CECPQ1_offer(uint8_t send[CECPQ1_OFFER_BYTES], CECPQ1_key *offer_key_output, RandomNumberGenerator &rng) {
            offer_key_output->m_x25519 = rng.random_vec(32);
            curve25519_basepoint(send, offer_key_output->m_x25519.data());

            newhope_keygen(send + 32, &offer_key_output->m_newhope, rng, Newhope_Mode::BoringSSL);
        }

        void CECPQ1_accept(uint8_t shared_key[CECPQ1_SHARED_KEY_BYTES], uint8_t send[CECPQ1_ACCEPT_BYTES],
                           const uint8_t received[CECPQ1_OFFER_BYTES], RandomNumberGenerator &rng) {
            secure_vector <uint8_t> x25519_key = rng.random_vec(32);

            curve25519_basepoint(send, x25519_key.data());

            curve25519_donna(shared_key, x25519_key.data(), received);

            newhope_sharedb(shared_key + 32, send + 32, received + 32, rng, Newhope_Mode::BoringSSL);
        }

        void CECPQ1_finish(uint8_t shared_key[CECPQ1_SHARED_KEY_BYTES], const CECPQ1_key &offer_key,
                           const uint8_t received[CECPQ1_ACCEPT_BYTES]) {
            curve25519_donna(shared_key, offer_key.m_x25519.data(), received);

            newhope_shareda(shared_key + 32, &offer_key.m_newhope, received + 32, Newhope_Mode::BoringSSL);
        }
    }
}
