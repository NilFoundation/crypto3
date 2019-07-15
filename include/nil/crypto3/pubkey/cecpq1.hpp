#ifndef CRYPTO3_CECPQ1_HPP
#define CRYPTO3_CECPQ1_HPP

#include <nil/crypto3/utilities/secmem.hpp>
#include <nil/crypto3/pubkey/newhope/newhope.hpp>

namespace nil {
    namespace crypto3 {

        class CECPQ1_key final {
        public:
            secure_vector<uint8_t> m_x25519;
            newhope_poly m_newhope;
        };

        void CECPQ1_offer(uint8_t *offer_message, CECPQ1_key *offer_key_output, RandomNumberGenerator &rng);

        void CECPQ1_accept(uint8_t *shared_key, uint8_t *accept_message, const uint8_t *offer_message,
                           RandomNumberGenerator &rng);

        void CECPQ1_finish(uint8_t *shared_key, const CECPQ1_key &offer_key, const uint8_t *accept_message);
    }    // namespace crypto3
}    // namespace nil

#endif
