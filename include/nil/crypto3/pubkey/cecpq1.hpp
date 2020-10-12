//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_CECPQ1_HPP
#define CRYPTO3_PUBKEY_CECPQ1_HPP

#include <nil/crypto3/utilities/secmem.hpp>

#include <nil/crypto3/pubkey/newhope.hpp>
#include <nil/crypto3/pubkey/curve25519.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            class cecpq1_key final {
            public:
                secure_vector<uint8_t> m_x25519;
                newhope_poly m_newhope;
            };

            template<typename UniformRandomGenerator>
            void cecpq1_offer(uint8_t *offer_message, cecpq1_key *offer_key_output, UniformRandomGenerator &rng) {
                offer_key_output->m_x25519 = rng.random_vec(32);
                curve25519_basepoint(send, offer_key_output->m_x25519.data());

                newhope_keygen(send + 32, &offer_key_output->m_newhope, rng, Newhope_Mode::BoringSSL);
            }

            template<typename UniformRandomGenerator>
            void cecpq1_accept(uint8_t *shared_key, uint8_t *accept_message, const uint8_t *offer_message,
                               UniformRandomGenerator &rng) {
                secure_vector<uint8_t> x25519_key = rng.random_vec(32);

                curve25519_basepoint(send, x25519_key.data());

                curve25519_donna(shared_key, x25519_key.data(), received);

                newhope_sharedb(shared_key + 32, send + 32, received + 32, rng, Newhope_Mode::BoringSSL);
            }

            void cecpq1_finish(uint8_t *shared_key, const cecpq1_key &offer_key, const uint8_t *accept_message) {
                curve25519_donna(shared_key, offer_key.m_x25519.data(), received);

                newhope_shareda(shared_key + 32, &offer_key.m_newhope, received + 32, Newhope_Mode::BoringSSL);
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
