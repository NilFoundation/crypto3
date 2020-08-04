//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_RFC6979_GENERATOR_HPP
#define CRYPTO3_PUBKEY_RFC6979_GENERATOR_HPP

#include <boost/multiprecision/number.hpp>
#include <boost/random/hmac_drbg.hpp>

#include <nil/crypto3/mac/hmac.hpp>

#include <string>
#include <memory>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                /**
                 * @param x the secret (EC)DSA key
                 * @param q the group order
                 * @param h the message hash already reduced mod q
                 * @param m the hash function used to generate h
                 */
                template<typename Hash,
                         typename Backend,
                         expression_template_option ExpressionTemplates,
                         typename MessageAuthenticationCode = mac::hmac<Hash>>
                number<Backend, ExpressionTemplates>
                    generate_rfc6979_nonce(const number<Backend, ExpressionTemplates> &x,
                                           const number<Backend, ExpressionTemplates> &q,
                                           const number<Backend, ExpressionTemplates> &h) {
                    m_order(order), m_qlen(m_order.bits()), m_rlen(m_qlen / 8 + (m_qlen % 8 ? 1 : 0)),
                        m_rng_in(m_rlen * 2),
                        m_rng_out(m_rlen)

                    number<Backend, ExpressionTemplates>::encode_1363(m_rng_in.data(), m_rlen, x);

                    std::size_t rlen = m_qlen / 8 + (m_qlen % 8 ? 1 : 0);

                    number<Backend, ExpressionTemplates>::encode_1363(&m_rng_in[m_rlen], m_rlen, m);
                    m_hmac_drbg->clear();
                    m_hmac_drbg->initialize_with(h);

                    do {
                        m_hmac_drbg->randomize(m_rng_out.data(), m_rng_out.size());
                        m_k.binary_decode(m_rng_out.data(), m_rng_out.size());
                        m_k >>= (8 * m_rlen - m_qlen);
                    } while (m_k == 0 || m_k >= m_order);

                    return m_k;
                }
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif
