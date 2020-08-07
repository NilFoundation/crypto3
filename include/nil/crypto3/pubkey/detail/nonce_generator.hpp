//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_NONCE_GENERATOR_HPP
#define CRYPTO3_PUBKEY_NONCE_GENERATOR_HPP

#include <boost/multiprecision/number.hpp>

#include <nil/crypto3/mac/hmac.hpp>

#include <nil/crypto3/pubkey/detail/modes/rfc6979.hpp>

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
                template<typename Hash, typename Backend,
                         boost::multiprecision::expression_template_option ExpressionTemplates,
                         typename MessageAuthenticationCode = mac::hmac<Hash>>
                boost::multiprecision::number<Backend, ExpressionTemplates>
                    generate_rfc6979_nonce(const boost::multiprecision::number<Backend, ExpressionTemplates> &x,
                                           const boost::multiprecision::number<Backend, ExpressionTemplates> &q,
                                           const boost::multiprecision::number<Backend, ExpressionTemplates> &h) {
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

                template<typename ResultType>
                struct nonce_generator {
                    typedef ResultType result_type;
                };

                template<typename UniformRandomGenerator, typename ResultType>
                struct random_nonce_generator : public nonce_generator<ResultType> {
                    typedef nonce_generator<ResultType> policy_type;

                    typedef typename policy_type::result_type result_type;

                    template<typename T, typename S, typename Q>
                    inline result_type operator()(const T &t, const S &s, const Q &q) {

                    }
                };

                template<typename Hash, typename ResultType>
                struct rfc6979_nonce_generator : public nonce_generator<ResultType> {
                    typedef nonce_generator<ResultType> policy_type;

                    typedef typename policy_type::result_type result_type;

                    template<typename T, typename S, typename Q>
                    inline result_type operator()(const T &t, const S &s, const Q &q) {
                        return generate_rfc6979_nonce<Hash>(t, s, q);
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif
