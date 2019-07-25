#ifndef CRYPTO3_PUBKEY_RFC6979_GENERATOR_HPP
#define CRYPTO3_PUBKEY_RFC6979_GENERATOR_HPP

#include <boost/multiprecision/number.hpp>

#include <nil/crypto3/random/hmac_drbg/hmac_drbg.hpp>

#include <string>
#include <memory>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            class hmac_drbg;

            template<typename NumberType>
            class rfc6979_nonce_generator {
            public:
                typedef NumberType number_type;
                /**
                 * Note: keeps persistent reference to order
                 */
                template<typename Backend, expression_template_option ExpressionTemplates>
                rfc6979_nonce_generator(const std::string &hash, const number<Backend, ExpressionTemplates> &order,
                                        const number<Backend, ExpressionTemplates> &x) :
                    m_order(order),
                    m_qlen(m_order.bits()), m_rlen(m_qlen / 8 + (m_qlen % 8 ? 1 : 0)), m_rng_in(m_rlen * 2),
                    m_rng_out(m_rlen) {
                    m_hmac_drbg.reset(new hmac_drbg(MessageAuthenticationCode::create("HMAC(" + hash + ")")));
                    boost::multiprecision::cpp_int::encode_1363(m_rng_in.data(), m_rlen, x);
                }

                template<typename Backend, expression_template_option ExpressionTemplates>
                const number_type &nonce_for(const number<Backend, ExpressionTemplates> &m) {
                    boost::multiprecision::cpp_int::encode_1363(&m_rng_in[m_rlen], m_rlen, m);
                    m_hmac_drbg->clear();
                    m_hmac_drbg->initialize_with(m_rng_in.data(), m_rng_in.size());

                    do {
                        m_hmac_drbg->randomize(m_rng_out.data(), m_rng_out.size());
                        m_k.binary_decode(m_rng_out.data(), m_rng_out.size());
                        m_k >>= (8 * m_rlen - m_qlen);
                    } while (m_k == 0 || m_k >= m_order);

                    return m_k;
                }

            private:
                const number_type &m_order;
                number_type m_k;
                size_t m_qlen, m_rlen;
                std::unique_ptr<hmac_drbg> m_hmac_drbg;
                secure_vector<uint8_t> m_rng_in, m_rng_out;
            };

            /**
             * @param x the secret (EC)DSA key
             * @param q the group order
             * @param h the message hash already reduced mod q
             * @param hash the hash function used to generate h
             */
            template<typename Backend, expression_template_option ExpressionTemplates>
            boost::multiprecision::cpp_int generate_rfc6979_nonce(const number<Backend, ExpressionTemplates> &x,
                                                                  const number<Backend, ExpressionTemplates> &q,
                                                                  const number<Backend, ExpressionTemplates> &h,
                                                                  const std::string &hash) {
                rfc6979_nonce_generator gen(hash, q, x);
                number<Backend, ExpressionTemplates> k = gen.nonce_for(h);
                return k;
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
