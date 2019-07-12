#include <nil/crypto3/pubkey/rfc6979.hpp>
#include <nil/crypto3/random/hmac_drbg/hmac_drbg.hpp>

namespace nil {
    namespace crypto3 {

        rfc6979_nonce_generator::rfc6979_nonce_generator(const std::string &hash,
                                                         const boost::multiprecision::cpp_int &order,
                                                         const boost::multiprecision::cpp_int &x) : m_order(order),
                m_qlen(m_order.bits()), m_rlen(m_qlen / 8 + (m_qlen % 8 ? 1 : 0)), m_rng_in(m_rlen * 2),
                m_rng_out(m_rlen) {
            m_hmac_drbg.reset(new hmac_drbg(MessageAuthenticationCode::create("HMAC(" + hash + ")")));
            boost::multiprecision::cpp_int::encode_1363(m_rng_in.data(), m_rlen, x);
        }

        rfc6979_nonce_generator::~rfc6979_nonce_generator() {
            // for ~unique_ptr
        }

        const boost::multiprecision::cpp_int &rfc6979_nonce_generator::nonce_for(
                const boost::multiprecision::cpp_int &m) {
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

        boost::multiprecision::cpp_int generate_rfc6979_nonce(const boost::multiprecision::cpp_int &x,
                                                              const boost::multiprecision::cpp_int &q,
                                                              const boost::multiprecision::cpp_int &h,
                                                              const std::string &hash) {
            rfc6979_nonce_generator gen(hash, q, x);
            boost::multiprecision::cpp_int k = gen.nonce_for(h);
            return k;
        }
    }
}
