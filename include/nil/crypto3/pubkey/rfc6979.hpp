#ifndef CRYPTO3_RFC6979_GENERATOR_HPP_
#define CRYPTO3_RFC6979_GENERATOR_HPP_

#include <nil/crypto3/multiprecision/bigint/bigint.hpp>

#include <string>
#include <memory>

namespace nil {
    namespace crypto3 {

        class hmac_drbg;

        class rfc6979_nonce_generator final {
        public:
            /**
            * Note: keeps persistent reference to order
            */
            rfc6979_nonce_generator(const std::string &hash, const boost::multiprecision::cpp_int &order, const boost::multiprecision::cpp_int &x);

            ~rfc6979_nonce_generator();

            const boost::multiprecision::cpp_int &nonce_for(const boost::multiprecision::cpp_int &m);

        private:
            const boost::multiprecision::cpp_int &m_order;
            boost::multiprecision::cpp_int m_k;
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
        boost::multiprecision::cpp_int generate_rfc6979_nonce(const boost::multiprecision::cpp_int &x, const boost::multiprecision::cpp_int &q, const boost::multiprecision::cpp_int &h, const std::string &hash);
    }
}

#endif
