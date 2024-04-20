//---------------------------------------------------------------------------//
// Copyright (c) 2023 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_PRIMES_HPP
#define CRYPTO3_ALGEBRA_PRIMES_HPP

#include <cassert>

#include <set>

#include <nil/crypto3/multiprecision/miller_rabin.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>
#include "random_element.hpp"

namespace nil {
    namespace crypto3 {
        namespace algebra {
            /*
             The Pollard Rho factorization of a number n.
             Input: n the number to be factorized.
             Output: a factor of n.
             */
            template<typename Backend,
                    multiprecision::expression_template_option ExpressionTemplates>
            multiprecision::number<Backend, ExpressionTemplates>
            pollard_rho_factorization(const multiprecision::number<Backend, ExpressionTemplates> &n) {
                using namespace multiprecision;

                if (!(n % 2)) {
                    return 2;
                }

                boost::random::independent_bits_engine<std::mt19937, 256, number<Backend, ExpressionTemplates>> rng;
                number<modular_adaptor<Backend, backends::modular_params_rt<Backend>>, ExpressionTemplates> divisor,
                        c(rng(), n), x(rng(), n), nn(n, n), xx = x;
                do {
                    x = x * x + c;
                    xx = xx * xx + c;
                    xx = xx * xx + c;
                    divisor = multiprecision::gcd((x > xx) ? x - xx : xx - x, nn);
                } while (static_cast<int>(divisor) == 1);
                return static_cast<multiprecision::number<Backend, ExpressionTemplates>>(divisor);
            }

            /*
             Recursively factorizes and find the distinct primefactors of a number
             Input: n is the number to be prime factorized,
             prime_factors is a set of prime factors of n.
             */
            template<typename IntegerType>
            void prime_factorize(IntegerType n, std::set<IntegerType> &prime_factors) {
                if (n == 0 || n == 1)
                    return;
                if (multiprecision::miller_rabin_test(n, 100)) {
                    prime_factors.insert(n);
                    return;
                }

                IntegerType divisor(pollard_rho_factorization(n));
                IntegerType n_div = n / divisor;
                prime_factorize(divisor, prime_factors);
                prime_factorize(n_div, prime_factors);
            }

            template<typename IntegerType>
            IntegerType first_prime(uint64_t nBits, uint64_t m) {
                BOOST_ASSERT_MSG(nBits <= MAX_MODULUS_SIZE, "Requested bit length " + std::to_string(nBits) +
                                                            " exceeds maximum allowed length " +
                                                            std::to_string(MAX_MODULUS_SIZE));
                IntegerType mi(m);
                IntegerType qNew(IntegerType(1) << nBits);
                IntegerType r(qNew % mi);
                IntegerType qNew2(qNew + 1);
                if (r > IntegerType(0))
                    qNew2 += (mi - r);
                BOOST_ASSERT_MSG(qNew2 >= qNew, "FirstPrime parameters overflow this integer implementation");
                while (!multiprecision::miller_rabin_test((qNew = qNew2), 100)) {
                    qNew2 = qNew + mi;
                    BOOST_ASSERT_MSG(qNew2 >= qNew, "FirstPrime overflow growing candidate");
                }
                return qNew;
            }

            template<typename IntegerType>
            IntegerType next_prime(const IntegerType &q, uint64_t m) {
                IntegerType M(m), qNew(q + M);
                while (!multiprecision::miller_rabin_test(qNew, 100)) {
                    BOOST_VERIFY_MSG((qNew += M) >= q, "NextPrime overflow growing candidate");
                }
                return qNew;
            }

            template<typename IntegerType>
            IntegerType previous_prime(const IntegerType &q, uint64_t m) {
                IntegerType M(m), qNew(q - M);
                while (!multiprecision::miller_rabin_test(qNew, 100)) {
                    BOOST_VERIFY_MSG((qNew -= M) <= q, "Moduli size is not sufficient! Must be increased.");
                }
                return qNew;
            }
        }
    }
}

#endif //CRYPTO3_PRIMES_HPP
