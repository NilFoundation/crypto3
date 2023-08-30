//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_TOTIENT_HPP
#define CRYPTO3_ALGEBRA_TOTIENT_HPP


namespace nil {
    namespace crypto3 {
        namespace algebra {
            /**
             * Returns the totient value phi of a number n.
             *
             * @param &n the input number.
             * @return phi of n which is the number of integers m coprime to n such that 1 <= m <=
             * n.
             */
            template<typename IntegerType>
            IntegerType totient(const IntegerType n) {
                std::set < IntegerType > factors;
                IntegerType enn(n);
                PrimeFactorize(enn, factors);

                IntegerType primeProd(1);
                IntegerType numerator(1);
                for (auto &r: factors) {
                    numerator = numerator * (r - 1);
                    primeProd = primeProd * r;
                }

                primeProd = (enn / primeProd) * numerator;
                return primeProd;
            }

            /**
             * Returns the list of coprimes to number n in ascending order.
             *
             * @param &n the input number.
             * @return vector of mi's such that 1 <= mi <= n and gcd(mi,n)==1.
             */
            template<typename IntegerType>
            std::vector<IntegerType> totient_list(const IntegerType &n) {
                std::vector<IntegerType> result;
                IntegerType one = 1;

                for (IntegerType i = 1; i < n; i++) {
                    if (multiprecision::gcd(i, n) == one)
                        result.push_back(i);
                }

                return result;
            }
        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_RANDOM_ELEMENT_HPP
