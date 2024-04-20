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

#ifndef CRYPTO3_MATH_CYCLOTOMIC_HPP
#define CRYPTO3_MATH_CYCLOTOMIC_HPP

#include <vector>

#include <nil/crypto3/math/polynomial/polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            /**
             * Returns the m-th cyclotomic polynomial.
             *
             * @param &m the input cyclotomic order.
             * @return resultant m-th cyclotomic polynomial.
             */
            template<typename FieldValueType, typename IntegerType>
            polynomial<FieldValueType> make_cyclotomic_recursive(IntegerType m) {
                polynomial<FieldValueType> result;
                if (m == 1) {
                    result = {-1, 1};
                    return result;
                }
                if (m == 2) {
                    result = {1, 1};
                    return result;
                }
                auto IsPrime = [](uint32_t val) {
                    bool flag = true;
                    for (uint32_t i = 2; i < val; i++) {
                        if (val % i == 0) {
                            flag = false;
                            return flag;
                        }
                    }
                    return flag;
                };
                if (IsPrime(m)) {
                    result = std::vector<int>(m, 1);
                    return result;
                }

                auto GetDivisibleNumbers = [](uint32_t val) {
                    std::vector<uint32_t> div;
                    for (uint32_t i = 1; i < val; i++) {
                        if (val % i == 0) {
                            div.push_back(i);
                        }
                    }
                    return div;
                };

                auto PolyMult = [](const std::vector<int> &a, const std::vector<int> &b) {
                    uint32_t degreeA = a.size() - 1;
                    uint32_t degreeB = b.size() - 1;

                    uint32_t degreeResultant = degreeA + degreeB;

                    std::vector<int> product(degreeResultant + 1, 0);

                    for (uint32_t i = 0; i < a.size(); i++) {
                        for (uint32_t j = 0; j < b.size(); j++) {
                            const auto &valResult = product.at(i + j);
                            const auto &valMult = a.at(i) * b.at(j);
                            product.at(i + j) = valMult + valResult;
                        }
                    }

                    return product;
                };

                auto PolyQuotient = [](const std::vector<int> &dividend, const std::vector<int> &divisor) {
                    uint32_t divisorLength = divisor.size();
                    uint32_t dividendLength = dividend.size();

                    uint32_t runs = dividendLength - divisorLength + 1;    // no. of iterations
                    std::vector<int> quotient(runs + 1);

                    auto mat = [](const int x, const int y, const int z) {
                        int ret = z - (x * y);
                        return ret;
                    };

                    std::vector<int> runningDividend(dividend);

                    uint32_t divisorPtr;
                    for (uint32_t i = 0; i < runs; i++) {
                        // get the highest degree coeff
                        int divConst = (runningDividend[dividendLength - 1]);
                        divisorPtr = divisorLength - 1;
                        for (uint32_t j = 0; j < dividendLength - i - 1; j++) {
                            if (divisorPtr > j) {
                                runningDividend[dividendLength - 1 - j] =
                                        mat(divisor[divisorPtr - 1 - j], divConst,
                                            runningDividend[dividendLength - 2 - j]);
                            } else {
                                runningDividend[dividendLength - 1 - j] = runningDividend[dividendLength - 2 - j];
                            }
                        }
                        quotient.at(i + 1) = runningDividend.at(dividendLength - 1);
                    }
                    // under the assumption that both dividend and divisor are monic
                    quotient.at(0) = 1;
                    quotient.pop_back();

                    return quotient;
                };
                auto divisibleNumbers = GetDivisibleNumbers(m);

                std::vector<int> product(1, 1);

                for (unsigned int divisibleNumber: divisibleNumbers) {
                    auto P = make_cyclotomic_recursive<FieldValueType>(divisibleNumber);
                    product = PolyMult(product, P);
                }

                // make big poly = x^m - 1
                std::vector<int> bigPoly(m + 1, 0);
                bigPoly.at(0) = -1;
                bigPoly.at(m) = 1;

                result = PolyQuotient(bigPoly, product);

                return result;
            }

            /**
             * Returns the m-th cyclotomic polynomial.
             * Added as a wrapper to make_cyclotomic_recursive
             * @param &m the input cyclotomic order.
             * @param &modulus is the working modulus.
             * @return resultant m-th cyclotomic polynomial with coefficients in modulus.
             */
            template<typename FieldRange, typename IntegerType>
            FieldRange make_cyclotomic(IntegerType m, const typename FieldRange::value_type &modulus) {
                auto intCP = make_cyclotomic_recursive<typename FieldRange::value_type>(m);
                FieldRange result(intCP.size(), modulus);
                for (uint32_t i = 0; i < intCP.size(); i++) {
                    auto val = intCP[i];
                    if (intCP.at(i) > -1) {
                        result[i] = typename FieldRange::value_type(val);
                    } else {
                        val *= -1;
                        result[i] = modulus - typename FieldRange::value_type(val);
                    }
                }

                return result;
            }
        }
    }
}

#endif //CRYPTO3_CYCLOTOMIC_HPP
