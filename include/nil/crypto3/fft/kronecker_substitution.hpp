//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_FFT_KRONECKER_SUBSTITUTION_HPP
#define CRYPTO3_ALGEBRA_FFT_KRONECKER_SUBSTITUTION_HPP

#include <vector>
#include <algorithm>
#include <cmath>

#include <boost/math/tools/polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace fft {
            /*!
             * @brief Given two polynomial vectors, A and B, the function performs
             * polynomial multiplication and returns the resulting polynomial vector.
             * The implementation makes use of
             * [Harvey 07, Multipoint Kronecker Substitution, Section 2.1] and
             * [Gathen and Gerhard, Modern Computer Algebra 3rd Ed., Section 8.4].
             */
            template<typename FieldType>
            void kronecker_substitution(std::vector<typename FieldType::value_type>& v3,
                                        const std::vector<typename FieldType::value_type>& v1,
                                        const std::vector<typename FieldType::value_type>& v2) {
                typedef typename FieldType::value_type value_type;

                // Initialize
                bool square = (v1 == v2) ? 1 : 0;

                // Polynomial length
                std::size_t n1 = v1.size();
                std::size_t n2 = v2.size();
                std::size_t n3 = n1 + n2 - 1;

                // Determine number of bits needed
                value_type v1_max = *max_element(std::begin(v1), std::end(v1));
                value_type v2_max = *max_element(std::begin(v2), std::end(v2));
                /*size_t b = 2 * (v1_max * v2_max).as_bigint().num_bits() + 1;


                // Number of limbs needed in total
                std::size_t k1 = (n1 * b + (GMP_NUMB_BITS)-1) / GMP_NUMB_BITS;
                std::size_t k2 = (n2 * b + (GMP_NUMB_BITS)-1) / GMP_NUMB_BITS;


                // Output polynomial
                v3.resize(n3, value_type::zero());

                // Allocate all MP_LIMB_T space once and store the reference pointer M1
                // to free memory afterwards. P1, P2, and P3 will remain fixed pointers
                // to the start of their respective polynomials as reference.
                mp_limb_t* m1 = (mp_limb_t*)malloc(sizeof(mp_limb_t) * 2 * (k1 + k2));
                mp_limb_t* p1 = m1;
                mp_limb_t* p2 = p1 + k1;
                mp_limb_t* p3 = p2 + k2;

                // Helper variables
                mp_limb_t* ref;
                mp_limb_t limb;
                unsigned long val;
                unsigned long mask;
                unsigned long limb_b;
                unsigned long delta;
                unsigned long delta_b;

                // Construct P1 limb
                ref = p1;
                limb = 0;
                limb_b = 0;
                for (std::size_t i = 0; i < n1; i++) {
                    val = v1[i].as_ulong();
                    limb += (val << limb_b);

                     // If the next iteration of LIMB_B is >= to the GMP_LIMB_BITS, then
                     // write it out to MP_LIMB_T* and reset LIMB. If VAL has remaining
                     // bits due to GMP_LIMB_BITS boundary, set it in LIMB and proceed.
                    if (limb_b + b >= GMP_LIMB_BITS) {
                        *ref++ = limb;
                        limb = limb_b ? (val >> (GMP_LIMB_BITS - limb_b)) : 0;
                        limb_b -= GMP_LIMB_BITS;
                    }
                    limb_b += b;
                }
                if (limb_b)
                    *ref++ = limb;

                // Construct P2 limb. If V2 == V1, then P2 = P1 - square case.
                if (square)
                    p2 = p1;
                else {
                    ref = p2;
                    limb = 0;
                    limb_b = 0;
                    for (std::size_t i = 0; i < n2; i++) {
                        val = v2[i].as_ulong();
                        limb += (val << limb_b);

                         // If the next iteration of LIMB_B is >= to the GMP_LIMB_BITS, then
                         // write it out to MP_LIMB_T* and reset LIMB. If VAL has remaining
                         // bits due to GMP_LIMB_BITS boundary, set it in LIMB and proceed.
                        if (limb_b + b >= GMP_LIMB_BITS) {
                            *ref++ = limb;
                            limb = limb_b ? (val >> (GMP_LIMB_BITS - limb_b)) : 0;
                            limb_b -= GMP_LIMB_BITS;
                        }
                        limb_b += b;
                    }
                    if (limb_b)
                        *ref++ = limb;
                }

                // Multiply P1 and P2 limbs and store result in P3 limb.
                mpn_mul(p3, p1, k1, p2, k2);

                // Perfect alignment case: bits B is equivalent to GMP_LIMB_BITS
                if (b == GMP_LIMB_BITS)
                    for (std::size_t i = 0; i < n3; i++)
                        v3[i] = value_type(*p3++);
                // Non-alignment case
                else {
                    // Mask of 2^b - 1
                    mask = (1UL << b) - 1;

                    limb = 0;
                    limb_b = 0;
                    for (std::size_t i = 0; i < n3; i++) {

                         // If the coefficient's bit length is contained in LIMB, then
                         // write the masked value out to vector V3 and decrement LIMB
                         // by B bits.
                        if (b <= limb_b) {
                            v3[i] = value_type(limb & mask);

                            delta = b;
                            delta_b = limb_b - delta;
                        }

                         // If the remaining coefficient is across two LIMBs, then write
                         // to vector V3 the current limb's value and add upper bits from
                         // the second part. Lastly, decrement LIMB by the coefficient's
                         // upper portion bit length.
                        else {
                            v3[i] = value_type(limb);
                            v3[i] += value_type(((limb = *p3++) << limb_b) & mask);

                            delta = b - limb_b;
                            delta_b = GMP_LIMB_BITS - delta;
                        }

                        limb >>= delta;
                        limb_b = delta_b;
                    }
                }

                // Free memory
                free(m1);

                _condense(v3);*/
            }

            /**
             * Perform the multiplication of two polynomials, polynomial A * polynomial B, using Kronecker Substitution,
             * and stores result in polynomial C.
             */
            template<typename FieldType>
            void _polynomial_multiplication_on_kronecker(std::vector<typename FieldType::value_type>& c,
                                                         const std::vector<typename FieldType::value_type>& a,
                                                         const std::vector<typename FieldType::value_type>& b) {
                kronecker_substitution<FieldType>(c, a, b);
            }

        }    // namespace fft
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_KRONECKER_SUBSTITUTION_HPP
