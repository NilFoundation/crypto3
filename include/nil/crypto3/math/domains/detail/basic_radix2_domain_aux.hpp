//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MATH_BASIC_RADIX2_DOMAIN_AUX_HPP
#define CRYPTO3_MATH_BASIC_RADIX2_DOMAIN_AUX_HPP

#include <algorithm>
#include <vector>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/detail/field_utils.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            namespace detail {

                /*
                 * Below we make use of pseudocode from [CLRS 2n Ed, pp. 864].
                 * Also, note that it's the caller's responsibility to multiply by 1/N.
                 */
                template<typename FieldType, typename Range>
                void basic_radix2_fft(Range &a, const typename FieldType::value_type &omega) {
                    typedef typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type
                        value_type;
                    typedef typename FieldType::value_type field_value_type;
                    BOOST_STATIC_ASSERT(algebra::is_field<FieldType>::value);
                    
                    // It now supports curve elements too, should probably some other assertion about the field type and value type
                    // BOOST_STATIC_ASSERT(std::is_same<typename FieldType::value_type, value_type>::value);

                    const std::size_t n = a.size(), logn = log2(n);
                    if (n != (1u << logn))
                        throw std::invalid_argument("expected n == (1u << logn)");

                    /* swapping in place (from Storer's book) */
                    for (std::size_t k = 0; k < n; ++k) {
                        const std::size_t rk = bitreverse(k, logn);
                        if (k < rk)
                            std::swap(a[k], a[rk]);
                    }

                    std::size_t m = 1;    // invariant: m = 2^{s-1}
                    for (std::size_t s = 1; s <= logn; ++s) {
                        // w_m is 2^s-th root of unity now
                        const field_value_type w_m = omega.pow(n / (2 * m));

                        asm volatile("/* pre-inner */");
                        for (std::size_t k = 0; k < n; k += 2 * m) {
                            field_value_type w = field_value_type::one();
                            for (std::size_t j = 0; j < m; ++j) {
                                const value_type t = a[k + j + m] * w;
                                a[k + j + m] = a[k + j] - t;
                                a[k + j] = a[k + j] + t;
                                w *= w_m;
                            }
                        }
                        asm volatile("/* post-inner */");
                        m *= 2;
                    }
                }

                /**
                 * Compute the m Lagrange coefficients, relative to the set S={omega^{0},...,omega^{m-1}}, at the
                 * field element t.
                 */
                template<typename FieldType>
                std::vector<typename FieldType::value_type>
                    basic_radix2_evaluate_all_lagrange_polynomials(const std::size_t m,
                                                                   const typename FieldType::value_type &t) {
                    typedef typename FieldType::value_type value_type;

                    if (m == 1) {
                        return std::vector<value_type>(1, value_type::one());
                    }

                    if (m != (1u << static_cast<std::size_t>(std::ceil(std::log2(m)))))
                        throw std::invalid_argument("expected m == (1u << log2(m))");

                    const value_type omega = unity_root<FieldType>(m);

                    std::vector<value_type> u(m, value_type::zero());

                    /*
                     If t equals one of the roots of unity in S={omega^{0},...,omega^{m-1}}
                     then output 1 at the right place, and 0 elsewhere
                     */

                    if (t.pow(m) == value_type::one()) {
                        value_type omega_i = value_type::one();
                        for (std::size_t i = 0; i < m; ++i) {
                            if (omega_i == t)    // i.e., t equals omega^i
                            {
                                u[i] = value_type::one();
                                return u;
                            }

                            omega_i *= omega;
                        }
                    }

                    /*
                     Otherwise, if t does not equal any of the roots of unity in S,
                     then compute each L_{i,S}(t) as Z_{S}(t) * v_i / (t-\omega^i)
                     where:
                     - Z_{S}(t) = \prod_{j} (t-\omega^j) = (t^m-1), and
                     - v_{i} = 1 / \prod_{j \neq i} (\omega^i-\omega^j).
                     Below we use the fact that v_{0} = 1/m and v_{i+1} = \omega * v_{i}.
                     */

                    const value_type Z = (t.pow(m)) - value_type::one();
                    value_type l = Z * value_type(m).inversed();
                    value_type r = value_type::one();
                    for (std::size_t i = 0; i < m; ++i) {
                        u[i] = l * (t - r).inversed();
                        l *= omega;
                        r *= omega;
                    }

                    return u;
                }
            }    // namespace detail
        }        // namespace fft
    }            // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_AUX_HPP
