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

#ifndef CRYPTO3_ALGEBRA_PAIRING_BLS12_ATE_MILLER_LOOP_HPP
#define CRYPTO3_ALGEBRA_PAIRING_BLS12_ATE_MILLER_LOOP_HPP

#include <nil/crypto3/algebra/pairing/detail/bls12/381/params.hpp>
#include <nil/crypto3/algebra/pairing/detail/bls12/381/types.hpp>

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<std::size_t Version = 381>
                class bls12_ate_miller_loop;

                template<>
                class bls12_ate_miller_loop<381> {
                    using curve_type = curves::bls12<381>;

                    using params_type = detail::params_type<curve_type>;
                    using types_policy = detail::types_policy<curve_type>;

                    using gt_type = typename curve_type::gt_type;
                public:

                    static typename gt_type::value_type process(
                        const types_policy::ate_g1_precomp &prec_P, 
                        const types_policy::ate_g2_precomp &prec_Q) {

                        typename gt_type::value_type f = gt_type::value_type::one();

                        bool found_one = false;
                        std::size_t idx = 0;

                        const typename types_policy::number_type &loop_count = params_type::ate_loop_count;

                        typename types_policy::ate_ell_coeffs c;

                        for (long i = params_type::number_type_max_bits; i >= 0; --i) {
                            const bool bit = multiprecision::bit_test(loop_count, i);
                            if (!found_one) {
                                /* this skips the MSB itself */
                                found_one |= bit;
                                continue;
                            }

                            /* code below gets executed for all bits (EXCEPT the MSB itself) of
                               param_p (skipping leading zeros) in MSB to LSB
                               order */

                            c = prec_Q.coeffs[idx++];
                            f = f.squared();
                            f = f.mul_by_045(c.ell_0, prec_P.PY * c.ell_VW, prec_P.PX * c.ell_VV);

                            if (bit) {
                                c = prec_Q.coeffs[idx++];
                                f = f.mul_by_045(c.ell_0, prec_P.PY * c.ell_VW, prec_P.PX * c.ell_VV);
                            }
                        }

                        if (params_type::ate_is_loop_count_neg) {
                            f = f.inversed();
                        }

                        return f;
                    }
                };
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_BLS12_ATE_MILLER_LOOP_HPP
