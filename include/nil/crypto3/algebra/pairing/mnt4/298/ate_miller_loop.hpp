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

#ifndef CRYPTO3_ALGEBRA_PAIRING_MNT4_298_ATE_MILLER_LOOP_HPP
#define CRYPTO3_ALGEBRA_PAIRING_MNT4_298_ATE_MILLER_LOOP_HPP

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/detail/mnt4/298/params.hpp>
#include <nil/crypto3/algebra/pairing/detail/forms/short_weierstrass/projective/types.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<std::size_t Version = 298>
                class mnt4_ate_miller_loop;

                template<>
                class mnt4_ate_miller_loop<298> {
                    using curve_type = curves::mnt4<298>;

                    using params_type = detail::pairing_params<curve_type>;
                    typedef detail::short_weierstrass_projective_types_policy<curve_type> policy_type;
                    using gt_type = typename curve_type::gt_type;

                    using base_field_type = typename curve_type::base_field_type;
                    using g1_type = typename curve_type::template g1_type<>;
                    using g2_type = typename curve_type::template g2_type<>;

                    using g1_field_type_value = typename g1_type::field_type::value_type;
                    using g2_field_type_value = typename g2_type::field_type::value_type;

                public:
                    static typename gt_type::value_type process(const policy_type::ate_g1_precomputed_type &prec_P,
                                                                const policy_type::ate_g2_precomputed_type &prec_Q) {

                        g2_field_type_value L1_coeff =
                            g2_field_type_value(prec_P.PX, g1_field_type_value::zero()) -
                            prec_Q.QX_over_twist;

                        typename gt_type::value_type f = gt_type::value_type::one();

                        bool found_one = false;
                        std::size_t dbl_idx = 0;
                        std::size_t add_idx = 0;

                        for (long i = params_type::integral_type_max_bits - 1; i >= 0; --i) {
                            const bool bit = multiprecision::bit_test(params_type::ate_loop_count, i);

                            if (!found_one) {
                                /* this skips the MSB itself */
                                found_one |= bit;
                                continue;
                            }

                            /* code below gets executed for all bits (EXCEPT the MSB itself) of
                               param_p (skipping leading zeros) in MSB to LSB
                               order */
                            typename policy_type::ate_dbl_coeffs dc = prec_Q.dbl_coeffs[dbl_idx++];

                            typename gt_type::value_type g_RR_at_P = typename gt_type::value_type(
                                -dc.c_4C - dc.c_J * prec_P.PX_twist + dc.c_L, dc.c_H * prec_P.PY_twist);
                            f = f.squared() * g_RR_at_P;
                            if (bit) {
                                typename policy_type::ate_add_coeffs ac = prec_Q.add_coeffs[add_idx++];

                                typename gt_type::value_type g_RQ_at_P = typename gt_type::value_type(
                                    ac.c_RZ * prec_P.PY_twist, -(prec_Q.QY_over_twist * ac.c_RZ + L1_coeff * ac.c_L1));
                                f = f * g_RQ_at_P;
                            }
                        }

                        if (params_type::ate_is_loop_count_neg) {
                            typename policy_type::ate_add_coeffs ac = prec_Q.add_coeffs[add_idx++];
                            typename gt_type::value_type g_RnegR_at_P = typename gt_type::value_type(
                                ac.c_RZ * prec_P.PY_twist, -(prec_Q.QY_over_twist * ac.c_RZ + L1_coeff * ac.c_L1));
                            f = (f * g_RnegR_at_P).inversed();
                        }

                        return f;
                    }
                };
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_MNT4_298_ATE_MILLER_LOOP_HPP
