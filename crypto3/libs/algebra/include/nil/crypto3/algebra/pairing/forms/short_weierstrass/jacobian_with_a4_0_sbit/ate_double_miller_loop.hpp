//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2024  Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_SBIT_ATE_DOUBLE_MILLER_LOOP_HPP
#define CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_SBIT_ATE_DOUBLE_MILLER_LOOP_HPP

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <nil/crypto3/algebra/pairing/pairing_policy.hpp>

#include <nil/crypto3/algebra/pairing/detail/forms/short_weierstrass/jacobian_with_a4_0/types.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<typename CurveType>
                class short_weierstrass_jacobian_with_a4_0_sbit_ate_double_miller_loop {
                    using curve_type = CurveType;

                    using params_type = detail::pairing_params<curve_type>;
                    typedef detail::short_weierstrass_jacobian_with_a4_0_types_policy<curve_type> policy_type;

                    using gt_type = typename curve_type::gt_type;

                public:
                    static typename gt_type::value_type
                        process(const typename policy_type::ate_g1_precomputed_type &prec_P1,
                                const typename policy_type::ate_g2_precomputed_type &prec_Q1,
                                const typename policy_type::ate_g1_precomputed_type &prec_P2,
                                const typename policy_type::ate_g2_precomputed_type &prec_Q2) {

                        typename gt_type::value_type f = gt_type::value_type::one();

                        std::size_t idx = 0;

                        typename policy_type::ate_ell_coeffs c1, c2;

                        for (auto bit = params_type::ate_loop_count_sbit.rbegin()+1; /* skip first bit */
                                bit != params_type::ate_loop_count_sbit.rend();
                                ++bit) {

                            f = f.squared();

                            c1 = prec_Q1.coeffs[idx];
                            c2 = prec_Q2.coeffs[idx];
                            ++idx;

                            if (params_type::twist_type == curve_twist_type::TWIST_TYPE_M) {
                                f = f.mul_by_014(c1.ell_0, prec_P1.PX * c1.ell_VW, prec_P1.PY * c1.ell_VV);
                                f = f.mul_by_014(c2.ell_0, prec_P2.PX * c2.ell_VW, prec_P2.PY * c2.ell_VV);
                            } else {
                                f = f.mul_by_034(prec_P1.PY * c1.ell_0, prec_P1.PX * c1.ell_VW, c1.ell_VV);
                                f = f.mul_by_034(prec_P2.PY * c2.ell_0, prec_P2.PX * c2.ell_VW, c2.ell_VV);
                            }

                            if (*bit != 0) {
                                c1 = prec_Q1.coeffs[idx];
                                c2 = prec_Q2.coeffs[idx];
                                ++idx;

                                if (params_type::twist_type == curve_twist_type::TWIST_TYPE_M) {
                                    f = f.mul_by_014(c1.ell_0, prec_P1.PX * c1.ell_VW, prec_P1.PY * c1.ell_VV);
                                    f = f.mul_by_014(c2.ell_0, prec_P2.PX * c2.ell_VW, prec_P2.PY * c2.ell_VV);
                                } else {
                                    f = f.mul_by_034(prec_P1.PY * c1.ell_0, prec_P1.PX * c1.ell_VW, c1.ell_VV);
                                    f = f.mul_by_034(prec_P2.PY * c2.ell_0, prec_P2.PX * c2.ell_VW, c2.ell_VV);
                                }
                            }
                        }

                        if (params_type::ate_is_loop_count_neg) {
                            f = f.inversed();
                        }

                        c1 = prec_Q1.coeffs[idx];
                        c2 = prec_Q2.coeffs[idx];
                        ++idx;

                        if (params_type::twist_type == curve_twist_type::TWIST_TYPE_M) {
                            f = f.mul_by_014(c1.ell_0, prec_P1.PX * c1.ell_VW, prec_P1.PY * c1.ell_VV);
                            f = f.mul_by_014(c2.ell_0, prec_P2.PX * c2.ell_VW, prec_P2.PY * c2.ell_VV);
                        } else {
                            f = f.mul_by_034(prec_P1.PY * c1.ell_0, prec_P1.PX * c1.ell_VW, c1.ell_VV);
                            f = f.mul_by_034(prec_P2.PY * c2.ell_0, prec_P2.PX * c2.ell_VW, c2.ell_VV);
                        }

                        c1 = prec_Q1.coeffs[idx];
                        c2 = prec_Q2.coeffs[idx];
                        ++idx;

                        if (params_type::twist_type == curve_twist_type::TWIST_TYPE_M) {
                            f = f.mul_by_014(c1.ell_0, prec_P1.PX * c1.ell_VW, prec_P1.PY * c1.ell_VV);
                            f = f.mul_by_014(c2.ell_0, prec_P2.PX * c2.ell_VW, prec_P2.PY * c2.ell_VV);
                        } else {
                            f = f.mul_by_034(prec_P1.PY * c1.ell_0, prec_P1.PX * c1.ell_VW, c1.ell_VV);
                            f = f.mul_by_034(prec_P2.PY * c2.ell_0, prec_P2.PX * c2.ell_VW, c2.ell_VV);
                        }

                        return f;
                    }
                };
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_SBIT_ATE_DOUBLE_MILLER_LOOP_HPP
