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

#ifndef CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_SBTI_ATE_MILLER_LOOP_HPP
#define CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_SBTI_ATE_MILLER_LOOP_HPP

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <nil/crypto3/algebra/pairing/pairing_policy.hpp>

#include <nil/crypto3/algebra/pairing/detail/forms/short_weierstrass/jacobian_with_a4_0/types.hpp>


namespace nil {
    namespace crypto3 {
        namespace algebra {

            namespace pairing {

                template<typename CurveType>
                class short_weierstrass_jacobian_with_a4_0_sbit_ate_miller_loop {
                    using curve_type = CurveType;

                    using params_type = detail::pairing_params<curve_type>;
                    typedef detail::short_weierstrass_jacobian_with_a4_0_types_policy<curve_type> policy_type;

                    using gt_type = typename curve_type::gt_type;

                public:
                    static typename gt_type::value_type
                        process(const typename policy_type::ate_g1_precomputed_type &prec_P,
                                const typename policy_type::ate_g2_precomputed_type &prec_Q) {

                        typename gt_type::value_type f = gt_type::value_type::one();

                        std::size_t idx = 0;

                        typename policy_type::ate_ell_coeffs c;

                        for (auto bit = params_type::ate_loop_count_sbit.rbegin()+1; /* skip first bit */
                                bit != params_type::ate_loop_count_sbit.rend();
                                ++bit) {

                            f = f.squared();

                            c = prec_Q.coeffs[idx];
                            ++idx;

                            if (params_type::twist_type == curve_twist_type::TWIST_TYPE_M) {
                                f = f.mul_by_014(c.ell_0, prec_P.PX * c.ell_VW, prec_P.PY * c.ell_VV);
                            } else {
                                f = f.mul_by_034(prec_P.PY * c.ell_0, prec_P.PX * c.ell_VW, c.ell_VV);
                            }

                            if (*bit != 0) {
                                c = prec_Q.coeffs[idx];
                                ++idx;
                                if (params_type::twist_type == curve_twist_type::TWIST_TYPE_M) {
                                    f = f.mul_by_014(c.ell_0, prec_P.PX * c.ell_VW, prec_P.PY * c.ell_VV);
                                } else {
                                    f = f.mul_by_034(prec_P.PY * c.ell_0, prec_P.PX * c.ell_VW, c.ell_VV);
                                }
                            }
                        }

                        if (params_type::final_exponent_is_z_neg) {
                            f = f.inversed();
                        }

                        c = prec_Q.coeffs[idx];
                        ++idx;
                        if (params_type::twist_type == curve_twist_type::TWIST_TYPE_M) {
                            f = f.mul_by_014(c.ell_0, prec_P.PX * c.ell_VW, prec_P.PY * c.ell_VV);
                        } else {
                            f = f.mul_by_034(prec_P.PY * c.ell_0, prec_P.PX * c.ell_VW, c.ell_VV);
                        }

                        c = prec_Q.coeffs[idx];
                        ++idx;
                        if (params_type::twist_type == curve_twist_type::TWIST_TYPE_M) {
                            f = f.mul_by_014(c.ell_0, prec_P.PX * c.ell_VW, prec_P.PY * c.ell_VV);
                        } else {
                            f = f.mul_by_034(prec_P.PY * c.ell_0, prec_P.PX * c.ell_VW, c.ell_VV);
                        }

                        return f;
                    }
                };
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_SBIT_ATE_MILLER_LOOP_HPP
