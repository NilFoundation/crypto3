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

#ifndef CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_PROJECTIVE_ATE_PRECOMPUTE_G2_HPP
#define CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_PROJECTIVE_ATE_PRECOMPUTE_G2_HPP

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/pairing/detail/forms/short_weierstrass/projective/types.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<typename CurveType>
                class short_weierstrass_projective_ate_precompute_g2 {
                    using curve_type = CurveType;

                    using params_type = detail::pairing_params<curve_type>;
                    typedef detail::short_weierstrass_projective_types_policy<curve_type> policy_type;

                    using base_field_type = typename curve_type::base_field_type;
                    using g2_type = typename curve_type::template g2_type<>;
                    using g2_affine_type = typename curve_type::template g2_type<curves::coordinates::affine>;

                    using g2_field_type_value = typename g2_type::field_type::value_type;

                    struct extended_g2_projective {
                        g2_field_type_value X;
                        g2_field_type_value Y;
                        g2_field_type_value Z;
                        g2_field_type_value T;
                    };

                    static void doubling_step_for_flipped_miller_loop(extended_g2_projective &current,
                                                                      typename policy_type::ate_dbl_coeffs &dc) {

                        const g2_field_type_value X = current.X, Y = current.Y, Z = current.Z, T = current.T;

                        const g2_field_type_value A = T.squared();                  // A = T1^2
                        const g2_field_type_value B = X.squared();                  // B = X1^2
                        const g2_field_type_value C = Y.squared();                  // C = Y1^2
                        const g2_field_type_value D = C.squared();                  // D = C^2
                        const g2_field_type_value E = (X + C).squared() - B - D;    // E = (X1+C)^2-B-D
                        const g2_field_type_value F =
                            (B + B + B) + params_type::twist_coeff_a * A;    // F = 3*B +  a  *A
                        const g2_field_type_value G = F.squared();           // G = F^2

                        current.X = -E.doubled().doubled() + G;    // X3 = -4*E+G
                        current.Y = -typename base_field_type::value_type(0x08) * D +
                                    F * (E + E - current.X);                // Y3 = -8*D+F*(2*E-X3)
                        current.Z = (Y + Z).squared() - C - Z.squared();    // Z3 = (Y1+Z1)^2-C-Z1^2
                        current.T = current.Z.squared();                    // T3 = Z3^2

                        dc.c_H = (current.Z + T).squared() - current.T - A;    // H = (Z3+T1)^2-T3-A
                        dc.c_4C = C + C + C + C;                               // fourC = 4*C
                        dc.c_J = (F + T).squared() - G - A;                    // J = (F+T1)^2-G-A
                        dc.c_L = (F + X).squared() - G - B;                    // L = (F+X1)^2-G-B
                    }

                    static void mixed_addition_step_for_flipped_miller_loop(const g2_field_type_value base_X,
                                                                            const g2_field_type_value base_Y,
                                                                            const g2_field_type_value base_Y_squared,
                                                                            extended_g2_projective &current,
                                                                            typename policy_type::ate_add_coeffs &ac) {

                        const g2_field_type_value X1 = current.X, Y1 = current.Y, Z1 = current.Z, T1 = current.T;
                        const g2_field_type_value &x2 = base_X, &y2 = base_Y, &y2_squared = base_Y_squared;

                        const g2_field_type_value B = x2 * T1;    // B = x2 * T1
                        const g2_field_type_value D =
                            ((y2 + Z1).squared() - y2_squared - T1) * T1;    // D = ((y2 + Z1)^2 - y2squared - T1) * T1
                        const g2_field_type_value H = B - X1;                // H = B - X1
                        const g2_field_type_value I = H.squared();           // I = H^2
                        const g2_field_type_value E = I + I + I + I;         // E = 4*I
                        const g2_field_type_value J = H * E;                 // J = H * E
                        const g2_field_type_value V = X1 * E;                // V = X1 * E
                        const g2_field_type_value L1 = D - (Y1 + Y1);        // L1 = D - 2 * Y1

                        current.X = L1.squared() - J - (V + V);              // X3 = L1^2 - J - 2*V
                        current.Y = L1 * (V - current.X) - (Y1 + Y1) * J;    // Y3 = L1 * (V-X3) - 2*Y1 * J
                        current.Z = (Z1 + H).squared() - T1 - I;             // Z3 = (Z1 + H)^2 - T1 - I
                        current.T = current.Z.squared();                     // T3 = Z3^2

                        ac.c_L1 = L1;
                        ac.c_RZ = current.Z;
                    }

                public:
                    using g2_precomputed_type = typename policy_type::ate_g2_precomputed_type;

                    static g2_precomputed_type process(const typename g2_type::value_type &Q) {

                        typename g2_affine_type::value_type Qcopy = Q.to_affine();

                        g2_field_type_value twist_inv =
                            params_type::twist.inversed();    // could add to global params if needed

                        g2_precomputed_type result;
                        result.QX = Qcopy.X;
                        result.QY = Qcopy.Y;
                        result.QY2 = Qcopy.Y.squared();
                        result.QX_over_twist = Qcopy.X * twist_inv;
                        result.QY_over_twist = Qcopy.Y * twist_inv;

                        extended_g2_projective R;
                        R.X = Qcopy.X;
                        R.Y = Qcopy.Y;
                        R.Z = g2_field_type_value::one();
                        R.T = g2_field_type_value::one();
                        bool found_one = false;

                        for (long i = params_type::integral_type_max_bits - 1; i >= 0; --i) {
                            const bool bit = multiprecision::bit_test(params_type::ate_loop_count, i);
                            if (!found_one) {
                                /* this skips the MSB itself */
                                found_one |= bit;
                                continue;
                            }

                            typename policy_type::ate_dbl_coeffs dc;
                            doubling_step_for_flipped_miller_loop(R, dc);
                            result.dbl_coeffs.push_back(dc);
                            if (bit) {
                                typename policy_type::ate_add_coeffs ac;
                                mixed_addition_step_for_flipped_miller_loop(result.QX, result.QY, result.QY2, R, ac);
                                result.add_coeffs.push_back(ac);
                            }
                        }

                        if (params_type::ate_is_loop_count_neg) {
                            g2_field_type_value RZ_inv = R.Z.inversed();
                            g2_field_type_value RZ2_inv = RZ_inv.squared();
                            g2_field_type_value RZ3_inv = RZ2_inv * RZ_inv;
                            g2_field_type_value minus_R_affine_X = R.X * RZ2_inv;
                            g2_field_type_value minus_R_affine_Y = -R.Y * RZ3_inv;
                            g2_field_type_value minus_R_affine_Y2 = minus_R_affine_Y.squared();
                            typename policy_type::ate_add_coeffs ac;
                            mixed_addition_step_for_flipped_miller_loop(minus_R_affine_X, minus_R_affine_Y,
                                                                        minus_R_affine_Y2, R, ac);
                            result.add_coeffs.push_back(ac);
                        }

                        return result;
                    }
                };
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_PROJECTIVE_ATE_PRECOMPUTE_G2_HPP
