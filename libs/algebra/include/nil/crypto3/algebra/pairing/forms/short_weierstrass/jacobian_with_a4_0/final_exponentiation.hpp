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

#ifndef CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_FINAL_EXPONENTIATION_HPP
#define CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_FINAL_EXPONENTIATION_HPP

#include <nil/crypto3/algebra/pairing/detail/forms/short_weierstrass/jacobian_with_a4_0/types.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<typename CurveType>
                class short_weierstrass_jacobian_with_a4_0_final_exponentiation {
                    using curve_type = CurveType;

                    using params_type = detail::pairing_params<curve_type>;
                    typedef detail::short_weierstrass_jacobian_with_a4_0_types_policy<curve_type> policy_type;

                    using base_field_type = typename curve_type::base_field_type;
                    using gt_type = typename curve_type::gt_type;

                    static typename gt_type::value_type
                        final_exponentiation_first_chunk(const typename gt_type::value_type &elt) {

                        /*
                          Computes result = elt^((q^6-1)*(q^2+1)).
                          Follows, e.g., Beuchat et al page 9, by computing result as follows:
                             elt^((q^6-1)*(q^2+1)) = (conj(elt) * elt^(-1))^(q^2+1)
                          More precisely:
                          A = conj(elt)
                          B = elt.inversed()
                          C = A * B
                          D = C.Frobenius_map(2)
                          result = D * C
                        */

                        const typename gt_type::value_type A = elt.unitary_inversed();
                        const typename gt_type::value_type B = elt.inversed();
                        const typename gt_type::value_type C = A * B;
                        const typename gt_type::value_type D = C.Frobenius_map(2);
                        const typename gt_type::value_type result = D * C;

                        return result;
                    }

                    static typename gt_type::value_type exp_by_z(const typename gt_type::value_type &elt) {

                        typename gt_type::value_type result = elt.cyclotomic_exp(params_type::final_exponent_z);
                        if (params_type::final_exponent_is_z_neg) {
                            result = result.unitary_inversed();
                        }

                        return result;
                    }

                    static typename gt_type::value_type
                        final_exponentiation_last_chunk(const typename gt_type::value_type &elt) {

                        const typename gt_type::value_type A = elt.cyclotomic_squared();    // elt^2
                        const typename gt_type::value_type B = A.unitary_inversed();        // elt^(-2)
                        const typename gt_type::value_type C = exp_by_z(elt);               // elt^z
                        const typename gt_type::value_type D = C.cyclotomic_squared();      // elt^(2z)
                        const typename gt_type::value_type E = B * C;                       // elt^(z-2)
                        const typename gt_type::value_type F = exp_by_z(E);                 // elt^(z^2-2z)
                        const typename gt_type::value_type G = exp_by_z(F);                 // elt^(z^3-2z^2)
                        const typename gt_type::value_type H = exp_by_z(G);                 // elt^(z^4-2z^3)
                        const typename gt_type::value_type I = H * D;                       // elt^(z^4-2z^3+2z)
                        const typename gt_type::value_type J = exp_by_z(I);                 // elt^(z^5-2z^4+2z^2)
                        const typename gt_type::value_type K = E.unitary_inversed();        // elt^(-z+2)
                        const typename gt_type::value_type L = K * J;      // elt^(z^5-2z^4+2z^2) * elt^(-z+2)
                        const typename gt_type::value_type M = elt * L;    // elt^(z^5-2z^4+2z^2) * elt^(-z+2) * elt
                        const typename gt_type::value_type N = elt.unitary_inversed();    // elt^(-1)
                        const typename gt_type::value_type O = F * elt;                   // elt^(z^2-2z) * elt
                        const typename gt_type::value_type P = O.Frobenius_map(3);        // (elt^(z^2-2z) * elt)^(q^3)
                        const typename gt_type::value_type Q = I * N;    // elt^(z^4-2z^3+2z) * elt^(-1)
                        const typename gt_type::value_type R =
                            Q.Frobenius_map(1);                          // (elt^(z^4-2z^3+2z) * elt^(-1))^q
                        const typename gt_type::value_type S = C * G;    // elt^(z^3-2z^2) * elt^z
                        const typename gt_type::value_type T = S.Frobenius_map(2);    // (elt^(z^3-2z^2) * elt^z)^(q^2)
                        const typename gt_type::value_type U =
                            T * P;    // (elt^(z^2-2z) * elt)^(q^3) * (elt^(z^3-2z^2) * elt^z)^(q^2)
                        const typename gt_type::value_type V =
                            U * R;    // (elt^(z^2-2z) * elt)^(q^3) * (elt^(z^3-2z^2) * elt^z)^(q^2) *
                                      // (elt^(z^4-2z^3+2z) * elt^(-1))^q
                        const typename gt_type::value_type W =
                            V * M;    // (elt^(z^2-2z) * elt)^(q^3) * (elt^(z^3-2z^2) * elt^z)^(q^2) *
                                      // (elt^(z^4-2z^3+2z) * elt^(-1))^q * elt^(z^5-2z^4+2z^2) * elt^(-z+2) * elt

                        return W;
                    }

                public:
                    static typename gt_type::value_type process(const typename gt_type::value_type &elt) {

                        /* OLD naive version:
                            typename gt_type::value_type result =
                                elt^final_exponent;
                        */
                        typename gt_type::value_type A = final_exponentiation_first_chunk(elt);
                        typename gt_type::value_type result = final_exponentiation_last_chunk(A);

                        return result;
                    }
                };
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_FINAL_EXPONENTIATION_HPP
