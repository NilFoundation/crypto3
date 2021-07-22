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

#ifndef CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_ADD_1998_CMO_2_HPP
#define CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_ADD_1998_CMO_2_HPP

#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>
#include <nil/crypto3/algebra/curves/detail/forms.hpp>

#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/coordinates.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    /** @brief A struct representing a group G1 of elliptic curve. 
                     *    @tparam CurveParams Parameters of the group 
                     *    @tparam Form Form of the curve 
                     *    @tparam Coordinates Representation coordinates of the group element 
                     */
                    template<typename CurveParams, 
                             algebra::curves::detail::forms Form, 
                             typename Coordinates>
                    struct element_g1{
                        using field_value_type = typename CurveParams::g1_field_type::value_type;

                        field_value_type X, Y, Z;
                    }

                    /** @brief A struct representing element addition from the group G1 of short Weierstrass curve.
                     *  NOTE: does not handle O and pts of order 2,4 
                     *  http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2
                     */
                    template<typename CurveParams>
                    struct add_1998_cmo_2 {
                        using field_type = typename CurveParams::g1_field_type;
                    private:
                        using params_type = CurveParams;
                        using field_value_type = typename field_type::value_type;
                    public:
                        using element_type = element_g1<CurveParams, algebra::curves::detail::forms::short_weierstrass, 
                                      algebra::curves::detail::short_weierstrass_coordinates::projective>;
                        using group_type = typename params_type::group_type;

                        constexpr static const algebra::curves::detail::forms form = 
                            algebra::curves::detail::forms::short_weierstrass;
                        constexpr static const 
                            algebra::curves::detail::short_weierstrass_coordinates coordinates = 
                            algebra::curves::detail::short_weierstrass_coordinates::projective;

                        constexpr static inline element_type process(
                            const element_type &first) {

                            const field_value_type Y1Z2 = (first.Y) * (second.Z);        // Y1Z2 = Y1*Z2
                            const field_value_type X1Z2 = (first.X) * (second.Z);        // X1Z2 = X1*Z2
                            const field_value_type Z1Z2 = (first.Z) * (second.Z);        // Z1Z2 = Z1*Z2
                            const field_value_type u = (second.Y) * (first.Z) - Y1Z2;    // u    = Y2*Z1-Y1Z2
                            const field_value_type uu = u.squared();            // uu   = u^2
                            const field_value_type v = (second.X) * (first.Z) - X1Z2;    // v    = X2*Z1-X1Z2
                            const field_value_type vv = v.squared();            // vv   = v^2
                            const field_value_type vvv = v * vv;                // vvv  = v*vv
                            const field_value_type R = vv * X1Z2;               // R    = vv*X1Z2
                            const field_value_type A =
                                uu * Z1Z2 - (vvv + R + R);                      // A    = uu*Z1Z2 - vvv - 2*R
                            const field_value_type X3 = v * A;                  // X3   = v*A
                            const field_value_type Y3 =
                                u * (R - A) - vvv * Y1Z2;                       // Y3   = u*(R-A) - vvv*Y1Z2
                            const field_value_type Z3 = vvv * Z1Z2;             // Z3   = vvv*Z1Z2

                            return element_type(X3, Y3, Z3);
                        }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_ADD_1998_CMO_2_HPP
