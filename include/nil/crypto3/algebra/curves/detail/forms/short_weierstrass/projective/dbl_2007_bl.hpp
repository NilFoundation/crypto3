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

#ifndef CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_DBL_2007_BL_HPP
#define CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_DBL_2007_BL_HPP

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
                             forms Form, 
                             typename Coordinates>
                    struct element_g1{
                        using field_value_type = typename CurveParams::g1_field_type::value_type;

                        field_value_type X, Y, Z;
                    }

                    /** @brief A struct representing element doubling from the group G1 of short Weierstrass curve.
                     *  NOTE: does not handle O and pts of order 2,4
                     *  http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl
                     */
                    template<typename CurveParams>
                    struct dbl_2007_bl {
                        using field_type = typename CurveParams::g1_field_type;
                    private:
                        using params_type = CurveParams;
                        using field_value_type = typename field_type::value_type;
                    public:
                        using element_type = element_g1<CurveParams, forms::short_weierstrass, 
                                      short_weierstrass_coordinates::projective>;
                        using group_type = typename params_type::group_type;

                        constexpr static const forms form = 
                            forms::short_weierstrass;
                        constexpr static const 
                            short_weierstrass_coordinates coordinates = 
                            short_weierstrass_coordinates::projective;

                        constexpr static inline element_type process(
                            const element_type &first) {

                            if (first.is_zero()) {
                                return (*this);
                            } else {

                                const field_value_type XX = (first.X).squared();       // XX  = X1^2
                                const field_value_type ZZ = (first.Z).squared();       // ZZ  = Z1^2
                                const field_value_type w = params_type::a * ZZ + (XX + XX + XX);    // w   = a*ZZ + 3*XX
                                const field_value_type Y1Z1 = (first.Y) * (first.Z);
                                const field_value_type s = Y1Z1 + Y1Z1;      // s   = 2*Y1*Z1
                                const field_value_type ss = s.squared();     // ss  = s^2
                                const field_value_type sss = s * ss;         // sss = s*ss
                                const field_value_type R = (first.Y) * s;    // R   = Y1*s
                                const field_value_type RR = R.squared();     // RR  = R^2
                                const field_value_type B =
                                    ((first.X) + R).squared() - XX - RR;    // B   = (X1+R)^2 - XX - RR
                                const field_value_type h = w.squared() - B.doubled();    // h   = w^2 - 2*B
                                const field_value_type X3 = h * s;                       // X3  = h*s
                                const field_value_type Y3 =
                                    w * (B - h) - RR.doubled();                // Y3  = w*(B-h) - 2*RR
                                const field_value_type Z3 = sss;    // Z3  = sss

                                return element_type(X3, Y3, Z3);
                            }
                        }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_DBL_2007_BL_HPP
