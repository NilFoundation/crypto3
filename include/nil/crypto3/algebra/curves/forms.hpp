//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_ALGEBRA_CURVES_FORMS_HPP
#define CRYPTO3_ZK_ALGEBRA_CURVES_FORMS_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                struct forms {

                    /* @brief Curve Doubling-oriented Doche–Icart–Kohel form.
                     * Description: http://www.hyperelliptic.org/EFD/g1p/auto-2dik.html
                     */
                    struct doubling_oriented_doche_icart_kohel { };
                    /* @brief Curve Tripling-oriented Doche–Icart–Kohel form.
                     * Description: http://www.hyperelliptic.org/EFD/g1p/auto-3dik.html
                     */
                    struct tripling_oriented_doche_icart_kohel { };
                    /* @brief Curve Edwards form.
                     * Description: http://www.hyperelliptic.org/EFD/g1p/auto-edwards.html
                     */
                    struct edwards { };
                    /* @brief Curve Hessian form.
                     * Description: http://www.hyperelliptic.org/EFD/g1p/auto-hessian.html
                     */
                    struct hessian { };
                    /* @brief Curve Jacobi intersections form.
                     * Description: http://www.hyperelliptic.org/EFD/g1p/auto-jintersect.html
                     */
                    struct jacobi_intersections { };
                    /* @brief Curve Jacobi quartics form.
                     * Description: http://www.hyperelliptic.org/EFD/g1p/auto-jquartic.html
                     */
                    struct jacobi_quatrics { };
                    /* @brief Curve Montgomery form.
                     * Description: http://www.hyperelliptic.org/EFD/g1p/auto-montgom.html
                     */
                    struct montgomery { };
                    /* @brief Curve Short Weierstrass form.
                     * Description: http://www.hyperelliptic.org/EFD/g1p/auto-shortw.html
                     */
                    struct short_weierstrass { };
                    /* @brief Curve Twisted Edwards form.
                     * Description: http://www.hyperelliptic.org/EFD/g1p/auto-twisted.html
                     */
                    struct twisted_edwards { };
                    /* @brief Curve Twisted Hessian form.
                     * Description: http://www.hyperelliptic.org/EFD/g1p/auto-twistedhessian.html
                     */
                    struct twisted_hessian { };
                };

            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_ALGEBRA_CURVES_FORMS_HPP
