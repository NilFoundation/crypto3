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

#ifndef CRYPTO3_ALGEBRA_CURVES_SECP_R1_256_SHORT_WEIERSTRASS_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_SECP_R1_256_SHORT_WEIERSTRASS_PARAMS_HPP

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/secp_r1/types.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    template<>
                    struct secp_r1_params<160, forms::short_weierstrass> {

                        using base_field_type = typename secp_r1_types<160>::base_field_type;
                        using scalar_field_type = typename secp_r1_types<160>::scalar_field_type;

                        constexpr static const typename secp_r1_types<160>::integral_type a =
                            typename secp_r1_types<160>::integral_type(
                                0xffffffffffffffffffffffffffffffff7ffffffc_cppui160);    ///< coefficient
                        ///< of
                        ///< short
                        ///< Weierstrass
                        ///< curve
                        ///< $y^2=x^3+a*x+b$
                        constexpr static const typename secp_r1_types<160>::integral_type b =
                            typename secp_r1_types<160>::integral_type(
                                0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45_cppui160);    ///< coefficient
                                                                                         ///< of
                                                                                         ///< short
                                                                                         ///< Weierstrass
                                                                                         ///< curve
                                                                                         ///< $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct secp_r1_g1_params<160, forms::short_weierstrass>
                        : public secp_r1_params<160, forms::short_weierstrass> {

                        using field_type = typename secp_r1_types<160>::g1_field_type;

                        template<typename Coordinates>
                        using group_type = secp_r1_types<160>::g1_type<forms::short_weierstrass, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(0x4a96b5688ef573284664698968c38bb913cbfc82_cppui160),
                            typename field_type::value_type(0x23a628553168947d59dcc912042351377ac5fb32_cppui160)};
                    };

                    constexpr typename secp_r1_types<160>::integral_type const
                        secp_r1_params<160, forms::short_weierstrass>::a;
                    constexpr typename secp_r1_types<160>::integral_type const
                        secp_r1_params<160, forms::short_weierstrass>::b;

                    constexpr std::array<
                        typename secp_r1_g1_params<160, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_r1_g1_params<160, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<
                        typename secp_r1_g1_params<160, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_r1_g1_params<160, forms::short_weierstrass>::one_fill;

                    template<>
                    struct secp_r1_params<192, forms::short_weierstrass> {

                        using base_field_type = typename secp_r1_types<192>::base_field_type;
                        using scalar_field_type = typename secp_r1_types<192>::scalar_field_type;

                        constexpr static const typename secp_r1_types<192>::integral_type a =
                            typename secp_r1_types<192>::integral_type(
                                0xfffffffffffffffffffffffffffffffefffffffffffffffc_cppui192);    ///< coefficient
                        ///< of
                        ///< short
                        ///< Weierstrass
                        ///< curve
                        ///< $y^2=x^3+a*x+b$
                        constexpr static const typename secp_r1_types<192>::integral_type b =
                            typename secp_r1_types<192>::integral_type(
                                0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1_cppui192);    ///< coefficient
                                                                                                 ///< of
                                                                                                 ///< short
                                                                                                 ///< Weierstrass
                                                                                                 ///< curve
                                                                                                 ///< $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct secp_r1_g1_params<192, forms::short_weierstrass>
                        : public secp_r1_params<192, forms::short_weierstrass> {

                        using field_type = typename secp_r1_types<192>::g1_field_type;

                        template<typename Coordinates>
                        using group_type = secp_r1_types<192>::g1_type<forms::short_weierstrass, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(
                                0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012_cppui192),
                            typename field_type::value_type(
                                0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811_cppui192)};
                    };

                    constexpr typename secp_r1_types<192>::integral_type const
                        secp_r1_params<192, forms::short_weierstrass>::a;
                    constexpr typename secp_r1_types<192>::integral_type const
                        secp_r1_params<192, forms::short_weierstrass>::b;

                    constexpr std::array<
                        typename secp_r1_g1_params<192, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_r1_g1_params<192, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<
                        typename secp_r1_g1_params<192, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_r1_g1_params<192, forms::short_weierstrass>::one_fill;

                    template<>
                    struct secp_r1_params<224, forms::short_weierstrass> {

                        using base_field_type = typename secp_r1_types<224>::base_field_type;
                        using scalar_field_type = typename secp_r1_types<224>::scalar_field_type;

                        constexpr static const typename secp_r1_types<224>::integral_type a =
                            typename secp_r1_types<224>::integral_type(
                                0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe_cppui224);    ///< coefficient
                        ///< of
                        ///< short
                        ///< Weierstrass
                        ///< curve
                        ///< $y^2=x^3+a*x+b$
                        constexpr static const typename secp_r1_types<224>::integral_type b =
                            typename secp_r1_types<224>::integral_type(
                                0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4_cppui224);    ///< coefficient
                                                                                                         ///< of
                                                                                                         ///< short
                        ///< Weierstrass
                        ///< curve
                        ///< $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct secp_r1_g1_params<224, forms::short_weierstrass>
                        : public secp_r1_params<224, forms::short_weierstrass> {

                        using field_type = typename secp_r1_types<224>::g1_field_type;

                        template<typename Coordinates>
                        using group_type = secp_r1_types<224>::g1_type<forms::short_weierstrass, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(
                                0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21_cppui224),
                            typename field_type::value_type(
                                0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34_cppui224)};
                    };

                    constexpr typename secp_r1_types<224>::integral_type const
                        secp_r1_params<224, forms::short_weierstrass>::a;
                    constexpr typename secp_r1_types<224>::integral_type const
                        secp_r1_params<224, forms::short_weierstrass>::b;

                    constexpr std::array<
                        typename secp_r1_g1_params<224, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_r1_g1_params<224, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<
                        typename secp_r1_g1_params<224, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_r1_g1_params<224, forms::short_weierstrass>::one_fill;

                    template<>
                    struct secp_r1_params<256, forms::short_weierstrass> {

                        using base_field_type = typename secp_r1_types<256>::base_field_type;
                        using scalar_field_type = typename secp_r1_types<256>::scalar_field_type;

                        constexpr static const typename secp_r1_types<256>::integral_type a =
                            typename secp_r1_types<256>::integral_type(
                                0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc_cppui256);    ///< coefficient
                                                                                                                 ///< of
                                                                                                                 ///< short
                                                                                                                 ///< Weierstrass
                                                                                                                 ///< curve
                                                                                                                 ///< $y^2=x^3+a*x+b$
                        constexpr static const typename secp_r1_types<256>::integral_type b =
                            typename secp_r1_types<256>::integral_type(
                                0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b_cppui256);    ///< coefficient
                                                                                                                 ///< of
                                                                                                                 ///< short
                                                                                                                 ///< Weierstrass
                                                                                                                 ///< curve
                                                                                                                 ///< $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct secp_r1_g1_params<256, forms::short_weierstrass>
                        : public secp_r1_params<256, forms::short_weierstrass> {

                        using field_type = typename secp_r1_types<256>::g1_field_type;

                        template<typename Coordinates>
                        using group_type = secp_r1_types<256>::g1_type<forms::short_weierstrass, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(
                                0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296_cppui256),
                            typename field_type::value_type(
                                0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_cppui256)};
                    };

                    constexpr typename secp_r1_types<256>::integral_type const
                        secp_r1_params<256, forms::short_weierstrass>::a;
                    constexpr typename secp_r1_types<256>::integral_type const
                        secp_r1_params<256, forms::short_weierstrass>::b;

                    constexpr std::array<
                        typename secp_r1_g1_params<256, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_r1_g1_params<256, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<
                        typename secp_r1_g1_params<256, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_r1_g1_params<256, forms::short_weierstrass>::one_fill;

                    template<>
                    struct secp_r1_params<384, forms::short_weierstrass> {

                        using base_field_type = typename secp_r1_types<384>::base_field_type;
                        using scalar_field_type = typename secp_r1_types<384>::scalar_field_type;

                        constexpr static const typename secp_r1_types<384>::integral_type a =
                            typename secp_r1_types<384>::integral_type(
                                0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc_cppui384);    ///< coefficient
                        ///< of
                        ///< short
                        ///< Weierstrass
                        ///< curve
                        ///< $y^2=x^3+a*x+b$
                        constexpr static const typename secp_r1_types<384>::integral_type b =
                            typename secp_r1_types<384>::integral_type(
                                0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef_cppui384);    ///< coefficient
                        ///< of
                        ///< short
                        ///< Weierstrass
                        ///< curve
                        ///< $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct secp_r1_g1_params<384, forms::short_weierstrass>
                        : public secp_r1_params<384, forms::short_weierstrass> {

                        using field_type = typename secp_r1_types<384>::g1_field_type;

                        template<typename Coordinates>
                        using group_type = secp_r1_types<384>::g1_type<forms::short_weierstrass, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(
                                0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7_cppui384),
                            typename field_type::value_type(
                                0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f_cppui384)};
                    };

                    constexpr typename secp_r1_types<384>::integral_type const
                        secp_r1_params<384, forms::short_weierstrass>::a;
                    constexpr typename secp_r1_types<384>::integral_type const
                        secp_r1_params<384, forms::short_weierstrass>::b;

                    constexpr std::array<
                        typename secp_r1_g1_params<384, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_r1_g1_params<384, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<
                        typename secp_r1_g1_params<384, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_r1_g1_params<384, forms::short_weierstrass>::one_fill;

                    template<>
                    struct secp_r1_params<521, forms::short_weierstrass> {

                        using base_field_type = typename secp_r1_types<521>::base_field_type;
                        using scalar_field_type = typename secp_r1_types<521>::scalar_field_type;

                        constexpr static const typename secp_r1_types<521>::integral_type a =
                            typename secp_r1_types<521>::integral_type(
                                0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc_cppui521);    ///< coefficient
                        ///< of
                        ///< short
                        ///< Weierstrass
                        ///< curve
                        ///< $y^2=x^3+a*x+b$
                        constexpr static const typename secp_r1_types<521>::integral_type b =
                            typename secp_r1_types<521>::integral_type(
                                0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00_cppui521);    ///< coefficient
                        ///< of
                        ///< short
                        ///< Weierstrass
                        ///< curve
                        ///< $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct secp_r1_g1_params<521, forms::short_weierstrass>
                        : public secp_r1_params<521, forms::short_weierstrass> {

                        using field_type = typename secp_r1_types<521>::g1_field_type;

                        template<typename Coordinates>
                        using group_type = secp_r1_types<521>::g1_type<forms::short_weierstrass, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(
                                0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66_cppui521),
                            typename field_type::value_type(
                                0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650_cppui521)};
                    };

                    constexpr typename secp_r1_types<521>::integral_type const
                        secp_r1_params<521, forms::short_weierstrass>::a;
                    constexpr typename secp_r1_types<521>::integral_type const
                        secp_r1_params<521, forms::short_weierstrass>::b;

                    constexpr std::array<
                        typename secp_r1_g1_params<521, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_r1_g1_params<521, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<
                        typename secp_r1_g1_params<521, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_r1_g1_params<521, forms::short_weierstrass>::one_fill;
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_SECP_R1_256_SHORT_WEIERSTRASS_PARAMS_HPP
