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

#ifndef CRYPTO3_ALGEBRA_CURVES_ALT_BN128_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_ALT_BN128_PARAMS_HPP

#include <nil/crypto3/algebra/fields/alt_bn128/base_field.hpp>
#include <nil/crypto3/algebra/fields/alt_bn128/scalar_field.hpp>

#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp12_2over3over2.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    template<std::size_t Version>
                    struct alt_bn128_g1;

                    template<std::size_t Version>
                    struct alt_bn128_g2;

                    using namespace algebra;
                    /** @brief A struct representing details about base and scalar fields.
                     *    @tparam Version version of the curve
                     *
                     */
                    template<std::size_t Version = 254>
                    struct alt_bn128_basic_params;

                    template<std::size_t Version = 254>
                    struct alt_bn128_short_weierstrass_params;

                    template<std::size_t Version = 254>
                    struct alt_bn128_short_weierstrass_g1_affine_params;

                    template<std::size_t Version = 254>
                    struct alt_bn128_short_weierstrass_g2_affine_params;

                    template<std::size_t Version = 254>
                    struct alt_bn128_short_weierstrass_g1_projective_params;

                    template<std::size_t Version = 254>
                    struct alt_bn128_short_weierstrass_g2_projective_params;

                    template<std::size_t Version = 254>
                    struct alt_bn128_short_weierstrass_g1_jacobian_with_a4_0_params;

                    template<std::size_t Version = 254>
                    struct alt_bn128_short_weierstrass_g2_jacobian_with_a4_0_params;

                    /** @brief A struct representing details about base and scalar fields.
                     *
                     */
                    template<>
                    struct alt_bn128_basic_params<254> {
                        using base_field_type = fields::alt_bn128_base_field<254>;
                        using scalar_field_type = fields::alt_bn128_scalar_field<254>;

                        using g1_field_type = base_field_type;
                        using g2_field_type = typename fields::fp2<base_field_type>;
                        using gt_field_type = typename fields::fp12_2over3over2<base_field_type>;
                    };

                    template<>
                    struct alt_bn128_short_weierstrass_params<254> : public alt_bn128_basic_params<254> {

                        using base_field_type = typename alt_bn128_basic_params<254>::base_field_type;
                        using scalar_field_type = typename alt_bn128_basic_params<254>::scalar_field_type;

                        constexpr static const typename base_field_type::modulus_type a =
                            typename base_field_type::modulus_type(0x00);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                        constexpr static const typename base_field_type::modulus_type b = 
                            typename base_field_type::modulus_type(0x03);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct alt_bn128_short_weierstrass_g1_jacobian_with_a4_0_params<254> : public alt_bn128_short_weierstrass_params<254> {

                        using field_type = typename alt_bn128_basic_params<254>::g1_field_type;
                        using group_type = alt_bn128_g1<254>;

                        constexpr static const std::array<typename field_type::value_type, 3> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one(),
                            field_type::value_type::zero()};

                        constexpr static const std::array<typename field_type::value_type, 3> one_fill = {
                            typename field_type::value_type(
                                0x01),
                            typename field_type::value_type(
                                0x02),
                            typename field_type::value_type(
                                0x01)};
                    };

                    template<>
                    struct alt_bn128_short_weierstrass_g2_jacobian_with_a4_0_params<254> : public alt_bn128_short_weierstrass_params<254> {

                        using field_type = typename alt_bn128_basic_params<254>::g2_field_type;
                        using group_type = alt_bn128_g2<254>;

                        constexpr static const typename field_type::value_type twist =
                            typename field_type::value_type(0x09, 0x01);
                        constexpr static const typename field_type::value_type::underlying_type g1_b = 
                            typename field_type::value_type::underlying_type(b);
                        constexpr static const typename field_type::value_type b = g1_b * twist.inversed();

                        constexpr static const std::array<typename field_type::value_type, 3> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one(),
                            field_type::value_type::zero()};

                        constexpr static const std::array<typename field_type::value_type, 3> one_fill = {
                            typename field_type::value_type(
                                0x1800DEEF121F1E76426A00665E5C4479674322D4F75EDADD46DEBD5CD992F6ED_cppui254,
                                0x198E9393920D483A7260BFB731FB5D25F1AA493335A9E71297E485B7AEF312C2_cppui254),
                            typename field_type::value_type(
                                0x12C85EA5DB8C6DEB4AAB71808DCB408FE3D1E7690C43D37B4CE6CC0166FA7DAA_cppui254,
                                0x90689D0585FF075EC9E99AD690C3395BC4B313370B38EF355ACDADCD122975B_cppui254),
                            field_type::value_type::one()};
                    };

                    constexpr typename alt_bn128_short_weierstrass_params<254>::base_field_type::modulus_type const alt_bn128_short_weierstrass_params<254>::a;
                    constexpr typename alt_bn128_short_weierstrass_params<254>::base_field_type::modulus_type const alt_bn128_short_weierstrass_params<254>::b;

                    constexpr std::array<typename alt_bn128_short_weierstrass_g1_jacobian_with_a4_0_params<254>::field_type::value_type, 3> const
                        alt_bn128_short_weierstrass_g1_jacobian_with_a4_0_params<254>::zero_fill;
                    constexpr std::array<typename alt_bn128_short_weierstrass_g1_jacobian_with_a4_0_params<254>::field_type::value_type, 3> const
                        alt_bn128_short_weierstrass_g1_jacobian_with_a4_0_params<254>::one_fill;
                    constexpr std::array<typename alt_bn128_short_weierstrass_g2_jacobian_with_a4_0_params<254>::field_type::value_type, 3> const
                        alt_bn128_short_weierstrass_g2_jacobian_with_a4_0_params<254>::zero_fill;
                    constexpr std::array<typename alt_bn128_short_weierstrass_g2_jacobian_with_a4_0_params<254>::field_type::value_type, 3> const
                        alt_bn128_short_weierstrass_g2_jacobian_with_a4_0_params<254>::one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_ALT_BN128_PARAMS_HPP
