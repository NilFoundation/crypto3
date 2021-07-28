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

#ifndef CRYPTO3_ALGEBRA_CURVES_MNT4_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_MNT4_PARAMS_HPP

#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>

#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp4.hpp>

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/coordinates.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    template<std::size_t Version, 
                             typename Form, 
                             typename Coordinates>
                    struct mnt4_g1;

                    template<std::size_t Version, 
                             typename Form, 
                             typename Coordinates>
                    struct mnt4_g2;

                    using namespace algebra;
                    /** @brief A struct representing details about base and scalar fields.
                     *    @tparam Version version of the curve
                     *
                     */
                    template<std::size_t Version = 298>
                    struct mnt4_basic_params;

                    template<std::size_t Version, 
                             typename Form>
                    struct mnt4_params;

                    template<std::size_t Version, 
                             typename Form, 
                             typename Coordinates>
                    struct mnt4_g1_params;

                    template<std::size_t Version, 
                             typename Form, 
                             typename Coordinates>
                    struct mnt4_g2_params;

                    /** @brief A struct representing details about base and scalar fields.
                     *
                     */
                    template<>
                    struct mnt4_basic_params<298> {
                        using base_field_type = fields::mnt4_base_field<298>;
                        using scalar_field_type = fields::mnt4_scalar_field<298>;

                        using g1_field_type = base_field_type;
                        using g2_field_type = typename fields::fp2<base_field_type>;
                        using gt_field_type = typename fields::fp4<base_field_type>;
                    };

                    template<>
                    struct mnt4_params<298, forms::short_weierstrass> : public mnt4_basic_params<298> {

                        using base_field_type = typename mnt4_basic_params<298>::base_field_type;
                        using scalar_field_type = typename mnt4_basic_params<298>::scalar_field_type;

                        constexpr static const typename base_field_type::modulus_type a =
                            typename base_field_type::modulus_type(0x02);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                        constexpr static const typename base_field_type::modulus_type b = 
                            typename base_field_type::modulus_type(
                            0x3545A27639415585EA4D523234FC3EDD2A2070A085C7B980F4E9CD21A515D4B0EF528EC0FD5_cppui298);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct mnt4_g1_params<298, 
                        forms::short_weierstrass, 
                        coordinates::projective> : 
                            public mnt4_params<298, forms::short_weierstrass> {

                        using field_type = typename mnt4_basic_params<298>::g1_field_type;
                        using group_type = mnt4_g1<298, forms::short_weierstrass,  
                            coordinates::projective>;

                        using affine_params = mnt4_g1_params<298, 
                            forms::short_weierstrass, 
                            coordinates::affine>;

                        constexpr static const std::array<typename field_type::value_type, 3> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one(),
                            field_type::value_type::zero()};

                        constexpr static const std::array<typename field_type::value_type, 3> one_fill = {
                            typename field_type::value_type(
                                0x7A2CAF82A1BA85213FE6CA3875AEE86ABA8F73D69060C4079492B948DEA216B5B9C8D2AF46_cppui295),
                            typename field_type::value_type(
                                0x2DB619461CC82672F7F159FEC2E89D0148DCC9862D36778C1AFD96A71E29CBA48E710A48AB2_cppui298),
                            field_type::value_type::one()};
                    };

                    template<>
                    struct mnt4_g1_params<298, 
                        forms::short_weierstrass, 
                        coordinates::affine> : 
                            public mnt4_params<298, forms::short_weierstrass> {

                        using field_type = typename mnt4_basic_params<298>::g1_field_type;
                        using group_type = mnt4_g1<298, forms::short_weierstrass,  
                            coordinates::projective>;

                        using projective_params = mnt4_g1_params<298, 
                            forms::short_weierstrass, 
                            coordinates::projective>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            projective_params::zero_fill[0]/projective_params::zero_fill[2], 
                            projective_params::zero_fill[1]/projective_params::zero_fill[2]};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            projective_params::one_fill[0]/projective_params::one_fill[2], 
                            projective_params::one_fill[1]/projective_params::one_fill[2]};
                    };

                    template<>
                    struct mnt4_g2_params<298, 
                        forms::short_weierstrass, 
                        coordinates::projective> : 
                            public mnt4_params<298, forms::short_weierstrass> {

                        using field_type = typename mnt4_basic_params<298>::g2_field_type;
                        using group_type = mnt4_g2<298, forms::short_weierstrass,  
                            coordinates::projective>;

                        using affine_params = mnt4_g2_params<298, 
                            forms::short_weierstrass, 
                            coordinates::affine>;

                        constexpr static const typename field_type::value_type a =
                            typename field_type::value_type(a * field_type::value_type::non_residue,
                                                            g1_field_type::value_type::zero());

                        constexpr static const typename field_type::value_type b =
                            typename field_type::value_type(g1_field_type::value_type::zero(),
                                                        b * field_type::value_type::non_residue);

                        constexpr static const std::array<typename field_type::value_type, 3> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one(),
                            field_type::value_type::zero()};

                        constexpr static const std::array<typename field_type::value_type, 3> one_fill = {
                            typename field_type::value_type(
                                0x371780491C5660571FF542F2EF89001F205151E12A72CB14F01A931E72DBA7903DF6C09A9A4_cppui298,
                                0x4BA59A3F72DA165DEF838081AF697C851F002F576303302BB6C02C712C968BE32C0AE0A989_cppui295),
                            typename field_type::value_type(
                                0x4B471F33FFAAD868A1C47D6605D31E5C4B3B2E0B60EC98F0F610A5AAFD0D9522BCA4E79F22_cppui295,
                                0x355D05A1C69A5031F3F81A5C100CB7D982F78EC9CFC3B5168ED8D75C7C484FB61A3CBF0E0F1_cppui298),
                            field_type::value_type::one()};  
                    };

                    template<>
                    struct mnt4_g2_params<298, 
                        forms::short_weierstrass, 
                        coordinates::affine> : 
                            public mnt4_params<298, forms::short_weierstrass> {

                        using field_type = typename mnt4_basic_params<298>::g2_field_type;
                        using group_type = mnt4_g2<298, forms::short_weierstrass,  
                            coordinates::projective>;

                        using projective_params = mnt4_g2_params<298, 
                            forms::short_weierstrass, 
                            coordinates::projective>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            projective_params::zero_fill[0]/projective_params::zero_fill[2], 
                            projective_params::zero_fill[1]/projective_params::zero_fill[2]};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            projective_params::one_fill[0]/projective_params::one_fill[2], 
                            projective_params::one_fill[1]/projective_params::one_fill[2]};
                    };

                    constexpr typename mnt4_params<298, forms::short_weierstrass>::base_field_type::modulus_type const mnt4_params<298, forms::short_weierstrass>::a;
                    constexpr typename mnt4_params<298, forms::short_weierstrass>::base_field_type::modulus_type const mnt4_params<298, forms::short_weierstrass>::b;

                    constexpr std::array<typename mnt4_g1_params<298, forms::short_weierstrass, 
                        coordinates::projective>::field_type::value_type, 3> const
                        mnt4_g1_params<298, forms::short_weierstrass, 
                            coordinates::projective>::zero_fill;
                    constexpr std::array<typename mnt4_g1_params<298, forms::short_weierstrass, 
                        coordinates::projective>::field_type::value_type, 3> const
                        mnt4_g1_params<298, forms::short_weierstrass, 
                            coordinates::projective>::one_fill;

                    constexpr std::array<typename mnt4_g1_params<298, forms::short_weierstrass, 
                        coordinates::affine>::field_type::value_type, 2> const
                        mnt4_g1_params<298, forms::short_weierstrass, 
                            coordinates::affine>::zero_fill;
                    constexpr std::array<typename mnt4_g1_params<298, forms::short_weierstrass, 
                        coordinates::affine>::field_type::value_type, 2> const
                        mnt4_g1_params<298, forms::short_weierstrass, 
                            coordinates::affine>::one_fill;

                    constexpr std::array<typename mnt4_g2_params<298, forms::short_weierstrass, 
                        coordinates::projective>::field_type::value_type, 3> const
                        mnt4_g2_params<298, forms::short_weierstrass, 
                            coordinates::projective>::zero_fill;
                    constexpr std::array<typename mnt4_g2_params<298, forms::short_weierstrass, 
                        coordinates::projective>::field_type::value_type, 3> const
                        mnt4_g2_params<298, forms::short_weierstrass, 
                            coordinates::projective>::one_fill;

                    constexpr std::array<typename mnt4_g2_params<298, forms::short_weierstrass, 
                        coordinates::affine>::field_type::value_type, 2> const
                        mnt4_g2_params<298, forms::short_weierstrass, 
                            coordinates::affine>::zero_fill;
                    constexpr std::array<typename mnt4_g2_params<298, forms::short_weierstrass, 
                        coordinates::affine>::field_type::value_type, 2> const
                        mnt4_g2_params<298, forms::short_weierstrass, 
                            coordinates::affine>::one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_MNT4_PARAMS_HPP
