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

#ifndef CRYPTO3_ALGEBRA_CURVES_EDWARDS_183_EDWARDS_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_EDWARDS_183_EDWARDS_PARAMS_HPP

#include <nil/crypto3/algebra/fields/edwards/base_field.hpp>
#include <nil/crypto3/algebra/fields/edwards/scalar_field.hpp>

#include <nil/crypto3/algebra/fields/fp3.hpp>
#include <nil/crypto3/algebra/fields/fp6_2over3.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    template<std::size_t Version>
                    struct edwards_g1;

                    template<std::size_t Version>
                    struct edwards_g2;

                    using namespace algebra;
                    /** @brief A struct representing details about base and scalar fields.
                     *    @tparam Version version of the curve
                     *
                     */
                    template<std::size_t Version = 183>
                    struct edwards_basic_params;

                    template<std::size_t Version = 183>
                    struct edwards_edwards_params;

                    template<std::size_t Version = 183>
                    struct edwards_edwards_g1_affine_params;

                    template<std::size_t Version = 183>
                    struct edwards_edwards_g2_affine_params;

                    template<std::size_t Version = 183>
                    struct edwards_edwards_g1_inverted_params;

                    template<std::size_t Version = 183>
                    struct edwards_edwards_g2_inverted_params;

                    /** @brief A struct representing details about base and scalar fields.
                     *
                     */
                    template<>
                    struct edwards_basic_params<183> {
                        using base_field_type = fields::edwards_base_field<183>;
                        using scalar_field_type = fields::edwards_scalar_field<183>;

                        using g1_field_type = base_field_type;
                        using g2_field_type = typename fields::fp3<base_field_type>;
                        using gt_field_type = typename fields::fp6_2over3<base_field_type>;
                    };

                    template<>
                    struct edwards_edwards_params<183> : public edwards_basic_params<183> {

                        using base_field_type = typename edwards_basic_params<183>::base_field_type;
                        using scalar_field_type = typename edwards_basic_params<183>::scalar_field_type;

                        constexpr static const typename base_field_type::modulus_type c =
                            typename base_field_type::modulus_type(0x01);
                        constexpr static const typename base_field_type::modulus_type d = 
                            typename base_field_type::modulus_type(
                            0x64536D55979879327CF1306BB5A6277D254EF9776CE70_cppui179);
                    };

                    template<>
                    struct edwards_edwards_g1_inverted_params<183> : public edwards_edwards_params<183> {

                        using field_type = typename edwards_basic_params<183>::g1_field_type;
                        using group_type = edwards_g1<183>;

                        constexpr static const std::array<typename field_type::value_type, 3> zero_fill = {
                            field_type::value_type::one(), 
                            field_type::value_type::zero(), 
                            field_type::value_type::zero()};

                        constexpr static const std::array<typename field_type::value_type, 3> one_fill = {
                            typename field_type::value_type(0x32d83d8aaa0c500f57b15fda90b1ad111067f812c7dd27_cppui182),
                            typename field_type::value_type(0x26c5df4587aa6a5d345efc9f2d47f8b1656517ef618f7a_cppui182),
                            typename field_type::value_type(0x3c6395f7eeafc1d930f0234a46e4a4806b953f0c3374ac_cppui182)};
                    };

                    template<>
                    struct edwards_edwards_g2_inverted_params<183> : public edwards_edwards_params<183> {

                        using field_type = typename edwards_basic_params<183>::g2_field_type;
                        using group_type = edwards_g2<183>;

                        constexpr static const typename field_type::value_type twist =
                            typename field_type::value_type(0x00, 0x01, 0x00);
                        constexpr static const typename field_type::value_type::underlying_type g1_a = 
                            typename field_type::value_type::underlying_type(a);
                        constexpr static const typename field_type::value_type a = g1_a * twist;
                        constexpr static const typename field_type::value_type::underlying_type g1_d = 
                            typename field_type::value_type::underlying_type(d);
                        constexpr static const typename field_type::value_type d = g1_d * twist;

                        constexpr static const std::array<typename field_type::value_type, 3> zero_fill = {
                            field_type::value_type::one(), 
                            field_type::value_type::zero(), 
                            field_type::value_type::zero()};

                        constexpr static const std::array<typename field_type::value_type, 3> one_fill = {
                            typename field_type::value_type(0x3CE954C85AD30F53B1BB4C4F87029780F4141927FEB19_cppui178,
                                                               0x2214EB976DE3A4D9DF9C8D5F7AEDFEC337E03A20B32FFF_cppui182,
                                                               0x249774AB0EDC7FE2E665DDBFE08594F3071E0B3AC994C3_cppui182),
                            typename field_type::value_type(0x2F501F9482C0D0D6E80AC55A79FD4D4594CAF187952660_cppui182,
                                                        0x37BF8F1B1CDA11A81E8BB8F41B5FF462C9A13DC7DE1578_cppui182,
                                                        0x2962F0DA0C7928B2CFBBACE3D0354652B6922A764C12D8_cppui182),
                            typename field_type::value_type(0x3b6ad5c355d8b231b16e97b5c6f635357993efdc248101_cppui182,
                                                               0x2e8b3daf5fa18f9d9c6fa2ca0603fd0c9b09eeece8fd0d_cppui182,
                                                               0x3c3baf061e62a04a4e9d1db335b8779c70384ae2933a73_cppui182)};
                    };

                    constexpr typename edwards_edwards_params<183>::base_field_type::modulus_type const edwards_edwards_params<183>::c;
                    constexpr typename edwards_edwards_params<183>::base_field_type::modulus_type const edwards_edwards_params<183>::d;

                    constexpr std::array<typename edwards_edwards_g1_inverted_params<183>::field_type::value_type, 3> const
                        edwards_edwards_g1_inverted_params<183>::zero_fill;
                    constexpr std::array<typename edwards_edwards_g1_inverted_params<183>::field_type::value_type, 3> const
                        edwards_edwards_g1_inverted_params<183>::one_fill;
                    constexpr std::array<typename edwards_edwards_g2_inverted_params<183>::field_type::value_type, 3> const
                        edwards_edwards_g2_inverted_params<183>::zero_fill;
                    constexpr std::array<typename edwards_edwards_g2_inverted_params<183>::field_type::value_type, 3> const
                        edwards_edwards_g2_inverted_params<183>::one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_EDWARDS_183_EDWARDS_PARAMS_HPP
