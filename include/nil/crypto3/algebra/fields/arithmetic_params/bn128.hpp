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

#ifndef CRYPTO3_ALGEBRA_FIELDS_BN128_ARITHMETIC_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_BN128_ARITHMETIC_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>

#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/bn128/base_field.hpp>
#include <nil/crypto3/algebra/fields/bn128/scalar_field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                template<std::size_t Version>
                struct arithmetic_params<bn128_base_field<Version>> : public params<bn128_base_field<Version>> {
                private:
                    typedef params<bn128_base_field<Version>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const std::size_t s = 0x01;
                    constexpr static const modulus_type t =
                        0x183227397098D014DC2822DB40C0AC2ECBC0B548B438E5469E10460B6C3E7EA3_cppui253;
                    constexpr static const modulus_type t_minus_1_over_2 =
                        0xC19139CB84C680A6E14116DA060561765E05AA45A1C72A34F082305B61F3F51_cppui252;
                    constexpr static const modulus_type arithmetic_generator = 0x01;
                    constexpr static const modulus_type geometric_generator = 0x02;
                    constexpr static const modulus_type multiplicative_generator = 0x03;
                    constexpr static const modulus_type root_of_unity =
                        0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD46_cppui254;
                    constexpr static const modulus_type nqr = 0x03;
                    constexpr static const modulus_type nqr_to_t =
                        0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD46_cppui254;
                    constexpr static const modulus_type Rsquared =
                        0x6D89F71CAB8351F47AB1EFF0A417FF6B5E71911D44501FBF32CFC5B538AFA89_cppui251;
                    constexpr static const modulus_type Rcubed =
                        0x20FD6E902D592544EF7F0B0C0ADA0AFB62F210E6A7283DB6B1CD6DAFDA1530DF_cppui254;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0x183227397098D014DC2822DB40C0AC2ECBC0B548B438E5469E10460B6C3E7EA3_cppui254;
                };

                template<std::size_t Version>
                struct arithmetic_params<fp2<bn128_base_field<Version>>>
                    : public params<bn128_base_field<Version>> {
                private:
                    typedef params<bn128_base_field<Version>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;
                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t s = 0x04;
                    constexpr static const extended_modulus_type t =
                        0x925C4B8763CBF9C599A6F7C0348D21CB00B85511637560626EDFA5C34C6B38D04689E957A1242C84A50189C6D96CADCA602072D09EAC1013B5458A2275D69B_cppui504;
                    constexpr static const extended_modulus_type t_minus_1_over_2 =
                        0x492E25C3B1E5FCE2CCD37BE01A4690E5805C2A88B1BAB031376FD2E1A6359C682344F4ABD09216425280C4E36CB656E5301039684F560809DAA2C5113AEB4D_cppui503;
                    constexpr static const std::array<modulus_type, 2> nqr = {0x02, 0x01};
                    constexpr static const std::array<modulus_type, 2> nqr_to_t = {
                        0xB20DCB5704E326A0DD3ECD4F30515275398A41A4E1DC5D347CFBBEDDA71CF82_cppui252,
                        0xB1FFEFD8885BF22252522C29527D19F05CFC50E9715370AB0F3A6CA462390C_cppui248};

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const extended_modulus_type group_order =
                        0x492E25C3B1E5FCE2CCD37BE01A4690E5805C2A88B1BAB031376FD2E1A6359C682344F4ABD09216425280C4E36CB656E5301039684F560809DAA2C5113AEB4D8_cppui507;
                };

                template<std::size_t Version>
                struct arithmetic_params<bn128_scalar_field<Version>>
                    : public params<bn128_scalar_field<Version>> {
                private:
                    typedef params<bn128_scalar_field<Version>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const std::size_t s = 0x1C;
                    constexpr static const modulus_type t =
                        0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F_cppui226;
                    constexpr static const modulus_type t_minus_1_over_2 =
                        0x183227397098D014DC2822DB40C0AC2E9419F4243CDCB848A1F0FAC9F_cppui225;
                    constexpr static const modulus_type arithmetic_generator = 0x01;
                    constexpr static const modulus_type geometric_generator = 0x02;
                    constexpr static const modulus_type multiplicative_generator = 0x05;
                    constexpr static const modulus_type root_of_unity =
                        0x2A3C09F0A58A7E8500E0A7EB8EF62ABC402D111E41112ED49BD61B6E725B19F0_cppui254;
                    constexpr static const modulus_type nqr = 0x05;
                    constexpr static const modulus_type nqr_to_t =
                        0x2A3C09F0A58A7E8500E0A7EB8EF62ABC402D111E41112ED49BD61B6E725B19F0_cppui254;
                    constexpr static const modulus_type Rsquared =
                        0x216D0B17F4E44A58C49833D53BB808553FE3AB1E35C59E31BB8E645AE216DA7_cppui250;
                    constexpr static const modulus_type Rcubed =
                        0xCF8594B7FCC657C893CC664A19FCFED2A489CBE1CFBB6B85E94D8E1B4BF0040_cppui252;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0x183227397098D014DC2822DB40C0AC2E9419F4243CDCB848A1F0FAC9F8000000_cppui254;
                };

                constexpr std::size_t const arithmetic_params<bn128_base_field<254>>::s;
                constexpr std::size_t const arithmetic_params<fp2<bn128_base_field<254>>>::s;
                constexpr std::size_t const arithmetic_params<bn128_scalar_field<254>>::s;

                constexpr typename arithmetic_params<bn128_base_field<254>>::modulus_type const
                    arithmetic_params<bn128_base_field<254>>::t;
                constexpr typename arithmetic_params<fp2<bn128_base_field<254>>>::extended_modulus_type const
                    arithmetic_params<fp2<bn128_base_field<254>>>::t;
                constexpr typename arithmetic_params<bn128_scalar_field<254>>::modulus_type const
                    arithmetic_params<bn128_scalar_field<254>>::t;

                constexpr typename arithmetic_params<bn128_base_field<254>>::modulus_type const
                    arithmetic_params<bn128_base_field<254>>::t_minus_1_over_2;
                constexpr typename arithmetic_params<fp2<bn128_base_field<254>>>::extended_modulus_type const
                    arithmetic_params<fp2<bn128_base_field<254>>>::t_minus_1_over_2;
                constexpr typename arithmetic_params<bn128_scalar_field<254>>::modulus_type const
                    arithmetic_params<bn128_scalar_field<254>>::t_minus_1_over_2;

                constexpr typename arithmetic_params<bn128_base_field<254>>::modulus_type const
                    arithmetic_params<bn128_base_field<254>>::arithmetic_generator;
                constexpr typename arithmetic_params<bn128_scalar_field<254>>::modulus_type const
                    arithmetic_params<bn128_scalar_field<254>>::arithmetic_generator;

                constexpr typename arithmetic_params<bn128_base_field<254>>::modulus_type const
                    arithmetic_params<bn128_base_field<254>>::geometric_generator;
                constexpr typename arithmetic_params<bn128_scalar_field<254>>::modulus_type const
                    arithmetic_params<bn128_scalar_field<254>>::geometric_generator;

                constexpr typename arithmetic_params<bn128_base_field<254>>::modulus_type const
                    arithmetic_params<bn128_base_field<254>>::multiplicative_generator;
                constexpr typename arithmetic_params<bn128_scalar_field<254>>::modulus_type const
                    arithmetic_params<bn128_scalar_field<254>>::multiplicative_generator;

                constexpr typename arithmetic_params<bn128_base_field<254>>::modulus_type const
                    arithmetic_params<bn128_base_field<254>>::root_of_unity;
                constexpr typename arithmetic_params<bn128_scalar_field<254>>::modulus_type const
                    arithmetic_params<bn128_scalar_field<254>>::root_of_unity;

                constexpr typename arithmetic_params<bn128_base_field<254>>::modulus_type const
                    arithmetic_params<bn128_base_field<254>>::nqr;
                constexpr std::array<typename arithmetic_params<fp2<bn128_base_field<254>>>::modulus_type, 2> const
                    arithmetic_params<fp2<bn128_base_field<254>>>::nqr;
                constexpr typename arithmetic_params<bn128_scalar_field<254>>::modulus_type const
                    arithmetic_params<bn128_scalar_field<254>>::nqr;

                constexpr typename arithmetic_params<bn128_base_field<254>>::modulus_type const
                    arithmetic_params<bn128_base_field<254>>::nqr_to_t;
                constexpr std::array<typename arithmetic_params<fp2<bn128_base_field<254>>>::modulus_type, 2> const
                    arithmetic_params<fp2<bn128_base_field<254>>>::nqr_to_t;
                constexpr typename arithmetic_params<bn128_scalar_field<254>>::modulus_type const
                    arithmetic_params<bn128_scalar_field<254>>::nqr_to_t;

                constexpr typename arithmetic_params<bn128_base_field<254>>::modulus_type const
                    arithmetic_params<bn128_base_field<254>>::Rsquared;
                constexpr typename arithmetic_params<bn128_scalar_field<254>>::modulus_type const
                    arithmetic_params<bn128_scalar_field<254>>::Rsquared;

                constexpr typename arithmetic_params<bn128_base_field<254>>::modulus_type const
                    arithmetic_params<bn128_base_field<254>>::Rcubed;
                constexpr typename arithmetic_params<bn128_scalar_field<254>>::modulus_type const
                    arithmetic_params<bn128_scalar_field<254>>::Rcubed;

                constexpr typename arithmetic_params<bn128_base_field<254>>::modulus_type const
                    arithmetic_params<bn128_base_field<254>>::modulus;
                constexpr typename arithmetic_params<fp2<bn128_base_field<254>>>::modulus_type const
                    arithmetic_params<fp2<bn128_base_field<254>>>::modulus;
                constexpr typename arithmetic_params<bn128_scalar_field<254>>::modulus_type const
                    arithmetic_params<bn128_scalar_field<254>>::modulus;

                constexpr typename arithmetic_params<bn128_base_field<254>>::modulus_type const
                    arithmetic_params<bn128_base_field<254>>::group_order;
                constexpr typename arithmetic_params<fp2<bn128_base_field<254>>>::extended_modulus_type const
                    arithmetic_params<fp2<bn128_base_field<254>>>::group_order;
                constexpr typename arithmetic_params<bn128_scalar_field<254>>::modulus_type const
                    arithmetic_params<bn128_scalar_field<254>>::group_order;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_BN128_ARITHMETIC_PARAMS_HPP
