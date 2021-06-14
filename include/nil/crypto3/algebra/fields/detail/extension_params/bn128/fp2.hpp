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

#ifndef CRYPTO3_ALGEBRA_FIELDS_BN128_FP2_EXTENSION_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_BN128_FP2_EXTENSION_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/bn128/base_field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                template<typename BaseField>
                struct fp2;
                namespace detail {

                    template<typename BaseField>
                    struct fp2_extension_params;

                    /************************* BN128 ***********************************/

                    template<std::size_t Version>
                    class fp2_extension_params<fields::bn128<Version>> : public params<fields::bn128<Version>> {

                        typedef fields::bn128<Version> base_field_type;
                        typedef params<base_field_type> policy_type;

                    public:
                        using field_type = fields::fp2<base_field_type>;

                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;
                        typedef typename policy_type::extended_modulus_type extended_modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        typedef base_field_type non_residue_field_type;
                        typedef typename non_residue_field_type::value_type non_residue_type;
                        typedef base_field_type underlying_field_type;
                        typedef typename underlying_field_type::value_type underlying_type;

                        constexpr static const std::size_t s = 0x04;
                        constexpr static const extended_modulus_type t =
                            0x925C4B8763CBF9C599A6F7C0348D21CB00B85511637560626EDFA5C34C6B38D04689E957A1242C84A50189C6D96CADCA602072D09EAC1013B5458A2275D69B_cppui504;
                        constexpr static const extended_modulus_type t_minus_1_over_2 =
                            0x492E25C3B1E5FCE2CCD37BE01A4690E5805C2A88B1BAB031376FD2E1A6359C682344F4ABD09216425280C4E36CB656E5301039684F560809DAA2C5113AEB4D_cppui503;
                        constexpr static const std::array<modulus_type, 2> nqr = {0x02, 0x01};
                        constexpr static const std::array<modulus_type, 2> nqr_to_t = {
                            0xB20DCB5704E326A0DD3ECD4F30515275398A41A4E1DC5D347CFBBEDDA71CF82_cppui252,
                            0xB1FFEFD8885BF22252522C29527D19F05CFC50E9715370AB0F3A6CA462390C_cppui248};

                        constexpr static const extended_modulus_type group_order =
                            0x492E25C3B1E5FCE2CCD37BE01A4690E5805C2A88B1BAB031376FD2E1A6359C682344F4ABD09216425280C4E36CB656E5301039684F560809DAA2C5113AEB4D8_cppui507;

                        /*constexpr static const std::array<non_residue_type, 2> Frobenius_coeffs_c1 =
                           {non_residue_type(0x00), non_residue_type(0x00)};*/

                        constexpr static const std::array<modulus_type, 2> Frobenius_coeffs_c1 = {0x00, 0x00};

                        constexpr static const non_residue_type non_residue =
                            non_residue_type(0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD46_cppui254);
                    };

                    template<std::size_t Version>
                    constexpr typename fp2_extension_params<bn128_base_field<Version>>::non_residue_type const
                        fp2_extension_params<bn128_base_field<Version>>::non_residue;

                    template<std::size_t Version>
                    constexpr typename std::size_t const fp2_extension_params<bn128_base_field<Version>>::s;

                    template<std::size_t Version>
                    constexpr typename fp2_extension_params<bn128_base_field<Version>>::extended_modulus_type const
                        fp2_extension_params<bn128_base_field<Version>>::t;

                    template<std::size_t Version>
                    constexpr typename fp2_extension_params<bn128_base_field<Version>>::extended_modulus_type const
                        fp2_extension_params<bn128_base_field<Version>>::t_minus_1_over_2;

                    template<std::size_t Version>
                    constexpr std::array<typename fp2_extension_params<bn128_base_field<Version>>::modulus_type,
                                         2> const fp2_extension_params<bn128_base_field<Version>>::nqr;

                    template<std::size_t Version>
                    constexpr std::array<typename fp2_extension_params<bn128_base_field<Version>>::modulus_type,
                                         2> const fp2_extension_params<bn128_base_field<Version>>::nqr_to_t;

                    template<std::size_t Version>
                    constexpr typename fp2_extension_params<bn128_base_field<Version>>::extended_modulus_type const
                        fp2_extension_params<bn128_base_field<Version>>::group_order;

                    template<std::size_t Version>
                    constexpr std::array<typename fp2_extension_params<bn128_base_field<Version>>::modulus_type,
                                         2> const
                        fp2_extension_params<bn128_base_field<Version>>::Frobenius_coeffs_c1;

                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_BN128_FP2_EXTENSION_PARAMS_HPP
