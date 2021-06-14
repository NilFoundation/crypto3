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

#ifndef CRYPTO3_ALGEBRA_FIELDS_BN128_FP6_3OVER2_EXTENSION_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_BN128_FP6_3OVER2_EXTENSION_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/bn128/base_field.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {

                    template<typename BaseField>
                    struct fp6_3over2_extension_params;

                    /************************* BN128 ***********************************/

                    template<std::size_t Version>
                    class fp6_3over2_extension_params<fields::bn128<Version>>
                        : public params<fields::bn128<Version>> {

                        typedef fields::bn128<Version> base_field_type;
                        typedef params<base_field_type> policy_type;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        typedef fields::fp2<base_field_type> non_residue_field_type;
                        typedef typename non_residue_field_type::value_type non_residue_type;
                        typedef fields::fp2<base_field_type> underlying_field_type;
                        typedef typename underlying_field_type::value_type underlying_type;

                        /*constexpr static const std::array<non_residue_type, 6> Frobenius_coeffs_c1 =
                        {non_residue_type(0x00, 0x00), non_residue_type(0x00, 0x00), non_residue_type(0x00, 0x00),
                            non_residue_type(0x00, 0x00),
                            non_residue_type(0x00, 0x00),
                            non_residue_type(0x00, 0x00)};

                        constexpr static const std::array<non_residue_type, 6> Frobenius_coeffs_c2 =
                        {non_residue_type(0x00, 0x00), non_residue_type(0x00, 0x00), non_residue_type(0x00, 0x00),
                            non_residue_type(0x00, 0x00),
                            non_residue_type(0x00, 0x00),
                            non_residue_type(0x00, 0x00)};*/

                        constexpr static const std::array<modulus_type, 6 * 2> Frobenius_coeffs_c1 = {
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

                        constexpr static const std::array<modulus_type, 6 * 2> Frobenius_coeffs_c2 = {
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

                        constexpr static const non_residue_type non_residue = non_residue_type(0x09, 0x01);
                    };

                    template<std::size_t Version>
                    constexpr typename fp6_3over2_extension_params<bn128_base_field<Version>>::non_residue_type const
                        fp6_3over2_extension_params<bn128_base_field<Version>>::non_residue;

                    template<std::size_t Version>
                    constexpr std::array<
                        typename fp6_3over2_extension_params<bn128_base_field<Version>>::modulus_type, 6 * 2> const
                        fp6_3over2_extension_params<bn128_base_field<Version>>::Frobenius_coeffs_c1;
                    template<std::size_t Version>
                    constexpr std::array<
                        typename fp6_3over2_extension_params<bn128_base_field<Version>>::modulus_type, 6 * 2> const
                        fp6_3over2_extension_params<bn128_base_field<Version>>::Frobenius_coeffs_c2;

                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_BN128_FP6_3OVER2_EXTENSION_PARAMS_HPP
