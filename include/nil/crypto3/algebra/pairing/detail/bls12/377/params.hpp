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

#ifndef CRYPTO3_ALGEBRA_PAIRING_BLS12_377_BASIC_PARAMS_HPP
#define CRYPTO3_ALGEBRA_PAIRING_BLS12_377_BASIC_PARAMS_HPP

#include <nil/crypto3/algebra/curves/detail/bls12/g1.hpp>
#include <nil/crypto3/algebra/curves/detail/bls12/g2.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<typename CurveType>
                    class pairing_params;

                    template<>
                    class pairing_params<curves::bls12<377>> {
                        using curve_type = curves::bls12<377>;

                    public:
                        using integral_type = typename curve_type::base_field_type::integral_type;
                        using extended_integral_type = typename curve_type::base_field_type::extended_integral_type;

                        constexpr static const std::size_t integral_type_max_bits =
                            curve_type::base_field_type::modulus_bits;

                        constexpr static const std::size_t integral_type_max_bits = base_field_bits;

                        constexpr static const integral_type ate_loop_count = integral_type(0x8508C00000000001_cppui64);
                        constexpr static const bool ate_is_loop_count_neg = false;
                        // constexpr static const extended_integral_type final_exponent = extended_integral_type(
                        //    0x1B2FF68C1ABDC48AB4F04ED12CC8F9B2F161B41C7EB8865B9AD3C9BB0571DD94C6BDE66548DC13624D9D741024CEB315F46A89CC2482605EB6AFC6D8977E5E2CCBEC348DD362D59EC2B5BC62A1B467AE44572215548ABC98BB4193886ED89CCEAEDD0221ABA84FB33E5584AC29619A87A00C315178155496857C995EAB4A8A9AF95F4015DB27955AE408D6927D0AB37D52F3917C4DDEC88F8159F7BCBA7EB65F1AAE4EEB4E70CB20227159C08A7FDFEA9B62BB308918EAC3202569DD1BCDD86B431E3646356FC3FB79F89B30775E006993ADB629586B6C874B7688F86F11EF7AD94A40EB020DA3C532B317232FA56DC564637B331A8E8832EAB84269F00B506602C8594B7F7DA5A5D8D851FFF6AB1D38A354FC8E0B8958E2A9E5CE2D7E50EC36D761D9505FE5E1F317257E2DF2952FCD4C93B85278C20488B4CCAEE94DB3FEC1CE8283473E4B493843FA73ABE99AF8BAFCE29170B2B863B9513B5A47312991F60C5A4F6872B5D574212BF00D797C0BEA3C0F7DFD748E63679FDA9B1C50F2DF74DE38F38E004AE0DF997A10DB31D209CACBF58BA0678BFE7CD0985BC43258D72D8D5106C21635AE1E527EB01FCA3032D50D97756EC9EE756EABA7F21652A808A4E2539E838EF7EC4B178B29E3B976C46BD0ECDD32C1FB75E6E0AEF2D8B5661F595A98023F3520381ABA8DA6CCE785DBB0A0BBA025478D75EE749619CDB7C42A21098ECE86A00C6C2046C1E00000063C69000000000000_cppui4269);

                        constexpr static const integral_type final_exponent_z =
                            integral_type(0x8508C00000000001_cppui64);
                        constexpr static const bool final_exponent_is_z_neg = false;

                        using g2_field_type_value = typename curve_type::g2_type::field_type::value_type;

                        constexpr static const g2_field_type_value twist = g2_type::params_type::twist;
                    };

                    constexpr typename pairing_params<curves::bls12<377>>::integral_type const
                        pairing_params<curves::bls12<377>>::ate_loop_count;

                    constexpr typename pairing_params<curves::bls12<377>>::integral_type const
                        pairing_params<curves::bls12<377>>::final_exponent_z;

                    constexpr bool const pairing_params<curves::bls12<377>>::final_exponent_is_z_neg;

                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_PAIRING_BLS12_377_BASIC_PARAMS_HPP
