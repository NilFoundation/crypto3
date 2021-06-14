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

#ifndef CRYPTO3_ALGEBRA_PAIRING_BLS128_BASIC_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_BLS128_BASIC_POLICY_HPP

#include <nil/crypto3/algebra/curves/detail/bls12/g1.hpp>
#include <nil/crypto3/algebra/curves/detail/bls12/g2.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<std::size_t Version = 381>
                    class bls12_basic_policy;

                    template<>
                    class bls12_basic_policy<381> {
                        using policy_type = curves::detail::bls12_basic_policy<381>;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::extended_number_type extended_number_type;

                        using fp_type = typename policy_type::scalar_field_type;
                        using fq_type = typename policy_type::g1_field_type;
                        using fqe_type = typename policy_type::g2_field_type;
                        using fqk_type = typename policy_type::gt_field_type;

                        using g1_type = curves::detail::bls12_g1<381>;
                        using g2_type = curves::detail::bls12_g2<381>;
                        using gt_type = typename policy_type::gt_field_type;

                        constexpr static const std::size_t base_field_bits = policy_type::base_field_type::modulus_bits;
                        constexpr static const number_type base_field_modulus = policy_type::base_field_type::modulus;
                        constexpr static const std::size_t scalar_field_bits = policy_type::scalar_field_type::modulus_bits;
                        constexpr static const number_type scalar_field_modulus = policy_type::scalar_field_type::modulus;

                        constexpr static const std::size_t number_type_max_bits = base_field_bits;

                        constexpr static const number_type coef_b = policy_type::b;

                        constexpr static const number_type ate_loop_count = 0xD201000000010000_cppui64;
                        constexpr static const bool ate_is_loop_count_neg = true;
                        // constexpr static const extended_number_type final_exponent = extended_number_type(
                        //    0x2EE1DB5DCC825B7E1BDA9C0496A1C0A89EE0193D4977B3F7D4507D07363BAA13F8D14A917848517BADC3A43D1073776AB353F2C30698E8CC7DEADA9C0AADFF5E9CFEE9A074E43B9A660835CC872EE83FF3A0F0F1C0AD0D6106FEAF4E347AA68AD49466FA927E7BB9375331807A0DCE2630D9AA4B113F414386B0E8819328148978E2B0DD39099B86E1AB656D2670D93E4D7ACDD350DA5359BC73AB61A0C5BF24C374693C49F570BCD2B01F3077FFB10BF24DDE41064837F27611212596BC293C8D4C01F25118790F4684D0B9C40A68EB74BB22A40EE7169CDC1041296532FEF459F12438DFC8E2886EF965E61A474C5C85B0129127A1B5AD0463434724538411D1676A53B5A62EB34C05739334F46C02C3F0BD0C55D3109CD15948D0A1FAD20044CE6AD4C6BEC3EC03EF19592004CEDD556952C6D8823B19DADD7C2498345C6E5308F1C511291097DB60B1749BF9B71A9F9E0100418A3EF0BC627751BBD81367066BCA6A4C1B6DCFC5CCEB73FC56947A403577DFA9E13C24EA820B09C1D9F7C31759C3635DE3F7A3639991708E88ADCE88177456C49637FD7961BE1A4C7E79FB02FAA732E2F3EC2BEA83D196283313492CAA9D4AFF1C910E9622D2A73F62537F2701AAEF6539314043F7BBCE5B78C7869AEB2181A67E49EEED2161DAF3F881BD88592D767F67C4717489119226C2F011D4CAB803E9D71650A6F80698E2F8491D12191A04406FBC8FBD5F48925F98630E68BFB24C0BCB9B55DF57510_cppui4314);

                        constexpr static const number_type final_exponent_z = 0xD201000000010000_cppui64;
                        constexpr static const bool final_exponent_is_z_neg = true;
                    };

                    template<>
                    class bls12_basic_policy<377> {
                        using policy_type = curves::detail::bls12_basic_policy<377>;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::extended_number_type extended_number_type;

                        using g1_type = curves::detail::bls12_g1<377>;
                        using g2_type = curves::detail::bls12_g2<377>;
                        using gt_type = typename policy_type::gt_field_type;

                        typedef typename policy_type::scalar_field_type Fp_field;
                        typedef typename policy_type::g1_field_type Fq_field;
                        typedef typename policy_type::g2_field_type Fqe_field;
                        typedef typename policy_type::gt_field_type Fqk_field;

                        typedef typename Fq_field::value_type Fq;
                        typedef typename Fqe_field::value_type Fq2;

                        constexpr static const std::size_t base_field_bits = policy_type::base_field_type::modulus_bits;
                        constexpr static const number_type base_field_modulus = policy_type::base_field_type::modulus;
                        constexpr static const std::size_t scalar_field_bits = policy_type::scalar_field_type::modulus_bits;
                        constexpr static const number_type scalar_field_modulus = policy_type::scalar_field_type::modulus;

                        constexpr static const std::size_t number_type_max_bits = base_field_bits;

                        constexpr static const number_type ate_loop_count = number_type(0x8508C00000000001_cppui64);
                        constexpr static const bool ate_is_loop_count_neg = false;
                        // constexpr static const extended_number_type final_exponent = extended_number_type(
                        //    0x1B2FF68C1ABDC48AB4F04ED12CC8F9B2F161B41C7EB8865B9AD3C9BB0571DD94C6BDE66548DC13624D9D741024CEB315F46A89CC2482605EB6AFC6D8977E5E2CCBEC348DD362D59EC2B5BC62A1B467AE44572215548ABC98BB4193886ED89CCEAEDD0221ABA84FB33E5584AC29619A87A00C315178155496857C995EAB4A8A9AF95F4015DB27955AE408D6927D0AB37D52F3917C4DDEC88F8159F7BCBA7EB65F1AAE4EEB4E70CB20227159C08A7FDFEA9B62BB308918EAC3202569DD1BCDD86B431E3646356FC3FB79F89B30775E006993ADB629586B6C874B7688F86F11EF7AD94A40EB020DA3C532B317232FA56DC564637B331A8E8832EAB84269F00B506602C8594B7F7DA5A5D8D851FFF6AB1D38A354FC8E0B8958E2A9E5CE2D7E50EC36D761D9505FE5E1F317257E2DF2952FCD4C93B85278C20488B4CCAEE94DB3FEC1CE8283473E4B493843FA73ABE99AF8BAFCE29170B2B863B9513B5A47312991F60C5A4F6872B5D574212BF00D797C0BEA3C0F7DFD748E63679FDA9B1C50F2DF74DE38F38E004AE0DF997A10DB31D209CACBF58BA0678BFE7CD0985BC43258D72D8D5106C21635AE1E527EB01FCA3032D50D97756EC9EE756EABA7F21652A808A4E2539E838EF7EC4B178B29E3B976C46BD0ECDD32C1FB75E6E0AEF2D8B5661F595A98023F3520381ABA8DA6CCE785DBB0A0BBA025478D75EE749619CDB7C42A21098ECE86A00C6C2046C1E00000063C69000000000000_cppui4269);

                        constexpr static const number_type final_exponent_z = number_type(0x8508C00000000001_cppui64);
                        constexpr static const bool final_exponent_is_z_neg = false;
                    };

                    constexpr
                        typename bls12_basic_policy<381>::number_type const bls12_basic_policy<381>::ate_loop_count;
                    constexpr
                        typename bls12_basic_policy<377>::number_type const bls12_basic_policy<377>::ate_loop_count;

                    constexpr
                        typename bls12_basic_policy<381>::number_type const bls12_basic_policy<381>::final_exponent_z;
                    constexpr
                        typename bls12_basic_policy<377>::number_type const bls12_basic_policy<377>::final_exponent_z;

                    constexpr bool const bls12_basic_policy<381>::final_exponent_is_z_neg;
                    constexpr bool const bls12_basic_policy<377>::final_exponent_is_z_neg;

                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_PAIRING_BLS128_BASIC_POLICY_HPP
