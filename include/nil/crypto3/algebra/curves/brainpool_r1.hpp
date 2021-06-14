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

#ifndef CRYPTO3_ALGEBRA_CURVES_BRAINPOOL_R1_HPP
#define CRYPTO3_ALGEBRA_CURVES_BRAINPOOL_R1_HPP

#include <nil/crypto3/algebra/curves/detail/brainpool_r1/g1.hpp>
#include <nil/crypto3/algebra/curves/detail/brainpool_r1/g2.hpp>

#include <nil/crypto3/algebra/fields/brainpool_r1/base_field.hpp>
#include <nil/crypto3/algebra/fields/brainpool_r1/scalar_field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                template<std::size_t PBits>
                struct brainpool_r1 { };

                template<>
                struct brainpool_r1<160> {

                    constexpr static const std::size_t base_field_bits = 160;
                    typedef fields::brainpool_r1_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 160;
                    typedef fields::brainpool_r1_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    typedef typename detail::brainpool_r1_g1<160> g1_type;
                    typedef typename detail::brainpool_r1_g2<160> g2_type;

                    typedef typename fields::fp ? ? <base_field_type>::value_type gt_type;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a = 0x340E7BE2A280EB74E2BE61BADA745D97E8F7C300_cppui160;
                    constexpr static const number_type b = 0x1E589A8595423412134FAA2DBDEC95C8D8675E58_cppui160;
                    constexpr static const number_type x = 0xBED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3_cppui160;
                    constexpr static const number_type y = 0x1667CB477A1A8EC338F94741669C976316DA6321_cppui160;
                };

                template<>
                struct brainpool_r1<192> {

                    constexpr static const std::size_t base_field_bits = 192;
                    typedef fields::brainpool_r1_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 192;
                    typedef fields::brainpool_r1_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    typedef typename detail::brainpool_r1_g1<192> g1_type;
                    typedef typename detail::brainpool_r1_g2<192> g2_type;

                    typedef typename fields::fp ? ? <base_field_type>::value_type gt_type;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a = 0x6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF_cppui192;
                    constexpr static const number_type b = 0x469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9_cppui192;
                    constexpr static const number_type x = 0xC0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6_cppui192;
                    constexpr static const number_type y = 0x14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F_cppui192;
                };

                template<>
                struct brainpool_r1<224> {

                    constexpr static const std::size_t base_field_bits = 224;
                    typedef fields::brainpool_r1_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 224;
                    typedef fields::brainpool_r1_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    typedef typename detail::brainpool_r1_g1<224> g1_type;
                    typedef typename detail::brainpool_r1_g2<224> g2_type;

                    typedef typename fields::fp ? ? <base_field_type>::value_type gt_type;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a =
                        0x68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43_cppui224;
                    constexpr static const number_type b =
                        0x2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B_cppui224;
                    constexpr static const number_type x =
                        0xD9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D_cppui224;
                    constexpr static const number_type y =
                        0x58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD_cppui224;
                };

                template<>
                struct brainpool_r1<256> {

                    constexpr static const std::size_t base_field_bits = 256;
                    typedef fields::brainpool_r1_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 256;
                    typedef fields::brainpool_r1_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    typedef typename detail::brainpool_r1_g1<256> g1_type;
                    typedef typename detail::brainpool_r1_g2<256> g2_type;

                    typedef typename fields::fp ? ? <base_field_type>::value_type gt_type;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a =
                        0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9_cppui256;
                    constexpr static const number_type b =
                        0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6_cppui256;
                    constexpr static const number_type x =
                        0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262_cppui256;
                    constexpr static const number_type y =
                        0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997_cppui256;
                };

                template<>
                struct brainpool_r1<320> {
                    constexpr static const std::size_t base_field_bits = 320;
                    typedef fields::brainpool_r1_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 320;
                    typedef fields::brainpool_r1_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    typedef typename detail::brainpool_r1_g1<320> g1_type;
                    typedef typename detail::brainpool_r1_g2<320> g2_type;

                    typedef typename fields::fp ? ? <base_field_type>::value_type gt_type;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a =
                        0x3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4_cppui320;
                    constexpr static const number_type b =
                        0x520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6_cppui320;
                    constexpr static const number_type x =
                        0x43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611_cppui320;
                    constexpr static const number_type y =
                        0x14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1_cppui320;
                };

                template<>
                struct brainpool_r1<384> {
                    constexpr static const std::size_t base_field_bits = 384;
                    typedef fields::brainpool_r1_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 384;
                    typedef fields::brainpool_r1_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    typedef typename detail::brainpool_r1_g1<384> g1_type;
                    typedef typename detail::brainpool_r1_g2<384> g2_type;

                    typedef typename fields::fp ? ? <base_field_type>::value_type gt_type;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a =
                        0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826_cppui384;
                    constexpr static const number_type b =
                        0x4A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11_cppui384;
                    constexpr static const number_type x =
                        0x1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E_cppui384;
                    constexpr static const number_type y =
                        0x8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315_cppui384;
                };

                template<>
                struct brainpool_r1<512> {
                    constexpr static const std::size_t base_field_bits = 512;
                    typedef fields::brainpool_r1_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 512;
                    typedef fields::brainpool_r1_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    typedef typename detail::brainpool_r1_g1<512> g1_type;
                    typedef typename detail::brainpool_r1_g2<512> g2_type;

                    typedef typename fields::fp ? ? <base_field_type>::value_type gt_type;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a =
                        0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA_cppui512;
                    constexpr static const number_type b =
                        0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723_cppui512;
                    constexpr static const number_type x =
                        0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822_cppui512;
                    constexpr static const number_type y =
                        0x7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892_cppui512;
                };

                typedef brainpool_r1<160> brainpool160r1;
                typedef brainpool_r1<192> brainpool192r1;
                typedef brainpool_r1<224> brainpool224r1;
                typedef brainpool_r1<256> brainpool256r1;
                typedef brainpool_r1<320> brainpool320r1;
                typedef brainpool_r1<384> brainpool384r1;
                typedef brainpool_r1<512> brainpool512r1;

            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_BRAINPOOL_R1_HPP
