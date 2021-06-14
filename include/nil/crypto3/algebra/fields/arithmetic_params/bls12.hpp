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

#ifndef CRYPTO3_ALGEBRA_FIELDS_BLS12_ARITHMETIC_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_BLS12_ARITHMETIC_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>

#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                /************************* BLS12-381 ***********************************/

                template<>
                struct arithmetic_params<bls12_base_field<381>> : public params<bls12_base_field<381>> {
                private:
                    typedef params<bls12_base_field<381>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const std::size_t s = 0x01;
                    constexpr static const modulus_type t =
                        0xD0088F51CBFF34D258DD3DB21A5D66BB23BA5C279C2895FB39869507B587B120F55FFFF58A9FFFFDCFF7FFFFFFFD555_cppui380;
                    constexpr static const modulus_type t_minus_1_over_2 =
                        0x680447A8E5FF9A692C6E9ED90D2EB35D91DD2E13CE144AFD9CC34A83DAC3D8907AAFFFFAC54FFFFEE7FBFFFFFFFEAAA_cppui379;
                    constexpr static const modulus_type arithmetic_generator = 0x01;
                    constexpr static const modulus_type geometric_generator = 0x02;
                    constexpr static const modulus_type multiplicative_generator = 0x02;
                    constexpr static const modulus_type root_of_unity =
                        0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA_cppui381;
                    constexpr static const modulus_type nqr = 0x02;
                    constexpr static const modulus_type nqr_to_t =
                        0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA_cppui381;
                    constexpr static const modulus_type Rsquared =
                        0x11988FE592CAE3AA9A793E85B519952D67EB88A9939D83C08DE5476C4C95B6D50A76E6A609D104F1F4DF1F341C341746_cppui381;
                    constexpr static const modulus_type Rcubed =
                        0xAA6346091755D4D2512D4356572472834C04E5E921E17619A53352A615E29DD315F831E03A7ADF8ED48AC6BD94CA1E0_cppui380;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0xD0088F51CBFF34D258DD3DB21A5D66BB23BA5C279C2895FB39869507B587B120F55FFFF58A9FFFFDCFF7FFFFFFFD555_cppui380;
                };

                template<>
                struct arithmetic_params<fp2<bls12_base_field<381>>> : public params<bls12_base_field<381>> {
                private:
                    typedef params<bls12_base_field<381>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;
                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t s = 0x03;
                    constexpr static const extended_modulus_type t =
                        0x5486F497186BF8E97A4F1D5445E4BD3C5B921CA1CE08D68CDCB3C92693D17A0A14C59FA2DBB94DDEA62926612F1DE023AD0C3390C30B8F6525D0B50E1234092CD7F23DA7CE36E862C586706C42279FAF9DAD63AEC705D564D54000038E31C7_cppui759;
                    constexpr static const extended_modulus_type t_minus_1_over_2 =
                        0x2A437A4B8C35FC74BD278EAA22F25E9E2DC90E50E7046B466E59E49349E8BD050A62CFD16DDCA6EF53149330978EF011D68619C86185C7B292E85A87091A04966BF91ED3E71B743162C338362113CFD7CED6B1D76382EAB26AA00001C718E3_cppui758;
                    constexpr static const std::array<modulus_type, 2> nqr = {1, 1};
                    constexpr static const std::array<modulus_type, 2> nqr_to_t = {
                        0x6AF0E0437FF400B6831E36D6BD17FFE48395DABC2D3435E77F76E17009241C5EE67992F72EC05F4C81084FBEDE3CC09_cppui379,
                        0x135203E60180A68EE2E9C448D77A2CD91C3DEDD930B1CF60EF396489F61EB45E304466CF3E67FA0AF1EE7B04121BDEA2_cppui381};

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const extended_modulus_type group_order =
                        0x1521BD25C61AFE3A5E93C75511792F4F16E48728738235A3372CF249A4F45E82853167E8B6EE5377A98A49984BC77808EB430CE430C2E3D949742D43848D024B35FC8F69F38DBA18B1619C1B1089E7EBE76B58EBB1C1755935500000E38C71C_cppui761;
                };

                template<>
                struct arithmetic_params<bls12_scalar_field<381>> : public params<bls12_scalar_field<381>> {
                private:
                    typedef params<bls12_scalar_field<381>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const std::size_t s = 0x20;
                    constexpr static const modulus_type t =
                        0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF_cppui223;
                    constexpr static const modulus_type t_minus_1_over_2 =
                        0x39F6D3A994CEBEA4199CEC0404D0EC02A9DED2017FFF2DFF7FFFFFFF_cppui222;
                    constexpr static const modulus_type arithmetic_generator = 0x01;
                    constexpr static const modulus_type geometric_generator = 0x02;
                    constexpr static const modulus_type multiplicative_generator = 0x07;
                    constexpr static const modulus_type root_of_unity =
                        0x16A2A19EDFE81F20D09B681922C813B4B63683508C2280B93829971F439F0D2B_cppui253;
                    constexpr static const modulus_type nqr = 0x05;
                    constexpr static const modulus_type nqr_to_t =
                        0x212D79E5B416B6F0FD56DC8D168D6C0C4024FF270B3E0941B788F500B912F1F_cppui250;
                    constexpr static const modulus_type Rsquared =
                        0x748D9D99F59FF1105D314967254398F2B6CEDCB87925C23C999E990F3F29C6D_cppui251;
                    constexpr static const modulus_type Rcubed =
                        0x6E2A5BB9C8DB33E973D13C71C7B5F4181B3E0D188CF06990C62C1807439B73AF_cppui255;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0x39F6D3A994CEBEA4199CEC0404D0EC02A9DED2017FFF2DFF7FFFFFFF80000000_cppui254;
                };

                /************************* BLS12-377 ***********************************/

                template<>
                struct arithmetic_params<bls12_base_field<377>> : public params<bls12_base_field<377>> {
                private:
                    typedef params<bls12_base_field<377>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const std::size_t s = 0x2E;
                    constexpr static const modulus_type t =
                        0x6B8E9185F1443AB18EC1701B28524EC688B67CC03D44E3C7BCD88BEE82520005C2D7510C00000021423_cppui331;
                    constexpr static const modulus_type t_minus_1_over_2 =
                        0x35C748C2F8A21D58C760B80D94292763445B3E601EA271E3DE6C45F741290002E16BA88600000010A11_cppui330;
                    constexpr static const modulus_type arithmetic_generator = 0x01;
                    constexpr static const modulus_type geometric_generator = 0x02;
                    constexpr static const modulus_type multiplicative_generator = 0x0F;
                    constexpr static const modulus_type root_of_unity =
                        0x36A92E05198A8030F152488AEFFC9B40FBE05B4512A3D4B44D994A0DDFF8C606DF0A4306FE0BC37ECA603CC563B9A1_cppui374;
                    constexpr static const modulus_type nqr = 0x05;
                    constexpr static const modulus_type nqr_to_t =
                        0x382D3D99CDBC5D8FE9DEE6AA914B0AD14FCACA7022110EC6EAA2BC56228AC41EA03D28CC795186BA6B5EF26B00BBE8_cppui374;
                    constexpr static const modulus_type Rsquared =
                        0x6DFCCB1E914B88837E92F041790BF9BFDF7D03827DC3AC22A5F11162D6B46D0329FCAAB00431B1B786686C9400CD22_cppui375;
                    constexpr static const modulus_type Rcubed =
                        0x1065AB4C0E7DDA53F72540713590CB96A2A9516C804A20E2BE8B1180449F513E50F4148BE329585581F532F8815DE20_cppui377;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0xD71D230BE28875631D82E03650A49D8D116CF9807A89C78F79B117DD04A4000B85AEA2180000004284600000000000_cppui376;
                };

                template<>
                struct arithmetic_params<fp2<bls12_base_field<377>>> : public params<bls12_base_field<377>> {
                private:
                    typedef params<bls12_base_field<377>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;
                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t s = 0x2F;
                    constexpr static const extended_modulus_type t =
                        0x5A60FA1775FF644AD227766C24C78977170FB495DD27E3EBCE2827BB49AB813A0315F720CC19B8029CE24A0549AD88C155555176E15C063064972B0C7193AD797F7A46BE3813495B44D1E5C37B000E671A4A9E00000021423_cppui707;
                    constexpr static const extended_modulus_type t_minus_1_over_2 =
                        0x2D307D0BBAFFB2256913BB361263C4BB8B87DA4AEE93F1F5E71413DDA4D5C09D018AFB90660CDC014E712502A4D6C460AAAAA8BB70AE0318324B958638C9D6BCBFBD235F1C09A4ADA268F2E1BD8007338D254F00000010A11_cppui706;
                    constexpr static const std::array<modulus_type, 2> nqr = {0x00, 0x01};
                    constexpr static const std::array<modulus_type, 2> nqr_to_t = {
                        0x00,
                        0x1ABEF7237D62007BB9B2EDA5AFCB52F9D179F23DBD49B8D1B24CF7C1BF8066791317689172D0F4CB90CF47182B7D7B2_cppui377};

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const extended_modulus_type group_order =
                        0x16983E85DD7FD912B489DD9B0931E25DC5C3ED257749F8FAF38A09EED26AE04E80C57DC833066E00A7389281526B62305555545DB857018C1925CAC31C64EB5E5FDE91AF8E04D256D1347970DEC00399C692A780000008508C00000000000_cppui753;
                };

                template<>
                struct arithmetic_params<bls12_scalar_field<377>> : public params<bls12_scalar_field<377>> {
                private:
                    typedef params<bls12_scalar_field<377>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const std::size_t s = 0x2F;
                    constexpr static const modulus_type t =
                        0x2556CABD34594AACC1689A3CB86F6002B354EDFDA00000021423_cppui206;
                    constexpr static const modulus_type t_minus_1_over_2 =
                        0x12AB655E9A2CA55660B44D1E5C37B00159AA76FED00000010A11_cppui205;
                    constexpr static const modulus_type arithmetic_generator = 0x01;
                    constexpr static const modulus_type geometric_generator = 0x02;
                    constexpr static const modulus_type multiplicative_generator = 0x16;
                    constexpr static const modulus_type root_of_unity =
                        0x11D4B7F60CB92CC160C69477D1A8A12F9B506EE363E3F04A476EF4A4EC2A895E_cppui253;
                    constexpr static const modulus_type nqr = 0x0B;
                    constexpr static const modulus_type nqr_to_t =
                        0xF4F58D6B338DB36480B0DA08D4FF39BE5C1F1B84059D4CD726869AAA623875C_cppui252;
                    constexpr static const modulus_type Rsquared =
                        0x11FDAE7EFF1C939A7CC008FE5DC8593CC2C27B58860591F25D577BAB861857B_cppui249;
                    constexpr static const modulus_type Rcubed =
                        0x601DFA555C48DDAB1E55EF6F1C9D713624D23FFAE2716996A4295C90F65454C_cppui251;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0x955B2AF4D1652AB305A268F2E1BD800ACD53B7F680000008508C00000000000_cppui252;
                };

                /************************* BLS12-381 definitions ***********************************/

                constexpr std::size_t const arithmetic_params<bls12_base_field<381>>::s;
                constexpr std::size_t const arithmetic_params<fp2<bls12_base_field<381>>>::s;
                constexpr std::size_t const arithmetic_params<bls12_scalar_field<381>>::s;

                constexpr typename arithmetic_params<bls12_base_field<381>>::modulus_type const
                    arithmetic_params<bls12_base_field<381>>::t;
                constexpr typename arithmetic_params<fp2<bls12_base_field<381>>>::extended_modulus_type const
                    arithmetic_params<fp2<bls12_base_field<381>>>::t;
                constexpr typename arithmetic_params<bls12_scalar_field<381>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<381>>::t;

                constexpr typename arithmetic_params<bls12_base_field<381>>::modulus_type const
                    arithmetic_params<bls12_base_field<381>>::t_minus_1_over_2;
                constexpr typename arithmetic_params<fp2<bls12_base_field<381>>>::extended_modulus_type const
                    arithmetic_params<fp2<bls12_base_field<381>>>::t_minus_1_over_2;
                constexpr typename arithmetic_params<bls12_scalar_field<381>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<381>>::t_minus_1_over_2;

                constexpr typename arithmetic_params<bls12_base_field<381>>::modulus_type const
                    arithmetic_params<bls12_base_field<381>>::arithmetic_generator;
                constexpr typename arithmetic_params<bls12_scalar_field<381>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<381>>::arithmetic_generator;

                constexpr typename arithmetic_params<bls12_base_field<381>>::modulus_type const
                    arithmetic_params<bls12_base_field<381>>::geometric_generator;
                constexpr typename arithmetic_params<bls12_scalar_field<381>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<381>>::geometric_generator;

                constexpr typename arithmetic_params<bls12_base_field<381>>::modulus_type const
                    arithmetic_params<bls12_base_field<381>>::multiplicative_generator;
                constexpr typename arithmetic_params<bls12_scalar_field<381>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<381>>::multiplicative_generator;

                constexpr typename arithmetic_params<bls12_base_field<381>>::modulus_type const
                    arithmetic_params<bls12_base_field<381>>::root_of_unity;
                constexpr typename arithmetic_params<bls12_scalar_field<381>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<381>>::root_of_unity;

                constexpr typename arithmetic_params<bls12_base_field<381>>::modulus_type const
                    arithmetic_params<bls12_base_field<381>>::nqr;
                constexpr std::array<typename arithmetic_params<fp2<bls12_base_field<381>>>::modulus_type, 2> const
                    arithmetic_params<fp2<bls12_base_field<381>>>::nqr;
                constexpr typename arithmetic_params<bls12_scalar_field<381>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<381>>::nqr;

                constexpr typename arithmetic_params<bls12_base_field<381>>::modulus_type const
                    arithmetic_params<bls12_base_field<381>>::nqr_to_t;
                constexpr std::array<typename arithmetic_params<fp2<bls12_base_field<381>>>::modulus_type, 2> const
                    arithmetic_params<fp2<bls12_base_field<381>>>::nqr_to_t;
                constexpr typename arithmetic_params<bls12_scalar_field<381>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<381>>::nqr_to_t;

                constexpr typename arithmetic_params<bls12_base_field<381>>::modulus_type const
                    arithmetic_params<bls12_base_field<381>>::Rsquared;
                constexpr typename arithmetic_params<bls12_scalar_field<381>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<381>>::Rsquared;

                constexpr typename arithmetic_params<bls12_base_field<381>>::modulus_type const
                    arithmetic_params<bls12_base_field<381>>::Rcubed;
                constexpr typename arithmetic_params<bls12_scalar_field<381>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<381>>::Rcubed;

                constexpr typename arithmetic_params<bls12_base_field<381>>::modulus_type const
                    arithmetic_params<bls12_base_field<381>>::modulus;
                constexpr typename arithmetic_params<fp2<bls12_base_field<381>>>::modulus_type const
                    arithmetic_params<fp2<bls12_base_field<381>>>::modulus;
                constexpr typename arithmetic_params<bls12_scalar_field<381>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<381>>::modulus;

                constexpr typename arithmetic_params<bls12_base_field<381>>::modulus_type const
                    arithmetic_params<bls12_base_field<381>>::group_order;
                constexpr typename arithmetic_params<fp2<bls12_base_field<381>>>::extended_modulus_type const
                    arithmetic_params<fp2<bls12_base_field<381>>>::group_order;
                constexpr typename arithmetic_params<bls12_scalar_field<381>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<381>>::group_order;

                /************************* BLS12-377 definitions ***********************************/

                constexpr std::size_t const arithmetic_params<bls12_base_field<377>>::s;
                constexpr std::size_t const arithmetic_params<fp2<bls12_base_field<377>>>::s;
                constexpr std::size_t const arithmetic_params<bls12_scalar_field<377>>::s;

                constexpr typename arithmetic_params<bls12_base_field<377>>::modulus_type const
                    arithmetic_params<bls12_base_field<377>>::t;
                constexpr typename arithmetic_params<fp2<bls12_base_field<377>>>::extended_modulus_type const
                    arithmetic_params<fp2<bls12_base_field<377>>>::t;
                constexpr typename arithmetic_params<bls12_scalar_field<377>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<377>>::t;

                constexpr typename arithmetic_params<bls12_base_field<377>>::modulus_type const
                    arithmetic_params<bls12_base_field<377>>::t_minus_1_over_2;
                constexpr typename arithmetic_params<fp2<bls12_base_field<377>>>::extended_modulus_type const
                    arithmetic_params<fp2<bls12_base_field<377>>>::t_minus_1_over_2;
                constexpr typename arithmetic_params<bls12_scalar_field<377>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<377>>::t_minus_1_over_2;

                constexpr typename arithmetic_params<bls12_base_field<377>>::modulus_type const
                    arithmetic_params<bls12_base_field<377>>::arithmetic_generator;
                constexpr typename arithmetic_params<bls12_scalar_field<377>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<377>>::arithmetic_generator;

                constexpr typename arithmetic_params<bls12_base_field<377>>::modulus_type const
                    arithmetic_params<bls12_base_field<377>>::geometric_generator;
                constexpr typename arithmetic_params<bls12_scalar_field<377>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<377>>::geometric_generator;

                constexpr typename arithmetic_params<bls12_base_field<377>>::modulus_type const
                    arithmetic_params<bls12_base_field<377>>::multiplicative_generator;
                constexpr typename arithmetic_params<bls12_scalar_field<377>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<377>>::multiplicative_generator;

                constexpr typename arithmetic_params<bls12_base_field<377>>::modulus_type const
                    arithmetic_params<bls12_base_field<377>>::root_of_unity;
                constexpr typename arithmetic_params<bls12_scalar_field<377>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<377>>::root_of_unity;

                constexpr typename arithmetic_params<bls12_base_field<377>>::modulus_type const
                    arithmetic_params<bls12_base_field<377>>::nqr;
                constexpr std::array<typename arithmetic_params<fp2<bls12_base_field<377>>>::modulus_type, 2> const
                    arithmetic_params<fp2<bls12_base_field<377>>>::nqr;
                constexpr typename arithmetic_params<bls12_scalar_field<377>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<377>>::nqr;

                constexpr typename arithmetic_params<bls12_base_field<377>>::modulus_type const
                    arithmetic_params<bls12_base_field<377>>::nqr_to_t;
                constexpr std::array<typename arithmetic_params<fp2<bls12_base_field<377>>>::modulus_type, 2> const
                    arithmetic_params<fp2<bls12_base_field<377>>>::nqr_to_t;
                constexpr typename arithmetic_params<bls12_scalar_field<377>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<377>>::nqr_to_t;

                constexpr typename arithmetic_params<bls12_base_field<377>>::modulus_type const
                    arithmetic_params<bls12_base_field<377>>::Rsquared;
                constexpr typename arithmetic_params<bls12_scalar_field<377>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<377>>::Rsquared;

                constexpr typename arithmetic_params<bls12_base_field<377>>::modulus_type const
                    arithmetic_params<bls12_base_field<377>>::Rcubed;
                constexpr typename arithmetic_params<bls12_scalar_field<377>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<377>>::Rcubed;

                constexpr typename arithmetic_params<bls12_base_field<377>>::modulus_type const
                    arithmetic_params<bls12_base_field<377>>::modulus;
                constexpr typename arithmetic_params<fp2<bls12_base_field<377>>>::modulus_type const
                    arithmetic_params<fp2<bls12_base_field<377>>>::modulus;
                constexpr typename arithmetic_params<bls12_scalar_field<377>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<377>>::modulus;

                constexpr typename arithmetic_params<bls12_base_field<377>>::modulus_type const
                    arithmetic_params<bls12_base_field<377>>::group_order;
                constexpr typename arithmetic_params<fp2<bls12_base_field<377>>>::extended_modulus_type const
                    arithmetic_params<fp2<bls12_base_field<377>>>::group_order;
                constexpr typename arithmetic_params<bls12_scalar_field<377>>::modulus_type const
                    arithmetic_params<bls12_scalar_field<377>>::group_order;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_BLS12_ARITHMETIC_PARAMS_HPP
