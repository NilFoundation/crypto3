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

#ifndef CRYPTO3_ALGEBRA_CURVES_X962_P_HPP
#define CRYPTO3_ALGEBRA_CURVES_X962_P_HPP

#include <nil/crypto3/algebra/curves/detail/x962_p/g1.hpp>
#include <nil/crypto3/algebra/curves/detail/x962_p/g2.hpp>

#include <nil/crypto3/algebra/fields/x962_p/base_field.hpp>
#include <nil/crypto3/algebra/fields/x962_p/scalar_field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                template<std::size_t PBits>
                struct x962_p_v1 { };

                template<std::size_t PBits>
                struct x962_p_v2 { };

                template<std::size_t PBits>
                struct x962_p_v3 { };

                template<>
                struct x962_p_v2<192> {
                    constexpr static const std::size_t base_field_bits = 192;
                    typedef fields::x962_p_v2_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 192;
                    typedef fields::x962_p_v2_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC_cppui192;
                    constexpr static const number_type b = 0xCC22D6DFB95C6B25E49C0D6364A4E5980C393AA21668D953_cppui192;
                    constexpr static const number_type x = 0xEEA2BAE7E1497842F2DE7769CFE9C989C072AD696F48034A_cppui192;
                    constexpr static const number_type y = 0x6574D11D69B6EC7A672BB82A083DF2F2B0847DE970B2DE15_cppui192;
                };

                template<>
                struct x962_p_v3<192> {
                    constexpr static const std::size_t base_field_bits = 192;
                    typedef fields::x962_p_v2_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 192;
                    typedef fields::x962_p_v2_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC_cppui192;
                    constexpr static const number_type b = 0x22123DC2395A05CAA7423DAECCC94760A7D462256BD56916_cppui192;
                    constexpr static const number_type x = 0x7D29778100C65A1DA1783716588DCE2B8B4AEE8E228F1896_cppui192;
                    constexpr static const number_type y = 0x38A90F22637337334B49DCB66A6DC8F9978ACA7648A943B0_cppui192;
                };

                template<>
                struct x962_p_v1<239> {
                    constexpr static const std::size_t base_field_bits = 239;
                    typedef fields::x962_p_v1_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 239;
                    typedef fields::x962_p_v1_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a =
                        0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC_cppui239;
                    constexpr static const number_type b =
                        0x6B016C3BDCF18941D0D654921475CA71A9DB2FB27D1D37796185C2942C0A_cppui239;
                    constexpr static const number_type x =
                        0xFFA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF_cppui239;
                    constexpr static const number_type y =
                        0x7DEBE8E4E90A5DAE6E4054CA530BA04654B36818CE226B39FCCB7B02F1AE_cppui239;
                };

                template<>
                struct x962_p_v2<239> {
                    constexpr static const std::size_t base_field_bits = 239;
                    typedef fields::x962_p_v2_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 239;
                    typedef fields::x962_p_v2_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a =
                        0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC_cppui239;
                    constexpr static const number_type b =
                        0x617FAB6832576CBBFED50D99F0249C3FEE58B94BA0038C7AE84C8C832F2C_cppui239;
                    constexpr static const number_type x =
                        0x38AF09D98727705120C921BB5E9E26296A3CDCF2F35757A0EAFD87B830E7_cppui239;
                    constexpr static const number_type y =
                        0x5B0125E4DBEA0EC7206DA0FC01D9B081329FB555DE6EF460237DFF8BE4BA_cppui239;
                };

                template<>
                struct x962_p_v3<239> {
                    constexpr static const std::size_t base_field_bits = 239;
                    typedef fields::x962_p_v3_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 239;
                    typedef fields::x962_p_v3_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a =
                        0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC_cppui239;
                    constexpr static const number_type b =
                        0x255705FA2A306654B1F4CB03D6A750A30C250102D4988717D9BA15AB6D3E_cppui239;
                    constexpr static const number_type x =
                        0x6768AE8E18BB92CFCF005C949AA2C6D94853D0E660BBF854B1C9505FE95A_cppui239;
                    constexpr static const number_type y =
                        0x1607E6898F390C06BC1D552BAD226F3B6FCFE48B6E818499AF18E3ED6CF3_cppui239;
                };

                typedef x962_p_v2<192> x962_p192v2;
                typedef x962_p_v3<192> x962_p192v3;
                typedef x962_p_v1<239> x962_p239v1;
                typedef x962_p_v2<239> x962_p239v2;
                typedef x962_p_v3<239> x962_p239v3;
            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_X962_P_HPP
