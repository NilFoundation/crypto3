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

#ifndef CRYPTO3_ALGEBRA_CURVES_SECP_HPP
#define CRYPTO3_ALGEBRA_CURVES_SECP_HPP

#include <nil/crypto3/algebra/fields/secp/base_field.hpp>
#include <nil/crypto3/algebra/fields/secp/scalar_field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                template<std::size_t PBits>
                struct secp_k1 { };

                template<std::size_t PBits>
                struct secp_r1 { };

                template<std::size_t PBits>
                struct secp_r2 { };

                template<>
                struct secp_k1<160> {
                    constexpr static const std::size_t base_field_bits = 160;
                    typedef fields::secp_k1_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 160;
                    typedef fields::secp_k1_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a = 0x0_cppui160;
                    constexpr static const number_type b = 0x7_cppui160;
                    constexpr static const number_type x = 0x3B4C382CE37AA192A4019E763036F4F5DD4D7EBB_cppui160;
                    constexpr static const number_type y = 0x938CF935318FDCED6BC28286531733C3F03C4FEE_cppui160;
                };

                template<>
                struct secp_r1<160> {
                    constexpr static const std::size_t base_field_bits = 160;
                    typedef fields::secp_r1_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 160;
                    typedef fields::secp_r1_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC_cppui160;
                    constexpr static const number_type b = 0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45_cppui160;
                    constexpr static const number_type x = 0x4A96B5688EF573284664698968C38BB913CBFC82_cppui160;
                    constexpr static const number_type y = 0x23A628553168947D59DCC912042351377AC5FB32_cppui160;
                };

                template<>
                struct secp_r2<160> {
                    constexpr static const std::size_t base_field_bits = 160;
                    typedef fields::secp_r2_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 160;
                    typedef fields::secp_r2_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70_cppui160;
                    constexpr static const number_type b = 0xB4E134D3FB59EB8BAB57274904664D5AF50388BA_cppui160;
                    constexpr static const number_type x = 0x52DCB034293A117E1F4FF11B30F7199D3144CE6D_cppui160;
                    constexpr static const number_type y = 0xFEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E_cppui160;
                };

                template<>
                struct secp_k1<192> {
                    constexpr static const std::size_t base_field_bits = 192;
                    typedef fields::secp_k1_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 192;
                    typedef fields::secp_k1_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a = 0x0_cppui192;
                    constexpr static const number_type b = 0x3_cppui192;
                    constexpr static const number_type x = 0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D_cppui192;
                    constexpr static const number_type y = 0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D_cppui192;
                };

                template<>
                struct secp_r1<192> {
                    constexpr static const std::size_t base_field_bits = 192;
                    typedef fields::secp_r1_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 192;
                    typedef fields::secp_r1_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a = 0x0_cppui192;
                    constexpr static const number_type b = 0x3_cppui192;
                    constexpr static const number_type x = 0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D_cppui192;
                    constexpr static const number_type y = 0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D_cppui192;
                };

                template<>
                struct secp_k1<224> {
                    constexpr static const std::size_t base_field_bits = 192;
                    typedef fields::secp_k1_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 192;
                    typedef fields::secp_k1_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a = 0x0_cppui224;
                    constexpr static const number_type b = 0x5_cppui224;
                    constexpr static const number_type x =
                        0xA1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C_cppui224;
                    constexpr static const number_type y =
                        0x7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5_cppui224;
                };

                template<>
                struct secp_r1<224> {
                    constexpr static const std::size_t base_field_bits = 192;
                    typedef fields::secp_r1_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 192;
                    typedef fields::secp_r1_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a =
                        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE_cppui224;
                    constexpr static const number_type b =
                        0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4_cppui224;
                    constexpr static const number_type x =
                        0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21_cppui224;
                    constexpr static const number_type y =
                        0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34_cppui224;
                };

                template<>
                struct secp_k1<256> {
                    constexpr static const std::size_t base_field_bits = 256;
                    typedef fields::secp_k1_fq<base_field_bits> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 256;
                    typedef fields::secp_k1_fr<scalar_field_bits> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a = 0x0_cppui256;
                    constexpr static const number_type b = 0x7_cppui256;
                    constexpr static const number_type x =
                        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798_cppui256;
                    constexpr static const number_type y =
                        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8_cppui256;
                };

                typedef secp_k1<160> secp160k1;
                typedef secp_r1<160> secp160r1;
                typedef secp_r2<160> secp160r2;
                typedef secp_k1<192> secp192k1;
                typedef secp_r1<192> secp192r1;
                typedef secp_k1<224> secp224k1;
                typedef secp_r1<224> secp224r1;
                typedef secp_k1<256> secp256k1;
            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_SECP_HPP
