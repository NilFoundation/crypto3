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

#ifndef CRYPTO3_ALGEBRA_FIELDS_SECP_SCALAR_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_SECP_SCALAR_FIELD_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                /*!
                 * @brief IETF IPsec groups
                 * @tparam Version
                 */
                template<std::size_t Version>
                struct secp_k1_scalar_field : public field<Version> { };

                template<std::size_t Version>
                struct secp_r1_scalar_field : public field<Version> { };

                template<std::size_t Version>
                struct secp_r2_scalar_field : public field<Version> { };

                template<>
                struct secp_k1_scalar_field<160> : public field<160> {
                    typedef field<160> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    typedef typename policy_type::number_type number_type;

                    constexpr static const modulus_type modulus = 0x100000000000000000001B8FA16DFAB9ACA16B6B3_cppui160;

                    typedef typename detail::element_fp<params<secp_k1_scalar_field<160>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_r1_scalar_field<160> : public field<160> {
                    typedef field<160> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus = 0x100000000000000000001F4C8F927AED3CA752257_cppui160;

                    typedef typename detail::element_fp<params<secp_r1_scalar_field<160>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_r2_scalar_field<160> : public field<160> {
                    typedef field<160> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus = 0x100000000000000000000351EE786A818F3A1A16B_cppui160;

                    typedef typename detail::element_fp<params<secp_r2_scalar_field<160>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_k1_scalar_field<192> : public field<192> {
                    typedef field<192> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D_cppui192;

                    typedef typename detail::element_fp<params<secp_k1_scalar_field<192>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_r1_scalar_field<192> : public field<192> {
                    typedef field<192> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D_cppui192;

                    typedef typename detail::element_fp<params<secp_r1_scalar_field<192>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_k1_scalar_field<224> : public field<224> {
                    typedef field<224> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0x10000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7_cppui224;

                    typedef typename detail::element_fp<params<secp_k1_scalar_field<224>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_r1_scalar_field<224> : public field<224> {
                    typedef field<224> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D_cppui224;

                    typedef typename detail::element_fp<params<secp_r1_scalar_field<224>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_k1_scalar_field<256> : public field<256> {
                    typedef field<256> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_cppui256;

                    typedef typename detail::element_fp<params<secp_k1_scalar_field<256>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                constexpr typename secp_k1_scalar_field<160>::modulus_type const secp_k1_scalar_field<160>::modulus;
                constexpr typename secp_r1_scalar_field<160>::modulus_type const secp_r1_scalar_field<160>::modulus;
                constexpr typename secp_r2_scalar_field<160>::modulus_type const secp_r2_scalar_field<160>::modulus;
                constexpr typename secp_k1_scalar_field<192>::modulus_type const secp_k1_scalar_field<192>::modulus;
                constexpr typename secp_r1_scalar_field<192>::modulus_type const secp_r1_scalar_field<192>::modulus;
                constexpr typename secp_k1_scalar_field<224>::modulus_type const secp_k1_scalar_field<224>::modulus;
                constexpr typename secp_r1_scalar_field<224>::modulus_type const secp_r1_scalar_field<224>::modulus;
                constexpr typename secp_k1_scalar_field<256>::modulus_type const secp_k1_scalar_field<256>::modulus;

                template<std::size_t Version = 160>
                using secp_k1_fr = secp_k1_scalar_field<Version>;
                template<std::size_t Version = 160>
                using secp_r1_fr = secp_r1_scalar_field<Version>;
                template<std::size_t Version = 160>
                using secp_r2_fr = secp_r2_scalar_field<Version>;
                template<std::size_t Version = 192>
                using secp_k1_fr = secp_k1_scalar_field<Version>;
                template<std::size_t Version = 192>
                using secp_r1_fr = secp_r1_scalar_field<Version>;
                template<std::size_t Version = 224>
                using secp_k1_fr = secp_k1_scalar_field<Version>;
                template<std::size_t Version = 224>
                using secp_r1_fr = secp_r1_scalar_field<Version>;
                template<std::size_t Version = 256>
                using secp_k1_fr = secp_k1_scalar_field<Version>;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_SECP_SCALAR_FIELD_HPP
