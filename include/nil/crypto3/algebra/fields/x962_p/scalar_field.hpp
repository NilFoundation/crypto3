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

#ifndef CRYPTO3_ALGEBRA_FIELDS_X962_P_SCALAR_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_X962_P_SCALAR_FIELD_HPP

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
                struct x962_p_v1_scalar_field : public field<Version> { };

                template<std::size_t Version>
                struct x962_p_v2_scalar_field : public field<Version> { };

                template<std::size_t Version>
                struct x962_p_v3_scalar_field : public field<Version> { };

                template<>
                struct x962_p_v2_scalar_field<192> : public field<192> {
                    typedef field<192> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    typedef typename policy_type::number_type number_type;

                    constexpr static const modulus_type modulus =
                        0xFFFFFFFFFFFFFFFFFFFFFFFE5FB1A724DC80418648D8DD31_cppui192;

                    typedef typename detail::element_fp<params<x962_p_v2_scalar_field<192>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct x962_p_v3_scalar_field<192> : public field<192> {
                    typedef field<192> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0xFFFFFFFFFFFFFFFFFFFFFFFF7A62D031C83F4294F640EC13_cppui192;

                    typedef typename detail::element_fp<params<x962_p_v3_scalar_field<192>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct x962_p_v1_scalar_field<239> : public field<239> {
                    typedef field<239> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF9E5E9A9F5D9071FBD1522688909D0B_cppui239;

                    typedef typename detail::element_fp<params<x962_p_v1_scalar_field<239>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct x962_p_v2_scalar_field<239> : public field<239> {
                    typedef field<239> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0x7FFFFFFFFFFFFFFFFFFFFFFF800000CFA7E8594377D414C03821BC582063_cppui239;

                    typedef typename detail::element_fp<params<x962_p_v2_scalar_field<239>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct x962_p_v3_scalar_field<239> : public field<239> {
                    typedef field<239> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF975DEB41B3A6057C3C432146526551_cppui239;

                    typedef typename detail::element_fp<params<x962_p_v3_scalar_field<239>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                constexpr typename x962_p_v2_scalar_field<192>::modulus_type const x962_p_v2_scalar_field<192>::modulus;
                constexpr typename x962_p_v3_scalar_field<192>::modulus_type const x962_p_v3_scalar_field<192>::modulus;
                constexpr typename x962_p_v1_scalar_field<239>::modulus_type const x962_p_v1_scalar_field<239>::modulus;
                constexpr typename x962_p_v2_scalar_field<239>::modulus_type const x962_p_v2_scalar_field<239>::modulus;
                constexpr typename x962_p_v3_scalar_field<239>::modulus_type const x962_p_v3_scalar_field<239>::modulus;

                template<std::size_t Version = 192>
                using x962_p_v2_fr = x962_p_v2_scalar_field_field<Version>;
                template<std::size_t Version = 192>
                using x962_p_v3_fr = x962_p_v3_scalar_field_field<Version>;
                template<std::size_t Version = 239>
                using x962_p_v1_fr = x962_p_v1_scalar_field_field<Version>;
                template<std::size_t Version = 239>
                using x962_p_v2_fr = x962_p_v2_scalar_field_field<Version>;
                template<std::size_t Version = 239>
                using x962_p_v3_fr = x962_p_v3_scalar_field_field<Version>;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_X962_P_SCALAR_FIELD_HPP
