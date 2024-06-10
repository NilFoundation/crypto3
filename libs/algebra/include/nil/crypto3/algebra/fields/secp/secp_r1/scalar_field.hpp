//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_FIELDS_SECP_R1_SCALAR_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_SECP_R1_SCALAR_FIELD_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/field.hpp>



namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                /*!
                 * @brief
                 * @tparam Version
                 */
                template<std::size_t Version>
                struct secp_r1_scalar_field;

                // We need to derive from field<161> here, since the modulus is actually 161 bits long.
                template<>
                struct secp_r1_scalar_field<160> : public field<161> {
                    typedef field<161> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::integral_type integral_type;

                    typedef typename policy_type::extended_integral_type extended_integral_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;

                    constexpr static const integral_type modulus =
                        0x0100000000000000000001f4c8f927aed3ca752257_cppui_modular161;

                    constexpr static const integral_type group_order_minus_one_half = (modulus - 1) / 2;

                    typedef typename policy_type::modular_backend modular_backend;
                    constexpr static const modular_params_type modulus_params = modulus.backend();
                    typedef boost::multiprecision::number<
                        boost::multiprecision::backends::modular_adaptor<
                            modular_backend,
                            boost::multiprecision::backends::modular_params_ct<modular_backend, modulus_params>>>
                        modular_type;

                    typedef typename detail::element_fp<params<secp_r1_scalar_field<160>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_r1_scalar_field<192> : public field<192> {
                    typedef field<192> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::integral_type integral_type;

                    typedef typename policy_type::extended_integral_type extended_integral_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;

                    constexpr static const integral_type modulus =
                        0xffffffffffffffffffffffff99def836146bc9b1b4d22831_cppui_modular192;

                    constexpr static const integral_type group_order_minus_one_half = (modulus - 1) / 2;

                    typedef typename policy_type::modular_backend modular_backend;
                    constexpr static const modular_params_type modulus_params = modulus.backend();
                    typedef boost::multiprecision::number<
                        boost::multiprecision::backends::modular_adaptor<
                            modular_backend,
                            boost::multiprecision::backends::modular_params_ct<modular_backend, modulus_params>>>
                        modular_type;

                    typedef typename detail::element_fp<params<secp_r1_scalar_field<192>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_r1_scalar_field<224> : public field<224> {
                    typedef field<224> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::integral_type integral_type;

                    typedef typename policy_type::extended_integral_type extended_integral_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;

                    constexpr static const integral_type modulus =
                        0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d_cppui_modular224;

                    constexpr static const integral_type group_order_minus_one_half = (modulus - 1) / 2;

                    typedef typename policy_type::modular_backend modular_backend;
                    constexpr static const modular_params_type modulus_params = modulus.backend();
                    typedef boost::multiprecision::number<
                        boost::multiprecision::backends::modular_adaptor<
                            modular_backend,
                            boost::multiprecision::backends::modular_params_ct<modular_backend, modulus_params>>>
                        modular_type;

                    typedef typename detail::element_fp<params<secp_r1_scalar_field<224>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_r1_scalar_field<256> : public field<256> {
                    typedef field<256> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::integral_type integral_type;

                    typedef typename policy_type::extended_integral_type extended_integral_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;

                    constexpr static const integral_type modulus =
                        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551_cppui_modular256;

                    constexpr static const integral_type group_order_minus_one_half = (modulus - 1) / 2;

                    typedef typename policy_type::modular_backend modular_backend;
                    constexpr static const modular_params_type modulus_params = modulus.backend();
                    typedef boost::multiprecision::number<
                        boost::multiprecision::backends::modular_adaptor<
                            modular_backend,
                            boost::multiprecision::backends::modular_params_ct<modular_backend, modulus_params>>>
                        modular_type;

                    typedef typename detail::element_fp<params<secp_r1_scalar_field<256>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_r1_scalar_field<384> : public field<384> {
                    typedef field<384> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::integral_type integral_type;

                    typedef typename policy_type::extended_integral_type extended_integral_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;

                    constexpr static const integral_type modulus =
                        0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973_cppui_modular384;

                    constexpr static const integral_type group_order_minus_one_half = (modulus - 1) / 2;

                    typedef typename policy_type::modular_backend modular_backend;
                    constexpr static const modular_params_type modulus_params = modulus.backend();
                    typedef boost::multiprecision::number<
                        boost::multiprecision::backends::modular_adaptor<
                            modular_backend,
                            boost::multiprecision::backends::modular_params_ct<modular_backend, modulus_params>>>
                        modular_type;

                    typedef typename detail::element_fp<params<secp_r1_scalar_field<384>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_r1_scalar_field<521> : public field<521> {
                    typedef field<521> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::integral_type integral_type;

                    typedef typename policy_type::extended_integral_type extended_integral_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;

                    constexpr static const integral_type modulus =
                        0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409_cppui_modular521;

                    constexpr static const integral_type group_order_minus_one_half = (modulus - 1) / 2;

                    typedef typename policy_type::modular_backend modular_backend;
                    constexpr static const modular_params_type modulus_params = modulus.backend();
                    typedef boost::multiprecision::number<
                        boost::multiprecision::backends::modular_adaptor<
                            modular_backend,
                            boost::multiprecision::backends::modular_params_ct<modular_backend, modulus_params>>>
                        modular_type;

                    typedef typename detail::element_fp<params<secp_r1_scalar_field<521>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<std::size_t Version>
                using secp_r1_fr = secp_r1_scalar_field<Version>;

                constexpr typename std::size_t const secp_r1_fr<160>::modulus_bits;
                constexpr typename std::size_t const secp_r1_fr<160>::number_bits;
                constexpr typename std::size_t const secp_r1_fr<160>::value_bits;
                constexpr typename secp_r1_fr<160>::integral_type const secp_r1_fr<160>::modulus;
                constexpr typename secp_r1_fr<160>::integral_type const secp_r1_fr<160>::group_order_minus_one_half;
                constexpr typename secp_r1_fr<160>::modular_params_type const secp_r1_fr<160>::modulus_params;

                constexpr typename std::size_t const secp_r1_fr<192>::modulus_bits;
                constexpr typename std::size_t const secp_r1_fr<192>::number_bits;
                constexpr typename std::size_t const secp_r1_fr<192>::value_bits;
                constexpr typename secp_r1_fr<192>::integral_type const secp_r1_fr<192>::modulus;
                constexpr typename secp_r1_fr<192>::integral_type const secp_r1_fr<192>::group_order_minus_one_half;
                constexpr typename secp_r1_fr<192>::modular_params_type const secp_r1_fr<192>::modulus_params;

                constexpr typename std::size_t const secp_r1_fr<224>::modulus_bits;
                constexpr typename std::size_t const secp_r1_fr<224>::number_bits;
                constexpr typename std::size_t const secp_r1_fr<224>::value_bits;
                constexpr typename secp_r1_fr<224>::integral_type const secp_r1_fr<224>::modulus;
                constexpr typename secp_r1_fr<224>::integral_type const secp_r1_fr<224>::group_order_minus_one_half;
                constexpr typename secp_r1_fr<224>::modular_params_type const secp_r1_fr<224>::modulus_params;

                constexpr typename std::size_t const secp_r1_fr<256>::modulus_bits;
                constexpr typename std::size_t const secp_r1_fr<256>::number_bits;
                constexpr typename std::size_t const secp_r1_fr<256>::value_bits;
                constexpr typename secp_r1_fr<256>::integral_type const secp_r1_fr<256>::modulus;
                constexpr typename secp_r1_fr<256>::integral_type const secp_r1_fr<256>::group_order_minus_one_half;
                constexpr typename secp_r1_fr<256>::modular_params_type const secp_r1_fr<256>::modulus_params;

                constexpr typename std::size_t const secp_r1_fr<384>::modulus_bits;
                constexpr typename std::size_t const secp_r1_fr<384>::number_bits;
                constexpr typename std::size_t const secp_r1_fr<384>::value_bits;
                constexpr typename secp_r1_fr<384>::integral_type const secp_r1_fr<384>::modulus;
                constexpr typename secp_r1_fr<384>::integral_type const secp_r1_fr<384>::group_order_minus_one_half;
                constexpr typename secp_r1_fr<384>::modular_params_type const secp_r1_fr<384>::modulus_params;

                constexpr typename std::size_t const secp_r1_fr<521>::modulus_bits;
                constexpr typename std::size_t const secp_r1_fr<521>::number_bits;
                constexpr typename std::size_t const secp_r1_fr<521>::value_bits;
                constexpr typename secp_r1_fr<521>::integral_type const secp_r1_fr<521>::modulus;
                constexpr typename secp_r1_fr<521>::integral_type const secp_r1_fr<521>::group_order_minus_one_half;
                constexpr typename secp_r1_fr<521>::modular_params_type const secp_r1_fr<521>::modulus_params;
            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_NIST_SCALAR_FIELD_HPP
