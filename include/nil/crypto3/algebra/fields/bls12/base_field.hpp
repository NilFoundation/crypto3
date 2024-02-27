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

#ifndef CRYPTO3_ALGEBRA_FIELDS_BLS12_BASE_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_BLS12_BASE_FIELD_HPP

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
                struct bls12_base_field;

                template<>
                struct bls12_base_field<381> : public field<381> {
                    typedef field<381> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;

                    typedef typename policy_type::integral_type integral_type;
                    typedef typename policy_type::extended_integral_type extended_integral_type;
#ifdef __ZKLLVM__
                    typedef __zkllvm_field_bls12381_base value_type;
#else

                    constexpr static const integral_type modulus =
                        0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB_cppui381;

                    constexpr static const integral_type group_order_minus_one_half =
                        0xD0088F51CBFF34D258DD3DB21A5D66BB23BA5C279C2895FB39869507B587B120F55FFFF58A9FFFFDCFF7FFFFFFFD555_cppui381;

                    typedef typename policy_type::modular_backend modular_backend;
                    constexpr static const modular_params_type modulus_params = modulus;
                    typedef nil::crypto3::multiprecision::number<
                        nil::crypto3::multiprecision::backends::modular_adaptor<
                            modular_backend,
                            nil::crypto3::multiprecision::backends::modular_params_ct<modular_backend, modulus_params>>>
                        modular_type;

                    typedef typename detail::element_fp<params<bls12_base_field<381>>> value_type;
#endif
                };

                template<>
                struct bls12_base_field<377> : public field<377> {
                    typedef field<377> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;

                    typedef typename policy_type::integral_type integral_type;
                    typedef typename policy_type::extended_integral_type extended_integral_type;
#ifdef __ZKLLVM__
                    // typedef __zkllvm_field_bls12377_base value_type;
#else

                    constexpr static const integral_type modulus =
                        0x1AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FBA094800170B5D44300000008508C00000000001_cppui377;

                    constexpr static const integral_type group_order_minus_one_half =
                        0xD71D230BE28875631D82E03650A49D8D116CF9807A89C78F79B117DD04A4000B85AEA2180000004284600000000000_cppui377;

                    typedef typename policy_type::modular_backend modular_backend;
                    typedef nil::crypto3::multiprecision::modular_params<modular_backend> modular_params_type;
                    constexpr static const modular_params_type modulus_params = modulus;
                    typedef nil::crypto3::multiprecision::number<
                        nil::crypto3::multiprecision::backends::modular_adaptor<
                            modular_backend,
                            nil::crypto3::multiprecision::backends::modular_params_ct<modular_backend, modulus_params>>>
                        modular_type;

                    typedef typename detail::element_fp<params<bls12_base_field<377>>> value_type;
#endif
                };

                constexpr typename std::size_t const bls12_base_field<381>::modulus_bits;
                constexpr typename std::size_t const bls12_base_field<377>::modulus_bits;

                constexpr typename std::size_t const bls12_base_field<381>::number_bits;
                constexpr typename std::size_t const bls12_base_field<377>::number_bits;

                constexpr typename std::size_t const bls12_base_field<381>::value_bits;
                constexpr typename std::size_t const bls12_base_field<377>::value_bits;

#ifdef __ZKLLVM__
#else
                constexpr typename bls12_base_field<381>::integral_type const bls12_base_field<381>::modulus;
                constexpr typename bls12_base_field<377>::integral_type const bls12_base_field<377>::modulus;

                constexpr typename bls12_base_field<381>::integral_type const bls12_base_field<381>::group_order_minus_one_half;
                constexpr typename bls12_base_field<377>::integral_type const bls12_base_field<377>::group_order_minus_one_half;

                constexpr
                    typename bls12_base_field<381>::modular_params_type const bls12_base_field<381>::modulus_params;
                constexpr
                    typename bls12_base_field<377>::modular_params_type const bls12_base_field<377>::modulus_params;
#endif
                template<std::size_t Version = 381>
                using bls12_fq = bls12_base_field<Version>;

                template<std::size_t Version = 381>
                using bls12 = bls12_base_field<Version>;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_BLS12_BASE_FIELD_HPP
