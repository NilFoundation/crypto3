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

#ifndef CRYPTO3_ALGEBRA_FIELDS_BLS12_SCALAR_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_BLS12_SCALAR_FIELD_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                /*!
                 * @brief
                 * @tparam Version
                 */
                template<std::size_t Version>
                struct bls12_scalar_field;

                template<>
                struct bls12_scalar_field<381> : public field<255> {
                    typedef field<255> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;

                    typedef typename policy_type::integral_type integral_type;
                    typedef typename policy_type::extended_integral_type extended_integral_type;
#ifdef __ZKLLVM__
                    typedef __zkllvm_field_bls12381_scalar value_type;
#else

                    constexpr static const integral_type modulus =
                        0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001_cppui255;

                    constexpr static const integral_type group_order_minus_one_half =
                        0x39F6D3A994CEBEA4199CEC0404D0EC02A9DED2017FFF2DFF7FFFFFFF80000000_cppui255;

                    typedef typename policy_type::modular_backend modular_backend;
                    constexpr static const modular_params_type modulus_params = modulus;
                    typedef nil::crypto3::multiprecision::number<
                        nil::crypto3::multiprecision::backends::modular_adaptor<
                            modular_backend,
                            nil::crypto3::multiprecision::backends::modular_params_ct<modular_backend, modulus_params>>>
                        modular_type;

                    typedef typename detail::element_fp<params<bls12_scalar_field<381>>> value_type;
#endif
                };

                template<>
                struct bls12_scalar_field<377> : public field<253> {
                    typedef field<253> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;

                    typedef typename policy_type::integral_type integral_type;
                    typedef typename policy_type::extended_integral_type extended_integral_type;
#ifdef __ZKLLVM__
                    // typedef __zkllvm_field__bls377_scalar value_type;
#else

                    constexpr static const integral_type modulus =
                        0x12AB655E9A2CA55660B44D1E5C37B00159AA76FED00000010A11800000000001_cppui253;
                    constexpr static const integral_type group_order_minus_one_half =
                        0x0955B2AF4D1652AB305A268F2E1BD800ACD53B7F680000008508C00000000000_cppui253;

                    typedef typename policy_type::modular_backend modular_backend;
                    constexpr static const modular_params_type modulus_params = modulus;
                    typedef nil::crypto3::multiprecision::number<
                        nil::crypto3::multiprecision::backends::modular_adaptor<
                            modular_backend,
                            nil::crypto3::multiprecision::backends::modular_params_ct<modular_backend, modulus_params>>>
                        modular_type;

                    typedef typename detail::element_fp<params<bls12_scalar_field<377>>> value_type;
#endif
                };

                constexpr typename std::size_t const bls12_scalar_field<381>::modulus_bits;
                constexpr typename std::size_t const bls12_scalar_field<377>::modulus_bits;

                constexpr typename std::size_t const bls12_scalar_field<381>::number_bits;
                constexpr typename std::size_t const bls12_scalar_field<377>::number_bits;

                constexpr typename std::size_t const bls12_scalar_field<381>::value_bits;
                constexpr typename std::size_t const bls12_scalar_field<377>::value_bits;

#ifdef __ZKLLVM__
#else
                constexpr typename bls12_scalar_field<381>::integral_type const bls12_scalar_field<381>::modulus;
                constexpr typename bls12_scalar_field<377>::integral_type const bls12_scalar_field<377>::modulus;
                constexpr typename bls12_scalar_field<381>::integral_type const bls12_scalar_field<381>::group_order_minus_one_half;
                constexpr typename bls12_scalar_field<377>::integral_type const bls12_scalar_field<377>::group_order_minus_one_half;

                constexpr
                    typename bls12_scalar_field<381>::modular_params_type const bls12_scalar_field<381>::modulus_params;
                constexpr
                    typename bls12_scalar_field<377>::modular_params_type const bls12_scalar_field<377>::modulus_params;
#endif
                template<std::size_t Version = 381>
                using bls12_fr = bls12_scalar_field<Version>;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_BLS12_SCALAR_FIELD_HPP
