//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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
                 * @tparam ModulusBits
                 * @tparam GeneratorBits
                 */
                template<std::size_t ModulusBits, std::size_t GeneratorBits = CHAR_BIT>
                struct bls12_base_field : public field<ModulusBits, GeneratorBits> { };

                template<>
                struct bls12_base_field<381, CHAR_BIT> : public field<381, CHAR_BIT> {
                    typedef field<381, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    typedef typename policy_type::number_type number_type;

                    constexpr static const modulus_type modulus =
                        0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB_cppui381;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    typedef typename detail::element_fp<params<bls12_base_field<381, CHAR_BIT>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct bls12_base_field<377, CHAR_BIT> : public field<377, CHAR_BIT> {
                    typedef field<377, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    typedef typename policy_type::number_type number_type;

                    constexpr static const modulus_type modulus =
                        0x1AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FBA094800170B5D44300000008508C00000000001_cppui377;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    typedef typename detail::element_fp<params<bls12_base_field<377, CHAR_BIT>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                constexpr typename std::size_t const bls12_base_field<381, CHAR_BIT>::modulus_bits;
                constexpr typename std::size_t const bls12_base_field<377, CHAR_BIT>::modulus_bits;

                constexpr typename std::size_t const bls12_base_field<381, CHAR_BIT>::number_bits;
                constexpr typename std::size_t const bls12_base_field<377, CHAR_BIT>::number_bits;

                constexpr typename std::size_t const bls12_base_field<381, CHAR_BIT>::value_bits;
                constexpr typename std::size_t const bls12_base_field<377, CHAR_BIT>::value_bits;

                constexpr typename bls12_base_field<381, CHAR_BIT>::modulus_type const
                    bls12_base_field<381, CHAR_BIT>::modulus;
                constexpr typename bls12_base_field<377, CHAR_BIT>::modulus_type const
                    bls12_base_field<377, CHAR_BIT>::modulus;

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                using bls12_fq = bls12_base_field<ModulusBits, GeneratorBits>;

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                using bls12 = bls12_base_field<ModulusBits, GeneratorBits>;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_BLS12_BASE_FIELD_HPP
