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

#ifndef CRYPTO3_ALGEBRA_CURVES_BLS12_BASIC_POLICY_HPP
#define CRYPTO3_ALGEBRA_CURVES_BLS12_BASIC_POLICY_HPP

#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>

#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp12_2over3over2.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    using namespace algebra;

                    template<std::size_t ModulusBits = 381>
                    struct bls12_basic_policy { };

                    template<>
                    struct bls12_basic_policy<381> {
                        constexpr static const std::size_t base_field_bits = 381;
                        typedef fields::bls12_fq<base_field_bits> g1_field_type;
                        using base_field_type = g1_field_type;
                        typedef typename fields::fp2<base_field_type> g2_field_type;
                        typedef typename fields::fp12_2over3over2<base_field_type> gt_field_type;

                        typedef typename base_field_type::modulus_type number_type;
                        typedef typename base_field_type::extended_modulus_type extended_number_type;

                        constexpr static const number_type base_field_modulus = base_field_type::modulus;

                        constexpr static const std::size_t scalar_field_bits = 381;    // actually, 255
                        typedef fields::bls12_fr<scalar_field_bits> scalar_field_type;
                        constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                        constexpr static const number_type p = base_field_modulus;
                        constexpr static const number_type q = scalar_field_modulus;

                        constexpr static const number_type a = number_type(0x00);
                        constexpr static const number_type b = number_type(0x04);
                    };

                    template<>
                    struct bls12_basic_policy<377> {
                        constexpr static const std::size_t base_field_bits = 377;
                        typedef fields::bls12_fq<base_field_bits> g1_field_type;
                        using base_field_type = g1_field_type;
                        typedef typename fields::fp2<base_field_type> g2_field_type;
                        typedef typename fields::fp12_2over3over2<base_field_type> gt_field_type;

                        typedef typename base_field_type::modulus_type number_type;
                        constexpr static const number_type base_field_modulus = base_field_type::modulus;
                        typedef typename base_field_type::extended_modulus_type extended_number_type;

                        constexpr static const std::size_t scalar_field_bits = 377;    // actually, 253
                        typedef fields::bls12_fr<scalar_field_bits> scalar_field_type;
                        constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                        constexpr static const number_type p = base_field_modulus;
                        constexpr static const number_type q = scalar_field_modulus;

                        constexpr static const number_type a = number_type(0x00);
                        constexpr static const number_type b = number_type(0x01);
                    };

                    constexpr typename bls12_basic_policy<381>::number_type const
                        bls12_basic_policy<381>::a;
                    constexpr typename bls12_basic_policy<377>::number_type const
                        bls12_basic_policy<377>::a;

                    constexpr typename bls12_basic_policy<381>::number_type const
                        bls12_basic_policy<381>::b;
                    constexpr typename bls12_basic_policy<377>::number_type const
                        bls12_basic_policy<377>::b;

                    constexpr typename std::size_t const bls12_basic_policy<381>::base_field_bits;
                    constexpr typename std::size_t const bls12_basic_policy<377>::base_field_bits;

                    constexpr typename std::size_t const bls12_basic_policy<381>::scalar_field_bits;
                    constexpr typename std::size_t const bls12_basic_policy<377>::scalar_field_bits;

                    constexpr typename bls12_basic_policy<381>::number_type const
                        bls12_basic_policy<381>::p;
                    constexpr typename bls12_basic_policy<377>::number_type const
                        bls12_basic_policy<377>::p;

                    constexpr typename bls12_basic_policy<381>::number_type const
                        bls12_basic_policy<381>::q;
                    constexpr typename bls12_basic_policy<377>::number_type const
                        bls12_basic_policy<377>::q;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_BLS12_BASIC_POLICY_HPP