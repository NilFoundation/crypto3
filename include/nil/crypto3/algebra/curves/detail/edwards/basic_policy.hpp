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

#ifndef CRYPTO3_ALGEBRA_CURVES_EDWARDS_BASIC_POLICY_HPP
#define CRYPTO3_ALGEBRA_CURVES_EDWARDS_BASIC_POLICY_HPP

#include <nil/crypto3/algebra/fields/edwards/base_field.hpp>
#include <nil/crypto3/algebra/fields/edwards/scalar_field.hpp>

#include <nil/crypto3/algebra/fields/fp3.hpp>
#include <nil/crypto3/algebra/fields/fp6_2over3.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    using namespace algebra;

                    template<std::size_t ModulusBits = 183>
                    struct edwards_basic_policy { };

                    template<>
                    struct edwards_basic_policy<183> {
                        constexpr static const std::size_t base_field_bits = 183;
                        typedef fields::edwards_fq<base_field_bits> g1_field_type;
                        typedef g1_field_type base_field_type;
                        typedef typename fields::fp3<base_field_type> g2_field_type;
                        typedef typename fields::fp6_2over3<base_field_type> gt_field_type;

                        typedef typename base_field_type::modulus_type number_type;
                        typedef typename base_field_type::extended_modulus_type extended_number_type;

                        constexpr static const number_type base_field_modulus = base_field_type::modulus;

                        constexpr static const std::size_t scalar_field_bits = 183;
                        typedef fields::edwards_fr<scalar_field_bits> scalar_field_type;
                        constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                        constexpr static const number_type p = base_field_modulus;
                        constexpr static const number_type q = scalar_field_modulus;

                        constexpr static const number_type a = 0x01;
                        constexpr static const number_type d = 0x64536D55979879327CF1306BB5A6277D254EF9776CE70_cppui179;
                    };

                    constexpr typename edwards_basic_policy<183>::number_type const
                        edwards_basic_policy<183>::base_field_modulus;

                    constexpr typename edwards_basic_policy<183>::number_type const
                        edwards_basic_policy<183>::scalar_field_modulus;

                    constexpr typename edwards_basic_policy<183>::number_type const
                        edwards_basic_policy<183>::a;

                    constexpr typename edwards_basic_policy<183>::number_type const
                        edwards_basic_policy<183>::d;

                    constexpr typename edwards_basic_policy<183>::number_type const
                        edwards_basic_policy<183>::p;

                    constexpr typename edwards_basic_policy<183>::number_type const
                        edwards_basic_policy<183>::q;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_EDWARDS_BASIC_POLICY_HPP
