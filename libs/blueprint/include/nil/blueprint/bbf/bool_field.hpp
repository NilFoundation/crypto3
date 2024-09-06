//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_FIELDS_BOOL_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_BOOL_FIELD_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/field.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                /**
                 * @brief A struct representing a Boolean field = {0,1} (yes, really!)
                 */
                struct bool_field : public field<2> {
                    typedef field<2> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;

                    typedef typename policy_type::integral_type integral_type;
                    typedef typename policy_type::extended_integral_type extended_integral_type;

                    constexpr static const integral_type modulus = 2;

                    constexpr static const integral_type group_order_minus_one_half = 1;

                    typedef typename policy_type::modular_backend modular_backend;
                    constexpr static const modular_params_type modulus_params = modulus.backend();
                    typedef boost::multiprecision::number<
                        boost::multiprecision::backends::modular_adaptor<
                            modular_backend,
                            boost::multiprecision::backends::modular_params_ct<modular_backend, modulus_params>>>
                        modular_type;

                    typedef typename detail::element_fp<params<bool_field>> value_type;
                };

                constexpr typename std::size_t const bool_field::modulus_bits;
                constexpr typename std::size_t const bool_field::number_bits;
                constexpr typename std::size_t const bool_field::value_bits;

                constexpr typename bool_field::integral_type const bool_field::modulus;
                constexpr typename bool_field::integral_type const bool_field::group_order_minus_one_half;
            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_BOOL_FIELD_HPP
