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

#ifndef CRYPTO3_ALGEBRA_FIELDS_VESTA_BASE_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_VESTA_BASE_FIELD_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/field.hpp>



namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                /**
                 * @brief A struct representing a vesta curve.
                 */
                class vesta_base_field : public field<255> {
                public:
                    typedef field<255> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;

                    typedef typename policy_type::integral_type integral_type;
                    typedef typename policy_type::extended_integral_type extended_integral_type;
#ifdef __ZKLLVM__
                    typedef __zkllvm_field_vesta_base value_type;
#else

                    constexpr static const integral_type modulus =
                        0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001_cppui_modular255;
                    constexpr static const integral_type group_order_minus_one_half = (modulus - 1u) / 2;

                    typedef typename policy_type::modular_backend modular_backend;
                    constexpr static const modular_params_type modulus_params = modulus.backend();
                    typedef boost::multiprecision::number<
                        boost::multiprecision::backends::modular_adaptor<
                            modular_backend,
                            boost::multiprecision::backends::modular_params_ct<modular_backend, modulus_params>>>
                        modular_type;

                    typedef typename detail::element_fp<params<vesta_base_field>> value_type;
#endif
                };

                constexpr typename std::size_t const vesta_base_field::modulus_bits;
                constexpr typename std::size_t const vesta_base_field::number_bits;
                constexpr typename std::size_t const vesta_base_field::value_bits;

#ifdef __ZKLLVM__
#else
                constexpr typename vesta_base_field::integral_type const vesta_base_field::modulus;
#endif
                using vesta_fq = vesta_base_field;
            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_VESTA_BASE_FIELD_HPP
