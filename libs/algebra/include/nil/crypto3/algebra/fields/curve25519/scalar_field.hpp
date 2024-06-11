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

#ifndef CRYPTO3_ALGEBRA_FIELDS_CURVE25519_SCALAR_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_CURVE25519_SCALAR_FIELD_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/field.hpp>



namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                /**
                 * @brief A struct representing a curve25519 curve.
                 * https://datatracker.ietf.org/doc/html/rfc7748#section-4.1
                 * https://neuromancer.sk/std/other/Curve25519#
                 * https://neuromancer.sk/std/other/Ed25519#
                 */
                class curve25519_scalar_field : public field<253> {
                public:
                    typedef field<253> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;

                    typedef typename policy_type::integral_type integral_type;
                    typedef typename policy_type::extended_integral_type extended_integral_type;
#ifdef __ZKLLVM__
                    typedef __zkllvm_field_curve25519_scalar value_type;
#else

                    constexpr static const integral_type modulus =
                        0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed_cppui_modular253;

                    typedef typename policy_type::modular_backend modular_backend;
                    constexpr static const modular_params_type modulus_params = modulus.backend();
                    typedef boost::multiprecision::number<
                        boost::multiprecision::backends::modular_adaptor<
                            modular_backend,
                            boost::multiprecision::backends::modular_params_ct<modular_backend, modulus_params>>>
                        modular_type;

                    typedef typename detail::element_fp<params<curve25519_scalar_field>> value_type;
#endif
                };
                constexpr typename std::size_t const curve25519_scalar_field::modulus_bits;
                constexpr typename std::size_t const curve25519_scalar_field::number_bits;
                constexpr typename std::size_t const curve25519_scalar_field::value_bits;

#ifdef __ZKLLVM__
#else
                constexpr typename curve25519_scalar_field::integral_type const curve25519_scalar_field::modulus;
                constexpr
                    typename curve25519_scalar_field::modular_params_type const curve25519_scalar_field::modulus_params;
#endif
                using curve25519_fr = curve25519_scalar_field;
            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_CURVE25519_SCALAR_FIELD_HPP
