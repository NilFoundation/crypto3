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

#ifndef CRYPTO3_ALGEBRA_FIELDS_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_FIELD_HPP

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                /**
                 * Arithmetic in the finite field F[p], for prime p of fixed length.
                 *
                 * This class implements Fp-arithmetic, for a large prime p, using a fixed number
                 * of words. It is optimized for tight memory consumption, so the modulus p is
                 * passed as a template parameter, to avoid per-element overheads.
                 */
                template<std::size_t ModulusBits>
                struct field {

                    constexpr static const std::size_t modulus_bits = ModulusBits;
                    typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::backends::cpp_int_backend<
                        modulus_bits, modulus_bits, nil::crypto3::multiprecision::unsigned_magnitude,
                        nil::crypto3::multiprecision::unchecked, void>>
                        modulus_type;

                    typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::backends::cpp_int_backend<
                        16 * modulus_bits, 16 * modulus_bits, nil::crypto3::multiprecision::unsigned_magnitude,
                        nil::crypto3::multiprecision::unchecked, void>>
                        extended_modulus_type;

                    constexpr static const std::size_t number_bits = ModulusBits;
                    typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::backends::modular_adaptor<
                        nil::crypto3::multiprecision::backends::cpp_int_backend<
                            modulus_bits, modulus_bits, nil::crypto3::multiprecision::signed_magnitude,
                            nil::crypto3::multiprecision::unchecked, void
                            >>>
                        number_type;
                };

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_FIELD_HPP
