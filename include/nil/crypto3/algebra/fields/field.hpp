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

#include <boost/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
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
                    constexpr static const std::size_t number_bits = ModulusBits;

#ifdef __ZKLLVM__
                    typedef int integral_type;
                    typedef int extended_integral_type;
#else
                    typedef boost::multiprecision::number<
                        boost::multiprecision::backends::cpp_int_modular_backend<modulus_bits>>
                        integral_type;

                    // TODO(martun): check why extended integral type must be 16x wider.
                    typedef boost::multiprecision::number<
                        boost::multiprecision::backends::cpp_int_modular_backend<16 * modulus_bits>>
                        extended_integral_type;

                    typedef boost::multiprecision::backends::cpp_int_modular_backend<modulus_bits> modular_backend;

                    typedef boost::multiprecision::backends::modular_params<modular_backend> modular_params_type;
#endif
                };

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_FIELD_HPP
