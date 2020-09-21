//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_FIELD_HPP

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/modular/modular_adaptor.hpp>

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
                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                struct field {

                    constexpr static const std::size_t modulus_bits = ModulusBits;
                    typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_int_backend<
                        modulus_bits, modulus_bits, boost::multiprecision::unsigned_magnitude,
                        boost::multiprecision::unchecked, void>>
                        modulus_type;

                    typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_int_backend<
                        16 * modulus_bits, 16 * modulus_bits, boost::multiprecision::unsigned_magnitude,
                        boost::multiprecision::unchecked, void>>
                        extended_modulus_type;

                    constexpr static const std::size_t number_bits = ModulusBits;
                    typedef boost::multiprecision::number<boost::multiprecision::backends::modular_adaptor<
                        boost::multiprecision::backends::cpp_int_backend<
                            // modulus_bits, modulus_bits, boost::multiprecision::unsigned_magnitude,
                            // boost::multiprecision::unchecked, void
                            >>>
                        number_type;

                    constexpr static const std::size_t generator_bits = GeneratorBits;
                    typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_int_backend<
                        generator_bits, generator_bits, boost::multiprecision::unsigned_magnitude,
                        boost::multiprecision::unchecked, void>>
                        generator_type;
                };

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FIELDS_FIELD_HPP
