//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_FP6_3OVER2_HPP
#define ALGEBRA_FF_FP6_3OVER2_HPP

#include <nil/algebra/fields/element.hpp>
#include <nil/algebra/fields/fp.hpp>

#include <nil/algebra/fields/detail/exponentiation.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
                    
            /**
             * Arithmetic in the finite field F[(p^2)^3].
             *
             * Let p := modulus. This interface provides arithmetic for the extension field
             * Fp6 = Fp2[V]/(V^3-non_residue) where non_residue is in Fp2.
             *
             * ASSUMPTION: p = 1 (mod 6)
             */
            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct fp6_3over2 {
                typedef element<fp2<ModulusBits, GeneratorBits>, number_type> non_residue_type;

                constexpr static const std::size_t modulus_bits = ModulusBits;
                typedef number<backends::cpp_int_backend<modulus_bits, modulus_bits, unsigned_magnitude, unchecked, void>>
                    modulus_type;

                constexpr static const std::size_t generator_bits = GeneratorBits;
                typedef number<
                    backends::cpp_int_backend<generator_bits, generator_bits, unsigned_magnitude, unchecked, void>>
                    generator_type;
                    
            };

        }   // namespace fields
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP6_3OVER2_HPP
