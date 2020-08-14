//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_FP4_HPP
#define ALGEBRA_FIELDS_FP4_HPP

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <nil/algebra/fields/element.hpp>
#include <nil/algebra/fields/detail/element/fp.hpp>

namespace nil {
    namespace algebra {
            namespace fields {

            /**
             * Arithmetic in the field F[p^2].
             *
             * Let p := modulus. This interface provides arithmetic for the extension field
             * Fp4 = Fp2[V]/(V^2-U) where Fp2 = Fp[U]/(U^2-non_residue) and non_residue is in Fp.
             *
             * ASSUMPTION: p = 1 (mod 6)
             */
            
            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct fp4 {
                typedef detail::element_fp<ModulusBits, GeneratorBits> non_residue_type;

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

#endif    // ALGEBRA_FIELDS_FP4_HPP
