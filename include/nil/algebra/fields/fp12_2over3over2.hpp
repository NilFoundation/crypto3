//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_FP12_2OVER3OVER2_HPP
#define ALGEBRA_FIELDS_FP12_2OVER3OVER2_HPP

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <nil/algebra/fields/element.hpp>
#include <nil/algebra/fields/detail/element/fp2.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
                    
            /**
             * Arithmetic in the finite field F[((p^2)^3)^2].
             *
             * Let p := modulus. This interface provides arithmetic for the extension field
             * Fp12 = Fp6[W]/(W^2-V) where Fp6 = Fp2[V]/(V^3-non_residue) and non_residue is in Fp2
             *
             * ASSUMPTION: p = 1 (mod 6)
             */
            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct fp12_2over3over2 {

                constexpr static const std::size_t modulus_bits = ModulusBits;
                typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_int_backend<
                    modulus_bits, modulus_bits, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked,
                    void>>
                    modulus_type;

                constexpr static const std::size_t generator_bits = GeneratorBits;
                typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_int_backend<
                    generator_bits, generator_bits, boost::multiprecision::unsigned_magnitude,
                    boost::multiprecision::unchecked, void>>
                    generator_type;
                    
            };

        }   // namespace fields
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_FP12_2OVER3OVER2_HPP
