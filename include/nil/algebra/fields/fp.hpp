//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_FP_HPP
#define ALGEBRA_FF_FP_HPP

#include <nil/algebra/fields/element.hpp>

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>

namespace nil {
    namespace algebra {
        /**
         * Arithmetic in the finite field F[p], for prime p of fixed length.
         *
         * This class implements Fp-arithmetic, for a large prime p, using a fixed number
         * of words. It is optimized for tight memory consumption, so the modulus p is
         * passed as a template parameter, to avoid per-element overheads.
         */
        template<std::size_t ModulusBits, std::size_t GeneratorBits>
        struct fp {

            constexpr static const std::size_t modulus_bits = ModulusBits;
            typedef number<backends::cpp_int_backend<modulus_bits, modulus_bits, unsigned_magnitude, unchecked, void>>
                modulus_type;

            constexpr static const std::size_t generator_bits = GeneratorBits;
            typedef number<
                backends::cpp_int_backend<generator_bits, generator_bits, unsigned_magnitude, unchecked, void>>
                generator_type;

        };

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP_HPP
