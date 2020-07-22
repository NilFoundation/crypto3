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

#include <nil/algebra/fields/point.hpp>

namespace nil {
    namespace algebra {
        /**
         * Arithmetic in the finite field F[p], for prime p of fixed length.
         *
         * This class implements Fp-arithmetic, for a large prime p, using a fixed number
         * of words. It is optimized for tight memory consumption, so the modulus p is
         * passed as a template parameter, to avoid per-element overheads.
         */
        template<std::size_t PBits, typename NumberType &Modulus>
        struct fp {
            using number_type = NumberType;

        private:
            typedef NumberType number_type;
            typedef detail::point<fp<Modulus>, number_type> point_type;

        public:
            constexpr fp(const point_fp &point) : top_non_residue(point) {
            }    // init point for non_residue in fp2 or higher
            constexpr fp() {
            }    // init point for non_residue in itself

            constexpr static const std::size_t arity = 1;

            constexpr static const number_type p = Modulus;
            constexpr static const number_type q = (p - 1) / 2;

            constexpr const point_fp top_non_residue;
            constexpr static const number_type g = 0x02;

            constexpr static const std::size_t num_bits = PBits;
        };

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP_HPP
