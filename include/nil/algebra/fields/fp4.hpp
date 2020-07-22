//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_FP4_HPP
#define ALGEBRA_FF_FP4_HPP

#include <nil/algebra/fields/fp3.hpp>

namespace nil {
    namespace algebra {

        /**
         * Arithmetic in the field F[p^2].
         *
         * Let p := modulus. This interface provides arithmetic for the extension field
         * Fp2 = Fp[U]/(U^2-non_residue), where non_residue is in Fp.
         *
         * ASSUMPTION: p = 1 (mod 6)
         */
        template<typename NumberType &Modulus>
        struct fp4 {
        private:
            using point_fp = detail::point<fp<Modulus>, NumberType>;
            using point_fp4 = detail::point<fp4<Modulus>, NumberType>;

        public:
            constexpr fp4(const point_fp4 &point) : top_non_residue(point) {
            }    // init point for non_residue in fp3 or higher

            constexpr fp4(const point_fp &point) : non_residue(fp(point)) {
            }    // init point for non_residue in itself

            constexpr static const std::size_t arity = 4;

            constexpr static const NumberType p = Modulus;
            constexpr static const NumberType q;

            constexpr const point_fp4 top_non_residue;
            constexpr const point_fp non_residue = 0;
            constexpr static const NumberType g;

            constexpr static const std::size_t num_bits = 0;
        };

        template<typename NumberType, const NumberType &modulus>
        fp4_model<n, modulus> fp4_model<n, modulus>::Frobenius_map(unsigned long power) const {
            return fp4_model<n, modulus>(c0, Frobenius_coeffs_c1[power % 2] * c1);
        }

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP2_HPP
