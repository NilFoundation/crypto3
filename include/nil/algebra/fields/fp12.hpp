//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_FP6_HPP
#define ALGEBRA_FF_FP6_HPP

#include <nil/algebra/fields/fp6.hpp>

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
        struct fp12 {
        private:
            using point_fp = detail::point<fp<Modulus>, NumberType>;
            using point_fp12 = detail::point<fp12<Modulus>, NumberType>;

        public:
            constexpr fp12(const point_fp12 &point) : top_non_residue(point) {
            }    // init point for non_residue in fp3 or higher

            constexpr fp12(const point_fp &point) : non_residue(fp(point)) {
            }    // init point for non_residue in itself

            constexpr static const std::size_t arity = 12;

            constexpr static const NumberType p = Modulus;
            constexpr static const NumberType q;

            constexpr const point_fp12 top_non_residue;
            constexpr const point_fp non_residue = 0;
            constexpr static const NumberType g;

            constexpr static const std::size_t num_bits = 0;
        };

        template<typename NumberType, const NumberType &modulus>
        fp12_model<n, modulus> fp12_model<n, modulus>::Frobenius_map(unsigned long power) const {
            return fp12_model<n, modulus>(c0, Frobenius_coeffs_c1[power % 2] * c1);
        }

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP2_HPP
