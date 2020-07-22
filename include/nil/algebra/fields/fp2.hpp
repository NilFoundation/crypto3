//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_FP2_HPP
#define ALGEBRA_FF_FP2_HPP

#include <nil/algebra/fields/fp.hpp>

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
        struct fp2 {
        private:
            using point_fp = detail::point<fp<Modulus>, NumberType>;
            using point_fp2 = detail::point<fp2<Modulus>, NumberType>;

        public:
            constexpr fp2(const point_fp2 &point) : top_non_residue(point) {
            }    // init point for non_residue in fp3 or higher

            constexpr fp2(const point_fp &point) : non_residue(fp(point)) {
            }    // init point for non_residue in itself

            constexpr static const std::size_t arity = 2;

            constexpr static const NumberType p = Modulus;
            constexpr static const NumberType q;

            constexpr const point_fp2 top_non_residue;
            constexpr const point_fp non_residue = 0;
            constexpr static const NumberType g;

            constexpr static const std::size_t num_bits = 0;
        };

        template<typename NumberType, const NumberType &modulus>
        fp2_model<n, modulus> fp2_model<n, modulus>::Frobenius_map(unsigned long power) const {
            return fp2_model<n, modulus>(c0, Frobenius_coeffs_c1[power % 2] * c1);
        }

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP2_HPP
