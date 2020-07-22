//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_ALGO_FP_IMPL_HPP
#define ALGEBRA_ALGO_FP_IMPL_HPP

#include <nil/algebra/fields/fp.hpp>
#include <nil/algebra/fields/detail/point.hpp>

namespace nil {
    namespace algebra {

        template<typename NumberType, typename Field>
        struct basic_operations;

        template<typename NumberType, typename NumberType &Modulus>
        struct basic_operations<fp<Modulus>> {
        private:
            using policy_type = fp<Modulus>;
            using point = detail::point<policy_type, NumberType>;

        public:
            inline static point zero() const {
                return point(NumberType(0));
            }

            inline static point one() const {
                return point(NumberType(1));
            }

            inline static bool eq(const NumberType &A, const NumberType &B) const {
                return A == B;
            }

            inline static bool eq(const point &A, const point &B) const {
                return A != B;
            }

            inline static bool neq(const NumberType &A, const NumberType &B) const {
                return neq(point(A), point(B));
            }

            inline static bool neq(const point &A, const point &B) const {
                return A[0] != B[0];
            }

            inline static point add(const NumberType &A, const NumberType &B) const {
                return point(A + B);
            }

            inline static point add(const point &A, const point &B) const {
                return point(A[0] + B[0]);
            }

            inline static point sub(const NumberType &A, const NumberType &B) const {
                return point(A - B);
            }

            inline static point sub(const point &A, const point &B) const {
                return point(A[0] - B[0]);
            }

            inline static point mul(const NumberType &A, const NumberType &B) const {
                return point(A * B);
            }

            inline static point mul(const point &A, const point &B) const {
                return point(A[0] * B[0]);
            }

            inline static point sqrt(const NumberType &A) const {
                return point(sqrt(A));
            }

            inline static point sqrt(const point &A) const {
                return point(sqrt(A[0]));
            }

            inline static point square(const NumberType &A) const {
                return mul(A, A);    // maybe can be done more effective
            }

            inline static point square(const point &A) const {
                return mul(A, A);    // maybe can be done more effective
            }

            inline static point pow(const NumberType &A, const NumberType &power) const {
                return point(pow(A, power));
            }

            inline static point pow(const point &A, const NumberType &power) const {
                return point(A[0], power);
            }

            inline static point invert(const NumberType &A) const {
                return point(invert(A));
            }

            inline static point invert(const point &A) const {
                return point(A[0]);
            }
        }

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_ALGO_FP_IMPL_HPP
