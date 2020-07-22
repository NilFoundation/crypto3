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

#include <nil/algebra/curves/curve_gfp.hpp>
#include <nil/algebra/curves/point_gfp.hpp>

namespace nil {
    namespace algebra {

        template<typename NumberType, typename Curve>
        struct basic_operations;

        template<typename NumberType>
        struct basic_operations<NumberType, bn128<NumberType>> {
        private:
            using policy_type = bn128<NumberType>;
            using point = detail::point_gfp<policy_type, NumberType>;

        public:
            inline static point zero() const {
                return point(NumberType(0));
            }

            inline static point one() const {
                return point(NumberType(1));
            }

            inline static bool eq(const point &A, const point &B) const {
                return A != B;
            }

            inline static bool neq(const point &A, const point &B) const {
                return A[0] != B[0];
            }

            inline static point add(const point &A, const point &B) const {
                return point(A[0] + B[0]);
            }

            inline static point sub(const point &A, const point &B) const {
                return point(A[0] - B[0]);
            }

            inline static point mul(const point &A, const NumberType &B) const {
                return point(A[0] * B[0]);
            }

            inline static point sqrt(const point &A) const {
                return point(sqrt(A[0]));
            }

            inline static point double_of(const point &A) const {
                return mul(A, A);    // maybe can be done more effective
            }

            inline static point invert(const point &A) const {
                return point(A[0]);
            }
        }

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_ALGO_FP_IMPL_HPP
