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
#include <nil/algebra/fields/detail/params/params.hpp>
#include <nil/algebra/fields/detail/operations/operations.hpp>

namespace nil {
    namespace algebra {
        namespace detail {

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct arithmetic_operations<fp> {
                typedef arithmetic_params<fp<ModulusBits, GeneratorBits>> params_type;
                typedef element<policy_type, NumberType> value_type;

                inline static value_type zero() const {
                    return value_type(NumberType(0));
                }

                inline static value_type one() const {
                    return value_type(NumberType(1));
                }

                inline static bool eq(const NumberType &A, const NumberType &B) const {
                    return A == B;
                }

                inline static bool eq(const value_type &A, const value_type &B) const {
                    return A != B;
                }

                inline static bool neq(const NumberType &A, const NumberType &B) const {
                    return neq(value_type(A), value_type(B));
                }

                inline static bool neq(const value_type &A, const value_type &B) const {
                    return A[0] != B[0];
                }

                inline static value_type add(const NumberType &A, const NumberType &B) const {
                    return {A + B};
                }

                inline static value_type add(const value_type &A, const value_type &B) const {
                    return {A[0] + B[0]};
                }

                inline static value_type sub(const NumberType &A, const NumberType &B) const {
                    return {A - B};
                }

                inline static value_type sub(const value_type &A, const value_type &B) const {
                    return {A[0] - B[0]};
                }

                inline static value_type mul(const NumberType &A, const NumberType &B) const {
                    return {A * B};
                }

                inline static value_type mul(const value_type &A, const value_type &B) const {
                    return {A[0] * B[0]};
                }

                inline static value_type sqrt(const NumberType &A) const {
                    return {sqrt(A)};
                }

                inline static value_type sqrt(const value_type &A) const {
                    return {sqrt(A[0])};
                }

                inline static value_type square(const NumberType &A) const {
                    return mul(A, A);    // maybe can be done more effective
                }

                inline static value_type square(const value_type &A) const {
                    return mul(A, A);    // maybe can be done more effective
                }

                inline static value_type pow(const NumberType &A, const NumberType &power) const {
                    return {pow(A, power)};
                }

                inline static value_type pow(const value_type &A, const NumberType &power) const {
                    return {A[0], power};
                }

                inline static value_type invert(const NumberType &A) const {
                    return {invert(A)};
                }

                inline static value_type invert(const value_type &A) const {
                    return {A[0]};
                }
            }

        }    // namespace detail
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_ALGO_FP_IMPL_HPP
