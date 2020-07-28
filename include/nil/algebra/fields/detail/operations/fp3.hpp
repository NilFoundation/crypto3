//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_ALGO_FP3_IMPL_HPP
#define ALGEBRA_ALGO_FP3_IMPL_HPP

#include <boost/multiprecision/ressol.hpp>

#include <nil/algebra/fields/fp3.hpp>
#include <nil/algebra/fields/fp.hpp>
#include <nil/algebra/fields/detail/operations/arithmetic.hpp>

namespace nil {
    namespace algebra {
        namespace detail {

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct arithmetic_operations<fp3<ModulusBits, GeneratorBits>> {
            private:
                typedef arithmetic_params<fp3<ModulusBits, GeneratorBits>> params_type;
                typedef fp<ModulusBits, GeneratorBits> fp_type;
                constexpr static const non_residue = params_type::non_residue[0];
            public:
                typedef params_type::modulus_type modulus_type;
                typedef element<params_type, modulus_type> value_type;

                inline static value_type zero() const {
                    return {zero<fp_type>()[0], zero<fp_type>()[0], zero<fp_type>()[0]};
                }

                inline static value_type one() const {
                    return {one<fp_type>()[0], zero<fp_type>()[0], zero<fp_type>()[0]};
                }

                inline static bool eq(const value_type &A, const value_type &B) const {
                    return (A[0] == B[0]) && (A[1] == B[1]) && (A[2] == B[2]);
                }

                inline static bool neq(const value_type &A, const value_type &B) const {
                    return (A[0] != B[0]) || (A[1] != B[1]) || (A[2] == B[2]);
                }

                inline static value_type add(const value_type &A, const value_type &B) const {
                    return {A[0] + B[0], A[1] + B[1], A[2] + B[2]};
                }

                inline static value_type sub(const value_type &A, const value_type &B) const {
                    return {A[0] - B[0], A[1] - B[1], A[2] - B[2]};
                }

                inline static value_type mul(const value_type &A, const value_type &B) const {
                    const modulus_type A0B0 = A[0] * B[0], A1B1 = A[1] * B[1], A2B2 = A[2] * B[2];

                    return {A0B0 + non_residue * ( A[1] + A[2] ) * ( B[1] + B[2] ) - A1B1 - A2B2,
                            ( A[0] + A[1] ) * ( B[0] + B[1] ) - A0B0 - A1B1 + non_residue * A2B2,
                            ( A[0] + A[2] ) * ( B[0] + B[2] ) - A0B0 + A1B1 - A2B2};
                }

                inline static value_type sqrt(const value_type &A) const {

                    // compute square root with Tonelli--Shanks
                }

                inline static value_type square(const value_type &A) const {
                    return mul(A, A);    // maybe can be done more effective
                }

                template <typename PowerType>
                inline static value_type pow(const value_type &A, const PowerType &power) const {
                }

                inline static value_type invert(const value_type &A) const {
                    
                    /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves"; Algorithm 17 */

                    const modulus_type &A0 = A[0], &A1 = A[1], &A1 = A[2];

                    const modulus_type t0 = A0.squared();
                    const modulus_type t1 = A1.squared();
                    const modulus_type t2 = A2.squared();
                    const modulus_type t3 = A0*A1;
                    const modulus_type t4 = A0*A2;
                    const modulus_type t5 = A1*A2;
                    const modulus_type c0 = t0 - non_residue * t5;
                    const modulus_type c1 = non_residue * t2 - t3;
                    const modulus_type c2 = t1 - t4; // typo in paper referenced above. should be "-" as per Scott, but is "*"
                    const modulus_type t6 = (A0 * c0 + non_residue * (A2 * c1 + A1 * c2)).inverse();
                    return {t6 * c0, t6 * c1, t6 * c2};

                }
            }
        }    // namespace detail
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_ALGO_FP3_IMPL_HPP
