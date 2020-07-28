//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_ALGO_FP6_3OVER2_IMPL_HPP
#define ALGEBRA_ALGO_FP6_3OVER2_IMPL_HPP

#include <boost/multiprecision/ressol.hpp>

#include <nil/algebra/fields/fp6_3over2.hpp>
#include <nil/algebra/fields/fp3.hpp>
#include <nil/algebra/fields/fp.hpp>
#include <nil/algebra/fields/detail/operations/arithmetic.hpp>

namespace nil {
    namespace algebra {
        namespace detail {

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct arithmetic_operations<fp6_3over2<ModulusBits, GeneratorBits>> {
            private:
                typedef arithmetic_params<fp6_3over2<ModulusBits, GeneratorBits>> params_type;
                typedef fp<ModulusBits, GeneratorBits> fp_type;
                typedef fp3<ModulusBits, GeneratorBits> fp3_type;
                typedef element<arithmetic_params<fp2<ModulusBits, GeneratorBits>>, modulus_type> fp2_value_type;

                constexpr static const non_residue = params_type::non_residue;
            public:
                typedef params_type::modulus_type modulus_type;
                typedef element<params_type, modulus_type> value_type;

                inline static value_type zero() const {
                    return {zero<fp2_type>(), zero<fp2_type>(), zero<fp2_type>()};
                }

                inline static value_type one() const {
                    return {one<fp2_type>(), zero<fp2_type>(), zero<fp2_type>()};
                }

                inline static bool eq(const value_type &A, const value_type &B) const {
                    return eq<fp2_type>(A[0], B[0]) && eq<fp2_type>(A[1], B[1]) && eq<fp2_type>(A[2], B[2]);
                }

                inline static bool neq(const value_type &A, const value_type &B) const {
                    return neq<fp2_type>(A[0], B[0]) || neq<fp2_type>(A[1], B[1]) || neq<fp2_type>(A[2], B[2]);
                }

                inline static value_type add(const value_type &A, const value_type &B) const {
                    return {add<fp2_type>(A[0], B[0]), add<fp2_type>(A[1], B[1]), add<fp2_type>(A[2], B[2])};
                }

                inline static value_type sub(const value_type &A, const value_type &B) const {
                    return {sub<fp2_type>(A[0], B[0]), sub<fp2_type>(A[1], B[1]), sub<fp2_type>(A[2], B[2])};
                }

                inline static value_type mul(const value_type &A, const value_type &B) const {

                    /* Devegili OhEig Scott Dahab --- Multiplication and Squaring on Pairing-Friendly Fields.pdf; Section 4 (Karatsuba) */

                    const fp2_value_type A0B0 = mul<fp2_type>(A[0], B[0]), A1B1 = mul<fp2_type>(A[1], B[1]), A2B2 = mul<fp2_type>(A[2], B[2]);

                    return {A0B0 + mul_by_non_residue( (A[1] + A[2]) * (B[1] + B[2]) - A1B1 - A2B2),
                            ( A[0] + A[1] ) * ( B[0] + B[1] ) - A0B0 - A1B1 + mul_by_non_residue (A2B2) ,
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
                    
                    /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves"; Algorithm 8 */
                    const fp2_value_type &A0 = A[0], &A1 = A[1], &A2 = A[2];
                    const fp2_value_type t0 = square<fp2_type>(A0);
                    const fp2_value_type t1 = square<fp2_type>(A1);
                    const fp2_value_type t2 = square<fp2_type>(A2);
                    const fp2_value_type t3 = mul<fp2_type>(A0, A1);
                    const fp2_value_type t4 = mul<fp2_type>(A0, A2);
                    const fp2_value_type t5 = mul<fp2_type>(A1, A2);
                    const fp2_value_type c0 = sub<fp2_type>(t0, mul_by_non_residue(t5));
                    const fp2_value_type c1 = sub<fp2_type>(mul_by_non_residue(t2), t3);
                    const fp2_value_type c2 = sub<fp2_type>(t1, t4); // according to libff, there is a typo in paper referenced above. should be "-" as per Scott, but is "*"
                    const fp2_value_type t6 = invert<fp2_type>( add<fp2_type>(mul<fp2_type>(A0, c0), mul_by_non_residue(add<fp2_type>(mul<fp2_type>(A2, c1), mul<fp2_type>(A1, c2)))));
                    return {mul<fp2_type>(t6, c0), mul<fp2_type>(t6, c1), mul<fp2_type>(t6, c2)};

                }

            private:
                inline static fp2_value_type mul_by_non_residue(const fp2_value_type &A){
                    return mul<fp2_type>(non_residue, A)};
                }
            }
        }    // namespace detail
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_ALGO_FP6_3OVER2_IMPL_HPP
