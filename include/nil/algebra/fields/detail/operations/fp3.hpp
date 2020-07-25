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
#include <nil/algebra/fields/fp2.hpp>
#include <nil/algebra/fields/detail/operations/operations.hpp>

namespace nil {
    namespace algebra {
        namespace detail {

            template<typename NumberType &Modulus, typename NumberType>
            struct arithmetic_operations<fp3<Modulus>> {
            private:
                using policy_type = arithmetic_params<fp3<Modulus>>;
                using fp_type = fp<Modulus>;
                using point = detail::element<policy_type, NumberType>;

            public:
                inline static point zero() const {
                    return point(zero<fp_type, NumberType>()[0], zero<fp_type, NumberType>()[0]);
                }

                inline static point one() const {
                    return point(one<fp_type, NumberType>()[0], zero<fp_type, NumberType>()[0]);
                }

                inline static bool eq(const NumberType &A0, const NumberType &A1, const NumberType &B0,
                                      const NumberType &B1) const {
                    return (A0 == B0) && (A1 == B1);
                }

                inline static bool eq(const point &A, const point &B) const {
                    return (A[0] == B[0]) && (A[1] == B[1]);
                }

                inline static bool neq(const NumberType &A0, const NumberType &A1, const NumberType &B0,
                                       const NumberType &B1) const {
                    return (A0 != B0) || (A1 != B1);
                }

                inline static bool neq(const point &A, const point &B) const {
                    return (A[0] != B[0]) || (A[1] != B[1]);
                }

                inline static point add(const NumberType &A0, const NumberType &A1, const NumberType &B0,
                                        const NumberType &B1) const {
                    return point(A0 + B0, A1 + B1);
                }

                inline static point add(const point &A, const point &B) const {
                    return point(A[0] + B[0], A[1] + B[1]);
                }

                inline static point sub(const NumberType &A0, const NumberType &A1, const NumberType &B0,
                                        const NumberType &B1) const {
                    return point(A0 - B0, A1 - B1);
                }

                inline static point sub(const point &A, const point &B) const {
                    return point(A[0] - B[0], A[1] - B[1]);
                }

                inline static point mul(const NumberType &A0, const NumberType &A1, const NumberType &B0,
                                        const NumberType &B1) const {

                    const NumberType A0B0 = A0 * B0, A1B1 = A1 * B1;

                    return point(A0B0 + policy_type::non_residue, (A0 + A1) * (B0 + B1) - A0B0 - A1B1);
                }

                inline static point mul(const point &A, const point &B) const {
                    const NumberType A0B0 = A[0] * B[0], A1B1 = A[1] * B[1];

                    return point(A0B0 + policy_type::non_residue, (A[0] + A[1]) * (B[0] + B[1]) - A0B0 - A1B1);
                }

                inline static point sqrt(const NumberType &A0, const NumberType &B0) const {

                    // compute square root with Tonelli--Shanks
                }

                inline static point square(const NumberType &A0, const NumberType &A1) const {
                    return mul(A0, A1, A0, A1);    // maybe can be done more effective
                }

                inline static point square(const point &A) const {
                    return mul(A, A);    // maybe can be done more effective
                }

                inline static policy_type::policy_modular pow(const NumberType &A0, const NumberType &B0) const {
                }

                inline static policy_type::policy_modular invert(const NumberType &A0, const NumberType &B0) const {

                    // The following needs to be adapted to our concepts:

                    const my_Fp &a = this->c0, &b = this->c1;

                    /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves";
                     * Algorithm 8 */
                    const my_Fp t0 = a.squared();
                    const my_Fp t1 = b.squared();
                    const my_Fp t2 = t0 - non_residue * t1;
                    const my_Fp t3 = t2.inverse();
                    const my_Fp c0 = a * t3;
                    const my_Fp c1 = -(b * t3);

                    return Fp2_model<n, modulus>(c0, c1);

                    // compute square root with Tonelli--Shanks
                    // (does not terminate if not a square!)
                    return invert(policy_type::policy_modular(A, policy_type::mod));
                }
            }
            
        }    // namespace detail
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_ALGO_FP3_IMPL_HPP
