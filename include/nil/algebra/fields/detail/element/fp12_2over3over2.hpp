//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_ELEMENT_FP12_2OVER3OVER2_HPP
#define ALGEBRA_FIELDS_ELEMENT_FP12_2OVER3OVER2_HPP

#include <nil/algebra/fields/detail/element/fp6_3over2.hpp>
#include <nil/algebra/fields/detail/exponentiation.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<typename FieldParams>
                struct element_fp12_2over3over2 {
                private:
                    typedef FieldParams policy_type;

                public:
                    /*constexpr static*/ const typename policy_type::non_residue_type non_residue =
                        policy_type::non_residue_type(policy_type::non_residue);

                    using underlying_type = typename policy_type::underlying_type;

                    using value_type = std::array<underlying_type, 2>;

                    value_type data;

                    element_fp12_2over3over2(value_type data) : data(data) {};

                    inline static element_fp12_2over3over2 zero() {
                        return element_fp12_2over3over2({underlying_type::zero(), underlying_type::zero()});
                    }

                    inline static element_fp12_2over3over2 one() {
                        return element_fp12_2over3over2({underlying_type::one(), underlying_type::zero()});
                    }

                    bool operator==(const element_fp12_2over3over2 &B) const {
                        return (data[0] == B.data[0]) && (data[1] == B.data[1]);
                    }

                    bool operator!=(const element_fp12_2over3over2 &B) const {
                        return (data[0] != B.data[0]) || (data[1] != B.data[1]);
                    }

                    element_fp12_2over3over2 &operator=(const element_fp12_2over3over2 &B) {
                        data[0] = B.data[0];
                        data[1] = B.data[1];

                        return *this;
                    }

                    element_fp12_2over3over2 operator+(const element_fp12_2over3over2 &B) const {
                        return element_fp12_2over3over2({data[0] + B.data[0], data[1] + B.data[1]});
                    }

                    element_fp12_2over3over2 doubled() const {
                        return element_fp12_2over3over2({data[0].doubled(), data[1].doubled()});
                    }

                    element_fp12_2over3over2 operator-(const element_fp12_2over3over2 &B) const {
                        return element_fp12_2over3over2({data[0] - B.data[0], data[1] - B.data[1]});
                    }

                    element_fp12_2over3over2 &operator-=(const element_fp12_2over3over2 &B) {
                        data[0] -= B.data[0];
                        data[1] -= B.data[1];

                        return *this;
                    }

                    element_fp12_2over3over2 &operator+=(const element_fp12_2over3over2 &B) {
                        data[0] += B.data[0];
                        data[1] += B.data[1];

                        return *this;
                    }

                    element_fp12_2over3over2 operator-() const {
                        return zero() - *this;
                    }

                    element_fp12_2over3over2 operator*(const element_fp12_2over3over2 &B) const {
                        const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1];

                        return element_fp12_2over3over2({A0B0 + mul_by_non_residue(A1B1),
                                                         (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 - A1B1});
                    }

                    element_fp12_2over3over2 sqrt() const {

                        // compute squared root with Tonelli--Shanks
                    }

                    element_fp12_2over3over2 squared() const {

                        return (*this) * (*this);    // maybe can be done more effective
                    }

                    template<typename PowerType>
                    element_fp12_2over3over2 pow(const PowerType &pwr) const {
                        return element_fp12_2over3over2(power(*this, pwr));
                    }

                    element_fp12_2over3over2 inversed() const {

                        /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig
                         * Curves"; Algorithm 8 */

                        const underlying_type &A0 = data[0], &A1 = data[1];

                        const underlying_type t0 = A0.squared();
                        const underlying_type t1 = A1.squared();
                        const underlying_type t2 = t0 - mul_by_non_residue(t1);
                        const underlying_type t3 = t2.inversed();
                        const underlying_type c0 = A0 * t3;
                        const underlying_type c1 = -(A1 * t3);

                        return element_fp12_2over3over2({c0, c1});
                    }

                    template<typename PowerType>
                    element_fp12_2over3over2 Frobenius_map(const PowerType &pwr) const {
                        //return element_fp12_2over3over2({data[0].Frobenius_map(pwr),
                        //                                 policy_type::Frobenius_coeffs_c1[pwr % 12] * data[1].Frobenius_map(pwr)});
                        return element_fp12_2over3over2({data[0].Frobenius_map(pwr),
                                                         non_residue_type(policy_type::Frobenius_coeffs_c1[(pwr % 12) * 2], policy_type::Frobenius_coeffs_c1[(pwr % 12) * 2 + 1]) * data[1].Frobenius_map(pwr)});
                    }

                    /*element_fp12_2over3over2 sqru() {
                        element_fp2<FieldParams> &z0(a_.a_);
                        element_fp2<FieldParams> &z4(a_.b_);
                        element_fp2<FieldParams> &z3(a_.c_);
                        element_fp2<FieldParams> &z2(b_.a_);
                        element_fp2<FieldParams> &z1(b_.b_);
                        element_fp2<FieldParams> &z5(b_.c_);
                        element_fp4<FieldParams> t0t1;
                        element_fp2<FieldParams> t0 = t0t1.data[0], t1 = t0t1.data[1];

                        t0t1 = sq_Fp4UseDbl({z0, z1});    // a^2 = t0 + t1*y
                        // For A
                        z0 = t0 - z0;
                        z0 += z0;
                        z0 += t0;

                        z1 = (t1 + z1).doubled() + t1;

                        // t0 and t1 are unnecessary from here.
                        element_fp2 t2, t3;
                        t0t1 = sq_Fp4UseDbl({z2, z3});    // b^2 = t0 + t1*y
                        t0t1 = sq_Fp4UseDbl({z4, z5});    // c^2 = t2 + t3*y
                        // For C
                        z4 = (t0 - z4).doubled() + t0;

                        z5 = (t1 + z5).doubled() + t1;

                        // For B
                        t0 = t3.mul_xi();

                        z2 = (t0 + z2).doubled() + t0;

                        z3 = (t2 - z3).doubled() + t2;
                    }*/

                private:
                    /*inline static*/ underlying_type mul_by_non_residue(const underlying_type &A) {
                        return element_fp12_2over3over2({non_residue * A.data[2], A.data[1], A.data[0]});
                    }
                };

                /*
                    (a + bw) -> (a - bw) gammar
                */
                /*template <typename FieldParams>
                element_fp12_2over3over2<FieldParams> Frobenius(element_fp12_2over3over2<FieldParams> A) {
                    // this assumes (q-1)/6 is odd

                    z.a_.a_.a_ = A.a_.a_.a_;
                    z.a_.b_.a_ = A.a_.b_.a_;
                    z.a_.c_.a_ = A.a_.c_.a_;
                    z.b_.a_.a_ = A.b_.a_.a_;
                    z.b_.b_.a_ = A.b_.b_.a_;
                    z.b_.c_.a_ = A.b_.c_.a_;

                    z.a_.a_.b_ = -A.a_.a_.b_;
                    z.a_.b_.b_ = -A.a_.b_.b_;
                    z.a_.c_.b_ = -A.a_.c_.b_;
                    z.b_.a_.b_ = -A.b_.a_.b_;
                    z.b_.b_.b_ = -A.b_.b_.b_;
                    z.b_.c_.b_ = -A.b_.c_.b_;

                    z.a_.b_ *= Param::gammar[1];
                    z.a_.c_ *= Param::gammar[3];

                    z.b_.a_ *= Param::gammar[0];
                    z.b_.b_ *= Param::gammar[2];
                    z.b_.c_ *= Param::gammar[4];
                }*/

                /*
                    gammar = c + dw
                    a + bw -> t = (a - bw)(c + dw)
                    ~t = (a + bw)(c - dw)
                    ~t * (c + dw) = (a + bw) * ((c + dw)(c - dw))
                    gammar2 = (c + dw)(c - dw) in Fp6
                */
                /*template <typename FieldParams>
                element_fp12_2over3over2<FieldParams> Frobenius2(element_fp12_2over3over2<FieldParams> A) {

                    z.a_.a_ = A.a_.a_;

                    z.a_.a_ = A.a_.a_;
                    z.a_.b_ = A.a_.b_.mul_Fp_0(Param::gammar2[1].a_);
                    z.a_.c_ = A.a_.c_.mul_Fp_0(Param::gammar2[3].a_);
                    z.b_.a_ = A.b_.a_.mul_Fp_0(Param::gammar2[0].a_);
                    z.b_.b_ = A.b_.b_.mul_Fp_0(Param::gammar2[2].a_);
                    z.b_.c_ = A.b_.c_.mul_Fp_0(Param::gammar2[4].a_);
                }

                template <typename FieldParams>
                element_fp12_2over3over2<FieldParams> Frobenius3(element_fp12_2over3over2<FieldParams> A) {
                    z.a_.a_.a_ = A.a_.a_.a_;
                    z.a_.b_.a_ = A.a_.b_.a_;
                    z.a_.c_.a_ = A.a_.c_.a_;
                    z.b_.a_.a_ = A.b_.a_.a_;
                    z.b_.b_.a_ = A.b_.b_.a_;
                    z.b_.c_.a_ = A.b_.c_.a_;

                    z.a_.a_.b_ = -A.a_.a_.b_;
                    z.a_.b_.b_ = -A.a_.b_.b_;
                    z.a_.c_.b_ = -A.a_.c_.b_;
                    z.b_.a_.b_ = -A.b_.a_.b_;
                    z.b_.b_.b_ = -A.b_.b_.b_;
                    z.b_.c_.b_ = -A.b_.c_.b_;

                    z.a_.b_ *= Param::gammar3[1];
                    z.a_.c_ *= Param::gammar3[3];

                    z.b_.a_ *= Param::gammar3[0];
                    z.b_.b_ *= Param::gammar3[2];
                    z.b_.c_ *= Param::gammar3[4];
                }*/

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_ELEMENT_FP12_2OVER3OVER2_HPP
