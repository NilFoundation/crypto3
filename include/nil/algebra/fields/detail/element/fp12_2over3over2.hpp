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
                struct element_fp12_2over3over2{
                private:
                    typedef FieldParams policy_type;
                public:
                    static const typename policy_type::fp12_2over3over2_non_residue_type 
                        non_residue = policy_type::fp12_2over3over2_non_residue_type(policy_type::fp12_2over3over2_non_residue);

                    using underlying_type = element_fp6_3over2<FieldParams>;

                    using value_type = std::array<underlying_type, 2>;

                    value_type data;

                    element_fp6_3over2(value_type data) : data(data) {};

                    inline static element_fp6_3over2 zero() {
                        return {underlying_type::zero(), underlying_type::zero()};
                    }

                    inline static element_fp6_3over2 one() {
                        return {underlying_type::one(), underlying_type::zero()};
                    }

                    bool operator==(const element_fp6_3over2 &B) const {
                        return (data[0] == B.data[0]) && (data[1] == B.data[1]);
                    }

                    bool operator!=(const element_fp6_3over2 &B) const {
                        return (data[0] != B.data[0]) || (data[1] != B.data[1]);
                    }

                    element_fp12_2over3over2& operator=(const element_fp12_2over3over2 &B) {
                        data[0] = B.data[0];
                        data[1] = B.data[1];

                        return *this;
                    }

                    element_fp6_3over2 operator+(const element_fp6_3over2 &B) const {
                        return {data[0] + B.data[0], data[1] + B.data[1]};
                    }

                    element_fp6_3over2 operator-(const element_fp6_3over2 &B) const {
                        return {data[0] - B.data[0], data[1] - B.data[1]};
                    }

                    element_fp6_3over2 operator-() const {
                        return zero()-data;
                    }
                    
                    element_fp6_3over2 operator*(const element_fp6_3over2 &B) const {
                        const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1];

                        return {A0B0 + mul_by_non_residue(A1B1), (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 - A1B1};
                    }

                    element_fp6_3over2 sqrt() const {

                        // compute square root with Tonelli--Shanks
                    }

                    element_fp6_3over2 square() const {
                        return data*data;    // maybe can be done more effective
                    }

                    template <typename PowerType>
                    element_fp6_3over2 pow(const PowerType &power) const {
                        return power(data, power);
                    }

                    element_fp6_3over2 inverse() const {

                        /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves";
                         * Algorithm 8 */

                        const underlying_type &A0 = data[0], &A1 = data[1];
                        
                        const underlying_type t0 = A0.square();
                        const underlying_type t1 = A1.square();
                        const underlying_type t2 = t0 - mul_by_non_residue(t1);
                        const underlying_type t3 = t2.inverse();
                        const underlying_type c0 = A0 * t3;
                        const underlying_type c1 = -(A1 * t3);

                        return {c0, c1};

                    }


                    element_fp6_3over2 sqru() {
                        element<fp2> &z0(a_.a_);
                        element<fp2> &z4(a_.b_);
                        element<fp2> &z3(a_.c_);
                        element<fp2> &z2(b_.a_);
                        element<fp2> &z1(b_.b_);
                        element<fp2> &z5(b_.c_);
                        element<fp4> t0t1;
                        element<fp2> t0 = t0t1.data[0], t1 = t0t1.data[1];

                        t0t1 = sq_Fp4UseDbl({z0, z1});    // a^2 = t0 + t1*y
                        // For A
                        z0 = t0 - z0;
                        z0 += z0;
                        z0 += t0;

                        z1 = (t1 + z1).dbl() + t1;

                        // t0 and t1 are unnecessary from here.
                        Fp2 t2, t3;
                        t0t1 = sq_Fp4UseDbl({z2, z3});    // b^2 = t0 + t1*y
                        t0t1 = sq_Fp4UseDbl({z4, z5});    // c^2 = t2 + t3*y
                        // For C
                        z4 = (t0 - z4).dbl() + t0;

                        z5 = (t1 + z5).dbl() + t1;

                        // For B
                        t0 = t3.mul_xi();

                        z2 = (t0 + z2).dbl() + t0;

                        z3 = (t2 - z3).dbl() + t2;
                    }

                private:
                    inline static underlying_type mul_by_non_residue(const underlying_type &A){
                        return {non_residue * A.data[2], A.data[1], A.data[0]};
                    }
                };

                /*
                    (a + bw) -> (a - bw) gammar
                */
                element<fp12_2over3over2> Frobenius(element<fp12_2over3over2> A) {
                    /* this assumes (q-1)/6 is odd */
                
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
                }

                /*
                    gammar = c + dw
                    a + bw -> t = (a - bw)(c + dw)
                    ~t = (a + bw)(c - dw)
                    ~t * (c + dw) = (a + bw) * ((c + dw)(c - dw))
                    gammar2 = (c + dw)(c - dw) in Fp6
                */
                element<fp12_2over3over2> Frobenius2(element<fp12_2over3over2> A) {

                    
                    z.a_.a_ = A.a_.a_;
                    
                    z.a_.a_ = A.a_.a_;
                    z.a_.b_ = A.a_.b_.mul_Fp_0(Param::gammar2[1].a_);
                    z.a_.c_ = A.a_.c_.mul_Fp_0(Param::gammar2[3].a_);
                    z.b_.a_ = A.b_.a_.mul_Fp_0(Param::gammar2[0].a_);
                    z.b_.b_ = A.b_.b_.mul_Fp_0(Param::gammar2[2].a_);
                    z.b_.c_ = A.b_.c_.mul_Fp_0(Param::gammar2[4].a_);
                }

                element<fp12_2over3over2> Frobenius3(element<fp12_2over3over2> A) {
                    z.a_.a_.a_ =  A.a_.a_.a_;
                    z.a_.b_.a_ =  A.a_.b_.a_;
                    z.a_.c_.a_ =  A.a_.c_.a_;
                    z.b_.a_.a_ =  A.b_.a_.a_;
                    z.b_.b_.a_ =  A.b_.b_.a_;
                    z.b_.c_.a_ =  A.b_.c_.a_;

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
                }
                
            }   // namespace detail
        }   // namespace fields
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_ELEMENT_FP12_2OVER3OVER2_HPP
