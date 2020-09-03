//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_FP6_3OVER2_DOUBLE_HPP
#define ALGEBRA_FIELDS_FP6_3OVER2_DOUBLE_HPP

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <nil/algebra/fields/fp.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                struct double_element_fp6_3over2 : public double_element<fp6_3over2<ModulusBits, GeneratorBits>> {

                    using underlying_type = double_element_fp2<ModulusBits, GeneratorBits>;

                    using value_type = std::array<underlying_type, 3>;

                    value_type data;

                    double_element_fp6_3over2(type data) : data(data);

                    inline static double_element_fp6_3over2 zero() const {
                        return {underlying_type::zero(), underlying_type::zero(), underlying_type::zero()};
                    }

                    bool operator==(const double_element_fp6_3over2 &B) const {
                        return (data[0] == B.data[0]) && (data[1] == B.data[1]) && (data[2] == B.data[2]);
                    }

                    bool operator!=(const double_element_fp6_3over2 &B) const {
                        return (data[0] != B.data[0]) || (data[1] != B.data[1]) || (data[2] != B.data[2]);
                    }

                    double_element_fp6_3over2 operator+(const double_element_fp6_3over2 &B) const {
                        return {data[0] + B.data[0], data[1] + B.data[1], data[2] + B.data[2]};
                    }

                    double_element_fp6_3over2 operator-(const double_element_fp6_3over2 &B) const {
                        return {data[0] - B.data[0], data[1] - B.data[1], data[2] - B.data[2]};
                    }

                    double_element_fp6_3over2 operator-() const {
                        return zero() - data;
                    }

                    // data + data
                    double_element_fp6_3over2 dbl() const {
                        return {data[0].dbl(), data[1].dbl(), data[2].dbl()};
                    }

                    double_element_fp6_3over2 addNC(const double_element_fp6_3over2 &B) {
                        return {addNC(data[0] + B.data[0]), addNC(data[1] + B.data[1]), addNC(data[2] + B.data[2])};
                    }

                    double_element_fp6_3over2 subNC(const double_element_fp6_3over2 &B) {
                        return {subNC(data[0] + B.data[0]), subNC(data[1] + B.data[1]), subNC(data[2] + B.data[2])};
                    }

                    element_fp6_3over2 mod() {
                        return {data[0].mod(), data[1].mod(), B.data[2].mod()};
                    }
                };

                double_element_fp6_3over2 mul(const element<fp6_3over2> &A, const element<fp6_3over2> &B) {
                    Fp2 t0, t1;
                    Fp2Dbl T0, T1, T2;
                    // # 1
                    T0 = mulOpt1(x.a_, y.a_);
                    T1 = mulOpt1(x.b_, y.b_);
                    T2 = mulOpt1(x.c_, y.c_);
                    // # 2
                    t0 = addNC(x.b_, x.c_);
                    t1 = addNC(y.b_, y.c_);
                    // # 3
                    z.c_ = mulOpt2(t0, t1);
                    // # 4
                    z.b_ = addNC(T1, T2);
                    // # 5
                    z.c_.a_ = z.c_.a_ - z.b_.a_;
                    // # 6
                    z.c_.b_ = subNC(z.c_.b_, z.b_.b_);
                    // # 7
                    z.b_ = z.c_.mul_xi();
                    // # 8
                    z.a_ = z.b_ + T0;
                    // # 9
                    t0 = addNC(x.a_, x.b_);
                    t1 = addNC(y.a_, y.b_);
                    // # 10
                    z.c_ = mulOpt2(t0, t1);
                    // # 11
                    z.b_ = addNC(T0, T1);
                    // # 12
                    z.c_.a_ = z.c_.a_ - z.b_.a_;
                    // # 13
                    z.c_.b_ = subNC(z.c_.b_, z.b_.b_);
                    /// c1 except xi * t2 term
                    // # 14, 15
                    z.b_ = T2.mul_xi();    // store xi * t2 term
                    // # 16
                    z.b_ = z.b_ + z.c_;
                    // # 17
                    t0 = addNC(x.a_, x.c_);
                    t1 = addNC(y.a_, y.c_);
                    // # 18
                    z.c_ = mulOpt2(t0, t1);
                    // # 19
                    T2 = addNC(T2, T0);
                    // # 20
                    z.c_.a_ = z.c_.a_ - T2.a_;
                    // # 22
                    z.c_.a_ = z.c_.a_ + T1.a_;
                    // # 21
                    z.c_.b_ = subNC(z.c_.b_, T2.b_);
                    // # 23
                    z.c_.b_ = addNC(z.c_.b_, T1.b_);
                }

                /*
                    Algorithm 11 in App.B of Aranha et al. ePrint 2010/526

                    NOTE:
                    The original version uses precomputed and stored value of -P[1].
                    But, we do not use that, this algorithm always calculates it.

                    input P[0..2], R[0..2]
                    R <- [2]R,
                    (l00, 0, l02, 0, l11, 0) = f_{R,R}(P),
                    l = (a,b,c) = (l00, l11, l02)
                    where P[2] == 1
                */
                double_element_fp6_3over2 pointDblLineEvalWithoutP(element_fp2 *R) {
                    element_fp2 t0, t1, t2, t3, t4, t5;
                    double_element_fp2 T0, T1, T2;
                    // X1, Y1, Z1 == R[0], R[1], R[2]
                    // xp, yp = P[0], P[1]

                    // # 1
                    t0 = R[2].square();
                    t4 = R[0] * R[1];
                    t1 = R[1].square();
                    // # 2
                    t3 = t0.dbl();
                    t4 = t4.divBy2();
                    t5 = t0 + t1;
                    // # 3
                    t0 += t3;
                    // # 4

                    if (ParamT<Fp2>::b == 82) {
                        // (a + bu) * (9 - u) = (9a + b) + (9b - a)u
                        t3.a_ = t0.b_;
                        t3.b_ = t0.a_;
                        t0 = t3.mul_xi();
                        t2.a_ = t0.b_;
                        t2.b_ = t0.a_;
                    } else {
                        // (a + bu) * binv_xi
                        t2 = t0 * ParamT<Fp2>::b_invxi;
                    }
                    // # 5
                    t0 = R[0].square();
                    t3 = t2.dbl();
                    // ## 6
                    t3 += t2;
                    l.c_ = addNC(t0, t0);
                    // ## 7
                    R[0] = t1 - t3;
                    l.c_ = addNC(l.c_, t0);
                    t3 += t1;
                    // # 8
                    R[0] *= t4;
                    t3 = t3.divBy2();
                    // ## 9
                    T0 = t3.square();
                    T1 = t2.square();
                    // # 10
                    T2 = addNC(T1, T1);
                    t3 = R[1] + R[2];
                    // # 11
                    T2 = T2 + T1;

                    t3 = t3.square();
                    // # 12
                    t3 -= t5;
                    // # 13
                    T0 -= T2;
                    // # 14
                    R[1] = T0.mod();
                    R[2] = t1 * t3;
                    t2 -= t1;
                    // # 15
                    l.a_ = t2.mul_xi();
                    l.b_ = -t3;
                }

                double_element_fp6_3over2 pointDblLineEval(element_fp2 *R, element_fp2 *P) {
                    return pointDblLineEvalWithoutP(R).mulFp6_24_Fp_01(P);
                }

                /*
                    Algorithm 12 in App.B of Aranha et al. ePrint 2010/526

                    input : P[0..1], Q[0..1], R[0..2]
                    R <- R + Q
                    (l00, 0, l02, 0, l11, 0) = f_{R,Q}(P),
                    l = (a,b,c) = (l00, l11, l02)
                    where Q[2] == 1, and P[2] == 1
                */
                double_element_fp6_3over2 pointAddLineEvalWithoutP(element_fp2 *R, const element_fp2 *Q) {
                    element_fp2 t1, t2, t3, t4;
                    double_element_fp2 T1, T2;
                    // # 1
                    t1 = R[2] * Q[0];
                    t2 = R[2] * Q[1];
                    // # 2
                    t1 = R[0] - t1;
                    t2 = R[1] - t2;
                    // # 3
                    t3 = t1.square();
                    // # 4
                    R[0] = t3 * R[0];
                    t4 = t2.square();
                    // # 5
                    t3 *= t1;
                    t4 *= R[2];
                    // # 6
                    t4 += t3;
                    // # 7
                    t4 -= R[0];
                    // # 8
                    t4 -= R[0];
                    // # 9
                    R[0] -= t4;
                    // # 10
                    T1 = mulOpt1(t2, R[0]);
                    T2 = mulOpt1(t3, R[1]);
                    // # 11
                    T2 = T1 - T2;
                    // # 12
                    R[1] = T2.mod();
                    R[0] = t1 * t4;
                    R[2] = t3 * R[2];
                    // # 14
                    l.c_ = -t2;
                    // # 15
                    T1 = mulOpt1(t2, Q[0]);
                    T2 = mulOpt1(t1, Q[1]);
                    // # 16
                    T1 = T1 - T2;
                    // # 17
                    t2 = T1.mod();
                    // ### @note: Be careful, below fomulas are typo.
                    // # 18
                    l.a_ = t2.mul_xi();
                    l.b_ = t1;
                }

                double_element_fp6_3over2 pointAddLineEval(element_fp2 *R, const element_fp2 *Q, const element<fp> *P) {
                    return pointAddLineEvalWithoutP(R, Q).mulFp6_24_Fp_01(P);
                }

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP6_3OVER2_DOUBLE_HPP
