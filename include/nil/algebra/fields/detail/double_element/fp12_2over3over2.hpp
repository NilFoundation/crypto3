//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FILEDS_FP12_2OVER3OVER2_DOUBLE_HPP
#define ALGEBRA_FILEDS_FP12_2OVER3OVER2_DOUBLE_HPP

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <nil/algebra/fields/fp.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                struct double_element_fp12_2over3over2
                    : public double_element<fp12_2over3over2<ModulusBits, GeneratorBits>> {

                    using underlying_type = double_element_fp6_3over2<ModulusBits, GeneratorBits>;

                    using value_type = std::array<underlying_type, 2>;

                    value_type data;

                    double_element_fp12_2over3over2(type data) : data(data);

                    inline static double_element_fp12_2over3over2 zero() const {
                        return {underlying_type::zero(), underlying_type::zero()};
                    }

                    bool operator==(const double_element_fp12_2over3over2 &B) const {
                        return (data[0] == B.data[0]) && (data[1] == B.data[1]);
                    }

                    bool operator!=(const double_element_fp12_2over3over2 &B) const {
                        return (data[0] != B.data[0]) || (data[1] != B.data[1]);
                    }

                    double_element_fp12_2over3over2 operator+(const double_element_fp12_2over3over2 &B) const {
                        return {data[0] + B.data[0], data[1] + B.data[1]};
                    }

                    double_element_fp12_2over3over2 operator-(const double_element_fp12_2over3over2 &B) const {
                        return {data[0] - B.data[0], data[1] - B.data[1]};
                    }

                    double_element_fp12_2over3over2 operator-() const {
                        return zero() - data;
                    }

                    // data + data
                    double_element_fp12_2over3over2 dbl() const {
                        return {data[0].dbl(), data[1].dbl()};
                    }

                    double_element_fp12_2over3over2 addNC(const double_element_fp12_2over3over2 &B) {
                        return {addNC(data[0] + B.data[0]), addNC(data[1] + B.data[1])};
                    }

                    double_element_fp12_2over3over2 subNC(const double_element_fp12_2over3over2 &B) {
                        return {subNC(data[0] + B.data[0]), subNC(data[1] + B.data[1])};
                    }

                    element<fp12_2over3over2> mod() {
                        return {data[0].mod(), data[1].mod()};
                    }
                };

                double_element_fp12_2over3over2 mul(const element<fp12_2over3over2> &A,
                                                    const element<fp12_2over3over2> &B) {
                }

                /*
                    z *= x,
                    position: 0   1   2      3   4   5
                        x = (l00, 0, l02) + (0, l11, 0)*w
                    x is represented as:
                    (x.a_, x.b_, x.c_) = (l00, l11, l02)
                    4800clk * 66
                */
                /*
                    Operation Count:

                    13 * Fp2Dbl::mulOpt2
                    6  * Fp2Dbl::mod
                    10 * Fp2::add/sub
                    19 * Fp2Dbl::add/sub == 19 * (2 * Fp2::add/sub) == 38 * Fp2::add/sub
                    4  * Fp2Dbl::mul_xi  == 4  * (2 * Fp2::add/sub) == 8  * Fp2::add/sub

                    Total:

                    13 * Fp2Dbl::mulOpt2
                    6  * Fp2Dbl::mod
                    56 * Fp2::add/sub
                */
                double_element_fp12_2over3over2 mul_Fp2_024(const element_fp6_3over2 &B) {
                    element<fp2> &z0 = z.a_.a_;
                    element<fp2> &z1 = z.a_.b_;
                    element<fp2> &z2 = z.a_.c_;
                    element<fp2> &z3 = z.b_.a_;
                    element<fp2> &z4 = z.b_.b_;
                    element<fp2> &z5 = z.b_.c_;
                    const element<fp2> &x0 = x.a_;
                    const element<fp2> &x2 = x.c_;
                    const element<fp2> &x4 = x.b_;
                    element<fp2> t0, t1, t2;
                    element<fp2> s0;

                    double_element<fp2> T3, T4;
                    double_element<fp2> D0, D2, D4;
                    double_element<fp2> S1;

                    D0 = mulOpt2(z0, x0);
                    D2 = mulOpt2(z2, x2);
                    D4 = mulOpt2(z4, x4);

                    t2 = z0 + z4;
                    t1 = z0 + z2;
                    s0 = z1 + z3 + z5;
                    // For z.a_.a_ = z0.
                    S1 = mulOpt2(z1, x2);
                    T4 = (S1 + D4).mul_xi() + D0;
                    z0 = T4.mod();
                    // For z.a_.b_ = z1.
                    T3 = mulOpt2(z5, x4);
                    S1 += T3;
                    T3 += D2;
                    T4 = T3.mul_xi();
                    T3 = mulOpt2(z1, x0);
                    S1 += T3;
                    T4 += T3;
                    z1 = T4.mod();
                    // For z.a_.c_ = z2.
                    t0 = x0 + x2;
                    T3 = mulOpt2(t1, t0) - D0 - D2;
                    T4 = mulOpt2(z3, x4);
                    S1 += T4;
                    T3 += T4;
                    // z3 needs z2.
                    // For z.b_.a_ = z3.
                    t0 = z2 + z4;
                    z2 = T3.mod();
                    t1 = x2 + x4;
                    T3 = mulOpt2(t0, t1) - D2 - D4;
                    T4 = T3.mul_xi();
                    T3 = mulOpt2(z3, x0);
                    S1 += T3;
                    T4 += T3;
                    z3 = T4.mod();
                    // For z.b_.b_ = z4.
                    T3 = mulOpt2(z5, x2);
                    S1 += T3;
                    T4 = T3.mul_xi() + mulOpt2(t2, x0 + x4) - D0 - D4;
                    z4 = T4.mod();
                    // For z.b_.c_ = z5.
                    z5 = (mulOpt2(s0, x0 + x2 + x4) - S1).mod();
                }

                /*
                    z = cv2 * cv3,
                    position:0  1   2      3   4   5
                    cv2 = (l00, 0, l02) + (0, l11, 0)*w
                    cv3 = (l00, 0, l02) + (0, l11, 0)*w
                    these are represented as:
                    (cv*.a_, cv*.b_, cv*.c_) = (l00, l11, l02)
                */
                /*
                    Operation Count:

                    6  * Fp2Dbl::mulOpt2
                    5  * Fp2Dbl::mod
                    6  * Fp2::add/sub
                    7  * Fp2Dbl::add/sub == 7 * (2 * Fp2::add/sub) == 14 * Fp2::add/sub
                    3  * Fp2Dbl::mul_xi == 3 * (2 * Fp2::add/sub)  == 6  * Fp2::add/sub

                    Total:

                    6  * Fp2Dbl::mulOpt2
                    5  * Fp2Dbl::mod
                    26 * Fp2::add/sub
                    call:2
                */
                double_element_fp12_2over3over2 mul_Fp2_024_Fp2_024(const element_fp6_3over2 &B1,
                                                                    const element_fp6_3over2 &B2) {
                    element<fp2> &z0 = z.a_.a_;
                    element<fp2> &z1 = z.a_.b_;
                    element<fp2> &z2 = z.a_.c_;
                    element<fp2> &z3 = z.b_.a_;
                    element<fp2> &z4 = z.b_.b_;
                    element<fp2> &z5 = z.b_.c_;
                    const element<fp2> &x0 = cv2.a_;
                    const element<fp2> &x2 = cv2.c_;
                    const element<fp2> &x4 = cv2.b_;
                    const element<fp2> &y0 = cv3.a_;
                    const element<fp2> &y2 = cv3.c_;
                    const element<fp2> &y4 = cv3.b_;
                    double_element<fp2> T00, T22, T44, T02, T24, T40;

                    T00 = mulOpt2(x0, y0);
                    T22 = mulOpt2(x2, y2);
                    T44 = mulOpt2(x4, y4);
                    z0 = x0 + x2;
                    z1 = y0 + y2;
                    T02 = mulOpt2(z0, z1);
                    T02 -= T00;
                    T02 -= T22;
                    z2 = T02.mod();
                    z0 = x2 + x4;
                    z1 = y2 + y4;
                    T24 = mulOpt2(z0, z1);
                    T24 -= T22;
                    T24 -= T44;
                    T02 = T24.mul_xi();
                    z3 = T02.mod();
                    z0 = x4 + x0;
                    z1 = y4 + y0;
                    T40 = mulOpt2(z0, z1);
                    T40 -= T00;
                    T40 -= T44;
                    z4 = T40.mod();
                    T02 = T22.mul_xi();
                    z1 = T02.mod();
                    T02 = T44.mul_xi();
                    T02 += T00;
                    z0 = T02.mod();
                    z5.clear();
                }

                /*
                    square over Fp4
                    Operation Count:

                    3 * Fp2Dbl::square
                    2 * Fp2Dbl::mod
                    1 * Fp2Dbl::mul_xi == 1 * (2 * Fp2::add/sub) == 2 * Fp2::add/sub
                    3 * Fp2Dbl::add/sub == 3 * (2 * Fp2::add/sub) == 6 * Fp2::add/sub
                    1 * Fp2::add/sub

                    Total:

                    3 * Fp2Dbl::square
                    2 * Fp2Dbl::mod
                    9 * Fp2::add/sub
                 */
                static inline void sq_Fp4UseDbl(Fp2 &z0, Fp2 &z1, const Fp2 &x0, const Fp2 &x1) {
                    Fp2Dbl T0, T1, T2;
                    Fp2Dbl::square(T0, x0);
                    Fp2Dbl::square(T1, x1);
                    Fp2Dbl::mul_xi(T2, T1);
                    T2 += T0;
                    z1 = x0 + x1;
                    Fp2Dbl::mod(z0, T2);
                    // overwrite z[0] (position 0).
                    Fp2Dbl::square(T2, z1);
                    T2 -= T0;
                    T2 -= T1;
                    Fp2Dbl::mod(z1, T2);
                }

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FILEDS_FP12_2OVER3OVER2_DOUBLE_HPP
