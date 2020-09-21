//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FILEDS_FP2_DOUBLE_HPP
#define CRYPTO3_ALGEBRA_FILEDS_FP2_DOUBLE_HPP

#include <nil/crypto3/algebra/fields/fp.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    struct double_element_fp2 : public double_element<fp2<ModulusBits, GeneratorBits>> {

                        using underlying_type = double_element_fp<ModulusBits, GeneratorBits>;

                        using value_type = std::array<underlying_type, 2>;

                        value_type data;

                        double_element_fp2(type data) : data(data);

                        inline static double_element_fp2 zero() const {
                            return {underlying_type::zero(), underlying_type::zero()};
                        }

                        bool is_zero() const {
                            return (data[0] == underlying_type::zero()) && (data[1] == underlying_type::zero());
                        }

                        bool operator==(const double_element_fp2 &B) const {
                            return (data[0] == B.data[0]) && (data[1] == B.data[1]);
                        }

                        bool operator!=(const double_element_fp2 &B) const {
                            return (data[0] != B.data[0]) || (data[1] != B.data[1]);
                        }

                        double_element_fp2 operator+(const double_element_fp2 &B) const {
                            return {data[0] + B.data[0], data[1] + B.data[1]};
                        }

                        double_element_fp2 operator-(const double_element_fp2 &B) const {
                            return {data[0] - B.data[0], data[1] - B.data[1]};
                        }

                        double_element_fp2 operator-() const {
                            return zero() - data;
                        }

                        // data + data
                        double_element_fp2 doubled() const {
                            return {data[0].doubled(), data[1].doubled()};
                        }

                        double_element_fp2 subOpt1() const {
                            return {mod(data[0]), mod(data[1])};
                        }

                        /*
                            XITAG
                            u^2 = -1
                            xi = 9 + u
                            (a + bu)(9 + u) = (9a - b) + (a + 9b)u
                        */
                        double_element_fp2 mul_xi() {
                            return {data[0].doubled().doubled().doubled() + data[0] - data[1],
                                    data[1].doubled().doubled().doubled() + data[1] + data[0]};
                        }

                        element_fp2 mod() {
                            return {data[0].mod(), data[1].mod()};
                        }
                    };

                    double_element_fp2 addNC(const double_element_fp2 &A, const double_element_fp2 &B) {
                        return {addNC(data[0] + B.data[0]), addNC(data[1] + B.data[1])};
                    }

                    double_element_fp2 subNC(const double_element_fp2 &A, const double_element_fp2 &B) {
                        return {subNC(data[0] + B.data[0]), subNC(data[1] + B.data[1])};
                    }

                    double_element_fp2 mulOpt(const element_fp2 &A, const element_fp2 &B, int mode) {
                        double_element<fp> d0;
                        double_element_fp2 z;
                        element<fp> s, t;

                        s = addNC(A.data[0], A.data[1]);
                        t = addNC(B.data[0], B.data[1]);
                        d0 = mul(A.data[1], B.data[1]);

                        z.data[0] = mul(A.data[0], B.data[0]);

                        z.data[1] = mul(s, t);
                        z.data[1] = subNC(z.data[1], z.data[0]);
                        z.data[1] = subNC(z.data[1], d0);

                        if (mode == 1) {
                            z.data[0] = subOpt1(z.data[0], d0);

                        } else {
                            z.data[0] = z.data[0] - d0;
                        }
                    }

                    double_element_fp2 mulOpt1(const element_fp2 &A, const element_fp2 &B) {
                        return mulOpt(A, B, 1);
                    }

                    double_element_fp2 mulOpt2(const element_fp2 &A, const element_fp2 &B) {
                        return mulOpt(A, B, 2);
                    }

                    double_element_fp2 squared(const element_fp2 &B) {
                        element_fp t0, t1;
                        t0 = addNC(x.b_, x.b_);
                        z.b_ = mul(t0, x.a_);
                        t1 = addNC(x.a_, Fp::getDirectP(1));    // RRR
                        t1 = subNC(t1, x.b_);
                        t0 = addNC(x.a_, x.b_);
                        z.a_ = mul(t0, t1);
                    }

                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FILEDS_FP2_DOUBLE_HPP
