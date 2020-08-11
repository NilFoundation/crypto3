//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_FP6_3OVER2_DOUBLE_HPP
#define ALGEBRA_FF_FP6_3OVER2_DOUBLE_HPP

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <nil/algebra/fields/fp.hpp>

namespace nil {
    namespace algebra {
        namespace detail {

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct double_element<fp6_3over2<ModulusBits, GeneratorBits>> {

                typedef arithmetic_params<fp6_3over2<ModulusBits, GeneratorBits>> params_type;

                typedef params_type::double_number_type number_type;

            private:
                using value_type = double_element<fp6_3over2<ModulusBits, GeneratorBits>>;

                number_type data;

            public:

                value_type(type data) : data(data);

                    
                inline static value_type zero() const {
                    return {underlying_type::zero(), underlying_type::zero(), underlying_type::zero()};
                }

                bool operator==(const value_type &B) const {
                    return (data[0] == B.data[0]) && (data[1] == B.data[1]) && (data[2] == B.data[2]);
                }

                bool operator!=(const value_type &B) const {
                    return (data[0] != B.data[0]) || (data[1] != B.data[1]) || (data[2] != B.data[2]);
                }

                value_type operator+(const value_type &B) const {
                    return {data[0] + B.data[0], data[1] + B.data[1], data[2] + B.data[2]};
                }

                value_type operator-(const value_type &B) const {
                    return {data[0] - B.data[0], data[1] - B.data[1], data[2] - B.data[2]};
                }

                value_type operator-() const {
                    return zero()-data;
                }
                
                //data + data
                value_type dbl() const {
                    return {data[0].dbl(), data[1].dbl(), data[2].dbl()};
                }

                value_type addNC(const value_type &B){
                    return {addNC(data[0] + B.data[0]), addNC(data[1] + B.data[1]), addNC(data[2] + B.data[2])};
                }

                value_type subNC(const value_type &B){
                    return {subNC(data[0] + B.data[0]), subNC(data[1] + B.data[1]), subNC(data[2] + B.data[2])};
                }

                element_type<fp6_3over2> mod(){
                    return {data[0].mod(), data[1].mod(), B.data[2].mod()};
                }
            };

            double_element_type<fp6_3over2> mul(const element_type<fp6_3over2> &A, const element_type<fp6_3over2> &B) {
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
                z.c_.a_ = z.c_.a_- T2.a_;
                // # 22
                z.c_.a_ = z.c_.a_ + T1.a_;
                // # 21
                z.c_.b_ = subNC(z.c_.b_, T2.b_);
                // # 23
                z.c_.b_ = addNC(z.c_.b_, T1.b_);
            }

        }    // namespace detail
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP6_3OVER2_DOUBLE_HPP
