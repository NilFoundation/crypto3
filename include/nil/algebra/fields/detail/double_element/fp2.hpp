//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_FP2_DOUBLE_HPP
#define ALGEBRA_FF_FP2_DOUBLE_HPP

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <nil/algebra/fields/fp.hpp>

namespace nil {
    namespace algebra {
        namespace detail {

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct double_element<fp2<ModulusBits, GeneratorBits>> {

                typedef arithmetic_params<fp2<ModulusBits, GeneratorBits>> params_type;

                typedef params_type::double_number_type number_type;

            private:
                using value_type = double_element<fp2<ModulusBits, GeneratorBits>>;

                number_type data;

            public:

                value_type(type data) : data(data);

                inline static value_type zero() const {
                    return {underlying_type::zero(), underlying_type::zero()};
                }

                bool is_zero() const {
                    return (data[0] == underlying_type::zero()) && (data[1] == underlying_type::zero());
                }

                bool operator==(const value_type &B) const {
                    return (data[0] == B.data[0]) && (data[1] == B.data[1]);
                }

                bool operator!=(const value_type &B) const {
                    return (data[0] != B.data[0]) || (data[1] != B.data[1]);
                }

                value_type operator+(const value_type &B) const {
                    return {data[0] + B.data[0], data[1] + B.data[1]};
                }

                value_type operator-(const value_type &B) const {
                    return {data[0] - B.data[0], data[1] - B.data[1]};
                }

                value_type operator-() const {
                    return zero()-data;
                }

                //data + data
                value_type dbl() const {
                    return {data[0].dbl(), data[1].dbl()};
                }

                value_type subOpt1() const {
                    return {mod(data[0]), mod(data[1])};
                }

                /*
                    XITAG
                    u^2 = -1
                    xi = 9 + u
                    (a + bu)(9 + u) = (9a - b) + (a + 9b)u
                */
                value_type mul_xi() {
                    return {data[0].dbl().dbl().dbl() + data[0] - data[1], data[1].dbl().dbl().dbl() + data[1] + data[0]};
                }

                element_type<fp2> mod(){
                    return {data[0].mod(), data[1].mod()};
                }

            };

            double_element_type<fp2> addNC(const double_element_type<fp2> &A, const double_element_type<fp2> &B){
                return {addNC(data[0] + B.data[0]), addNC(data[1] + B.data[1])};
            }

            double_element_type<fp2> subNC(const double_element_type<fp2> &A, const double_element_type<fp2> &B){
                return {subNC(data[0] + B.data[0]), subNC(data[1] + B.data[1])};
            }

            double_element_type<fp2> mulOpt(const element_type<fp2> &A, const element_type<fp2> &B, int mode) {
                double_element_type<fp> d0;
                double_element_type<fp2> z;
                element_type<fp> s, t;

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
                    z.data[0] = z.data[0] -  d0;
                }
            }

            double_element_type<fp2> mulOpt1(const element_type<fp2> &A, const element_type<fp2> &B) {
                return mulOpt(A, B, 1);
            }

            double_element_type<fp2> mulOpt2(const element_type<fp2> &A, const element_type<fp2> &B) {
                return mulOpt(A, B, 2);
            }

            double_element_type<fp2> square(const element_type<fp2> &B){
                element_type<fp>  t0, t1;
                t0 = addNC(x.b_, x.b_);
                z.b_ = mul(t0, x.a_);
                t1 = addNC(x.a_, Fp::getDirectP(1)); // RRR
                t1 = subNC(t1, x.b_);
                t0 = addNC(x.a_, x.b_);
                z.a_ = mul(t0, t1);
            }
        }    // namespace detail
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP2_DOUBLE_HPP
