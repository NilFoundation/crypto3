//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_FP_DOUBLE_HPP
#define ALGEBRA_FF_FP_DOUBLE_HPP

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>

namespace nil {
    namespace algebra {
        namespace detail {

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct double_element<fp<ModulusBits, GeneratorBits>> {

                typedef arithmetic_params<fp<ModulusBits, GeneratorBits>> params_type;

                typedef params_type::double_number_type number_type;

            private:
                using value_type = double_element<fp<ModulusBits, GeneratorBits>>;

                number_type data;

            public:

                value_type(type data) : data(data);

                inline static value_type zero() const {
                    return value_type(type(0));
                }

                inline static value_type one() const {
                    return value_type(type(1));
                }

                bool is_zero() const {
                    return data == type(0);
                }

                bool is_one() const {
                    return data == type(1);
                }

                bool operator==(const value_type &B) const {
                    return data == B.data;
                }

                bool operator!=(const value_type &B) const {
                    return data != B.data;
                }

                value_type operator+(const value_type &B) const {
                    return data + B.data;
                }

                value_type operator-(const value_type &B) const {
                    return data - B.data;
                }

                value_type operator-() const {
                    return -data;
                }

                value_type operator*(const value_type &B) const {
                    return data * B.data;
                }

                //data + data
                value_type dbl() const {
                    return data.dbl();
                }

                value_type addNC(const value_type &A, const value_type &B){

                }

                value_type subNC(const value_type &A, const value_type &B){

                }

                value_type subOpt1() const {
                    
                }
            };

            double_element_type<fp> mul(const element_type<fp> &A, const element_type<fp> &B) {
                
            }

            double_element_type<fp> square(const element_type<fp> &B){
            {
                Fp t0, t1;
                Fp::addNC(t0, x.b_, x.b_);
                FpDbl::mul(z.b_, t0, x.a_);
                Fp::addNC(t1, x.a_, Fp::getDirectP(1)); // RRR
                Fp::subNC(t1, t1, x.b_);
                Fp::addNC(t0, x.a_, x.b_);
                FpDbl::mul(z.a_, t0, t1);
            }

            double_element_type<fp> mod(const element_type<fp> &B){
            {
                return {mod(B.data[0]), mod(B.data[1])};
            }
        }    // namespace detail
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP_DOUBLE_HPP
