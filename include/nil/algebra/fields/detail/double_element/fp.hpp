//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_FP_DOUBLE_HPP
#define ALGEBRA_FIELDS_FP_DOUBLE_HPP

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
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

                    //data + data
                    value_type dbl() const {
                        return data + data;
                    }

                    value_type subOpt1() const {
                        
                    }

                    double_element<fp> mod(){
                        
                    }
                };

                double_element<fp> addNC(const double_element<fp> &A, const double_element<fp> &B){
                    return {addNC(data[0] + B.data[0]), addNC(data[1] + B.data[1])};
                }

                double_element<fp> subNC(const double_element<fp> &A, const double_element<fp> &B){
                    return {subNC(data[0] + B.data[0]), subNC(data[1] + B.data[1])};
                }

                double_element<fp> mul(const element<fp> &A, const element<fp> &B) {
                    
                }

                double_element<fp> square(const element<fp> &B){
                {
                    element<fp> t0, t1;
                    t0 = addNC(x.b_, x.b_);
                    z.b_ = mul(t0, x.a_);
                    t1 = addNC(x.a_, Fp::getDirectP(1)); // RRR
                    t1 = subNC(t1, x.b_);
                    t0 = addNC(x.a_, x.b_);
                    z.a_ = mul(t0, t1);
                }

            }    // namespace detail
        }   // namespace fields
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_FP_DOUBLE_HPP
