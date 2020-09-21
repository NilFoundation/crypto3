//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_FP_DOUBLE_HPP
#define CRYPTO3_ALGEBRA_FIELDS_FP_DOUBLE_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    struct double_element_fp : public double_element<fp<ModulusBits, GeneratorBits>> {

                        typedef params_type::double_number_type number_type;

                        number_type data;

                        double_element_fp(number_type data) : data(data);

                        inline static double_element_fp zero() const {
                            return double_element_fp(type(0));
                        }

                        inline static double_element_fp one() const {
                            return double_element_fp(type(1));
                        }

                        bool is_zero() const {
                            return data == type(0);
                        }

                        bool is_one() const {
                            return data == type(1);
                        }

                        bool operator==(const double_element_fp &B) const {
                            return data == B.data;
                        }

                        bool operator!=(const double_element_fp &B) const {
                            return data != B.data;
                        }

                        double_element_fp operator+(const double_element_fp &B) const {
                            return data + B.data;
                        }

                        double_element_fp operator-(const double_element_fp &B) const {
                            return data - B.data;
                        }

                        double_element_fp operator-() const {
                            return -data;
                        }

                        // data + data
                        double_element_fp doubled() const {
                            return data + data;
                        }

                        double_element_fp subOpt1() const {
                        }

                        element_fp mod() {
                        }
                    };

                    double_element_fp addNC(const double_element_fp &A, const double_element_fp &B) {
                        return {addNC(data[0] + B.data[0]), addNC(data[1] + B.data[1])};
                    }

                    double_element_fp subNC(const double_element_fp &A, const double_element_fp &B) {
                        return {subNC(data[0] + B.data[0]), subNC(data[1] + B.data[1])};
                    }

                    double_element_fp mul(const element_fp &A, const element_fp &B) {
                    }

                    double_element_fp squared(const element_fp &B) {
                        {
                            element_fp t0, t1;
                            t0 = addNC(x.b_, x.b_);
                            z.b_ = mul(t0, x.a_);
                            t1 = addNC(x.a_, Fp::getDirectP(1));    // RRR
                            t1 = subNC(t1, x.b_);
                            t0 = addNC(x.a_, x.b_);
                            z.a_ = mul(t0, t1);
                        }
                    }
                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FIELDS_FP_DOUBLE_HPP
