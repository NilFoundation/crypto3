//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP_HPP
#define CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP_HPP

#include <iostream>

#include <nil/crypto3/algebra/fields/detail/exponentiation.hpp>
#include <nil/crypto3/algebra/fields/detail/element/operations.hpp>

#include <nil/crypto3/multiprecision/ressol.hpp>
#include <nil/crypto3/multiprecision/inverse.hpp>
#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>

#include <boost/type_traits/is_integral.hpp>

#include <type_traits>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {
                    template<typename FieldParams>
                    class element_fp {
                        typedef FieldParams policy_type;

                    public:
                        typedef typename policy_type::field_type field_type;

                        typedef typename policy_type::modular_type modular_type;
                        typedef typename policy_type::integral_type integral_type;
                        typedef typename policy_type::modular_backend modular_backend;
                        typedef typename policy_type::modular_params_type modular_params_type;

                        constexpr static const modular_params_type modulus_params = policy_type::modulus_params;
                        constexpr static const integral_type modulus = policy_type::modulus;

                        using data_type = modular_type;
                        data_type data;

                        constexpr element_fp() : data(data_type(0, modulus_params)) {};

                        constexpr element_fp(const data_type &data) : data(data) {};

                        template<typename Number,
                                 typename std::enable_if<(multiprecision::is_number<Number>::value &&
                                                          !multiprecision::is_modular_number<Number>::value) ||
                                                             std::is_integral<Number>::value,
                                                         bool>::type = true>
                        constexpr element_fp(const Number &data) : data(data, modulus_params) {};

                        constexpr element_fp(const element_fp &B)
                            : data(B.data) {
                        };

                        constexpr element_fp(const element_fp &&B) BOOST_NOEXCEPT
                            : data(std::move(B.data)) {
                        };

                        constexpr inline static element_fp zero() {
                            return element_fp(0);
                        }

                        constexpr inline static element_fp one() {
                            return element_fp(1);
                        }

                        constexpr bool is_zero() const {
                            return data == data_type(0, modulus_params);
                        }

                        constexpr bool is_one() const {
                            return data == data_type(1, modulus_params);
                        }

                        constexpr bool operator==(const element_fp &B) const {
                            return data == B.data;
                        }

                        constexpr bool operator!=(const element_fp &B) const {
                            return data != B.data;
                        }

                        constexpr element_fp &operator=(const element_fp &B) {
                            data = B.data;

                            return *this;
                        }

                        constexpr element_fp operator+(const element_fp &B) const {
                            return element_fp(data + B.data);
                        }

                        constexpr element_fp operator-(const element_fp &B) const {
                            return element_fp(data - B.data);
                        }

                        constexpr element_fp &operator-=(const element_fp &B) {
                            data -= B.data;

                            return *this;
                        }

                        constexpr element_fp &operator+=(const element_fp &B) {
                            data += B.data;

                            return *this;
                        }

                        constexpr element_fp &operator*=(const element_fp &B) {
                            data *= B.data;

                            return *this;
                        }

                        constexpr element_fp &operator/=(const element_fp &B) {
                            data *= B.inversed().data;

                            return *this;
                        }

                        constexpr element_fp operator-() const {
                            return element_fp(-data);
                        }

                        constexpr element_fp operator*(const element_fp &B) const {
                            return element_fp(data * B.data);
                        }

                        constexpr element_fp operator/(const element_fp &B) const {
                            //                        return element_fp(data / B.data);
                            return element_fp(data * B.inversed().data);
                        }

                        constexpr bool operator<(const element_fp &B) const {
                            return data < B.data;
                        }

                        constexpr bool operator>(const element_fp &B) const {
                            return data > B.data;
                        }

                        constexpr bool operator<=(const element_fp &B) const {
                            return data <= B.data;
                        }

                        constexpr bool operator>=(const element_fp &B) const {
                            return data >= B.data;
                        }

                        constexpr element_fp &operator++() {
                            data = data + data_type(1, modulus_params);
                            return *this;
                        }

                        constexpr element_fp operator++(int) {
                            element_fp temp(*this);
                            ++*this;
                            return temp;
                        }

                        constexpr element_fp &operator--() {
                            data = data - data_type(1, modulus_params);
                            return *this;
                        }

                        constexpr element_fp operator--(int) {
                            element_fp temp(*this);
                            --*this;
                            return temp;
                        }

                        constexpr element_fp doubled() const {
                            return element_fp(data + data);
                        }

                        // TODO: maybe incorrect result here
                        constexpr element_fp sqrt() const {
                            return element_fp(ressol(data));
                        }

                        constexpr element_fp inversed() const {
                            return element_fp(inverse_mod(data));
                        }

                        // TODO: complete method
                        constexpr element_fp _2z_add_3x() {
                        }

                        constexpr element_fp squared() const {
                            return element_fp(data * data);    // maybe can be done more effective
                        }

                        constexpr bool is_square() const {
                            element_fp tmp = this->pow(policy_type::group_order_minus_one_half);
                            return (tmp.is_one() || tmp.is_zero());
                        }

                        template<typename PowerType,
                                 typename = typename std::enable_if<boost::is_integral<PowerType>::value>::type>
                        constexpr element_fp pow(const PowerType pwr) const {
                            return element_fp(multiprecision::powm(data, multiprecision::uint128_t(pwr)));
                        }

                        template<typename Backend, multiprecision::expression_template_option ExpressionTemplates>
                        constexpr element_fp
                            pow(const multiprecision::number<Backend, ExpressionTemplates> &pwr) const {
                            return element_fp(multiprecision::powm(data, pwr));
                        }
                    };

                    template<typename FieldParams>
                    constexpr typename element_fp<FieldParams>::integral_type const element_fp<FieldParams>::modulus;

                    template<typename FieldParams>
                    constexpr typename element_fp<FieldParams>::modular_params_type const element_fp<FieldParams>::modulus_params;

                    template<typename FieldParams>
                    std::ostream& operator<<(std::ostream& os, const element_fp<FieldParams>& elem) {
                        os << elem.data;
                        return os;
                    }

                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

template<typename FieldParams>
struct std::hash<typename nil::crypto3::algebra::fields::detail::element_fp<FieldParams>>
{
    std::hash<typename nil::crypto3::algebra::fields::detail::element_fp<FieldParams>::modular_type> hasher;
    size_t operator()(const nil::crypto3::algebra::fields::detail::element_fp<FieldParams>& elem) const
    {
        std::size_t result = hasher(elem.data);
        return result;
    }
};

#endif    // CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP_HPP
