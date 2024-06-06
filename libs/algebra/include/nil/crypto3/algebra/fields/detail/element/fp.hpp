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
#include <boost/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
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

                        constexpr element_fp() = default;

                        constexpr element_fp(const data_type &data) : data(data) {}

                        template<typename Number,
                                 typename std::enable_if<(boost::multiprecision::is_number<Number>::value), bool>::type = true>
                        constexpr element_fp(const Number &data)
                            : data(typename modular_type::backend_type(data.backend(), modulus_params)) {}

                        template<typename Number, typename std::enable_if<
                            std::is_integral<Number>::value, bool>::type = true>
                        constexpr element_fp(const Number &data)
                            : data(typename modular_type::backend_type(data, modulus_params)) {}

                        constexpr element_fp(const element_fp &B)
                            : data(B.data) {}

                        constexpr element_fp(const element_fp &&B) BOOST_NOEXCEPT
                            : data(std::move(B.data)) {}

                        // Creating a zero is a fairly slow operation and is called very often, so we must return a
                        // reference to the same static object every time.
                        constexpr static const element_fp& zero();
                        constexpr static const element_fp& one();

                        constexpr bool is_zero() const {
                            return *this == zero();
                        }

                        constexpr bool is_one() const {
                            return *this == one();
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
                            // TODO(martun): consider directly taking the backend and calling
                            // eval_add to improve performance.
                            data -= B.data;

                            return *this;
                        }

                        constexpr element_fp &operator+=(const element_fp &B) {
                            // TODO(martun): consider directly taking the backend and calling
                            // eval_add to improve performance.
                            data += B.data;

                            return *this;
                        }

                        constexpr element_fp &operator*=(const element_fp &B) {
                            data *= B.data;

                            return *this;
                        }

                        constexpr element_fp operator-() const {
                            return element_fp(-data);
                        }

                        constexpr element_fp operator*(const element_fp &B) const {
                            return element_fp(data * B.data);
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
                            data += one().data;
                            return *this;
                        }

                        constexpr element_fp operator++(int) {
                            element_fp temp(*this);
                            ++*this;
                            return temp;
                        }

                        constexpr element_fp &operator--() {
                            data = data - typename modular_type::backend_type(1u, modulus_params);
                        }

                        constexpr element_fp operator--(int) {
                            element_fp temp(*this);
                            --*this;
                            return temp;
                        }

                        constexpr element_fp doubled() const {
                            return element_fp(data + data);
                        }

                        // If the element does not have a square root, this function must not be called.
                        // Call is_square() before using this function.
                        constexpr element_fp sqrt() const {
                            if (this->is_zero())
                                return zero();
                            element_fp result = ressol(data);
                            assert(!result.is_zero());
                            return result;
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
                            return element_fp(boost::multiprecision::powm(data, boost::multiprecision::uint128_t(pwr)));
                        }

                        template<typename Backend, boost::multiprecision::expression_template_option ExpressionTemplates>
                        constexpr element_fp
                            pow(const boost::multiprecision::number<Backend, ExpressionTemplates> &pwr) const {
                            return element_fp(boost::multiprecision::powm(data, pwr));
                        }
                    };

                    template<typename FieldParams>
                    constexpr typename element_fp<FieldParams>::integral_type const element_fp<FieldParams>::modulus;

                    template<typename FieldParams>
                    constexpr typename element_fp<FieldParams>::modular_params_type const element_fp<FieldParams>::modulus_params;

                    namespace element_fp_details {
                        // These constexpr static variables can not be members of element_fp, because
                        // element_fp is incomplete type until the end of its declaration.
                        template<typename FieldParams>
                        constexpr static element_fp<FieldParams> zero_instance = 0u;

                        template<typename FieldParams>
                        constexpr static element_fp<FieldParams> one_instance = 1u;
                    }

                    template<typename FieldParams>
                    constexpr const element_fp<FieldParams>& element_fp<FieldParams>::zero() {
                        return element_fp_details::zero_instance<FieldParams>;
                    }

                    template<typename FieldParams>
                    constexpr const element_fp<FieldParams>& element_fp<FieldParams>::one() {
                        return element_fp_details::one_instance<FieldParams>;
                    }

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
