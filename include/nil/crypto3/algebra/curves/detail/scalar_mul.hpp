//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_SCALAR_MUL_HPP
#define CRYPTO3_ALGEBRA_CURVES_SCALAR_MUL_HPP

#include <nil/crypto3/detail/type_traits.hpp>

#include <boost/multiprecision/number.hpp>

// temporary includes begin
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/modular/modular_adaptor.hpp>
// temporary includes end

#include <cstdint>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    using namespace boost::multiprecision;

                    template<typename GroupValueType, typename Backend, expression_template_option ExpressionTemplates>
                    GroupValueType scalar_mul(const GroupValueType &base,
                                              const number<Backend, ExpressionTemplates> &scalar) {
                        GroupValueType result;

                        bool found_one = false;
                        for (auto i = static_cast<std::int64_t>(msb(scalar)); i >= 0; --i) {
                            if (found_one) {
                                result = result.doubled();
                            }

                            if (bit_test(scalar, i)) {
                                found_one = true;
                                result = result + base;
                            }
                        }

                        return result;
                    }

                    template<typename GroupValueType, typename Backend, expression_template_option ExpressionTemplates>
                    GroupValueType operator*(const GroupValueType &left,
                                             const number<Backend, ExpressionTemplates> &right) {

                        return scalar_mul(left, right);
                    }

                    template<typename GroupValueType, typename Backend, expression_template_option ExpressionTemplates>
                    GroupValueType operator*(const number<Backend, ExpressionTemplates> &left,
                                             const GroupValueType &right) {

                        return right * left;
                    }

                    /*template<typename GroupValueType, typename =
                        typename std::enable_if<::nil::crypto3::detail::is_curve_group<typename
                    GroupValueType::group_type>::value &&
                                                !::nil::crypto3::detail::is_field<typename
                    GroupValueType::group_type>::value>::type> GroupValueType operator*( const GroupValueType &left,
                        const typename GroupValueType::underlying_field_type::modulus_type &right) {

                        return scalar_mul(left, right);
                    }

                    template<typename GroupValueType, typename =
                        typename std::enable_if<::nil::crypto3::detail::is_curve_group<typename
                    GroupValueType::group_type>::value &&
                                                !::nil::crypto3::detail::is_field<typename
                    GroupValueType::group_type>::value>::type> GroupValueType operator*( const typename
                    GroupValueType::underlying_field_type::modulus_type &left, const GroupValueType &right) {

                        return right * left;
                    }*/

                    template<typename GroupValueType,
                             typename FieldValueType>
                    typename std::enable_if<::nil::crypto3::detail::is_curve_group<typename GroupValueType::group_type>::value &&
                                            !::nil::crypto3::detail::is_field<typename GroupValueType::group_type>::value &&
                                            ::nil::crypto3::detail::is_fp_field<typename FieldValueType::field_type>::value, GroupValueType>::type 
                         operator*(const GroupValueType &left, const FieldValueType &right) {

                        // temporary added until fixed-precision modular adaptor is ready:
                        typedef number<backends::cpp_int_backend<>> non_fixed_precision_modulus_type;

                        return left * non_fixed_precision_modulus_type(right.data);
                    }

                    template<typename GroupValueType,
                             typename FieldValueType>
                    typename std::enable_if<::nil::crypto3::detail::is_curve_group<typename GroupValueType::group_type>::value &&
                                            !::nil::crypto3::detail::is_field<typename GroupValueType::group_type>::value &&
                                            ::nil::crypto3::detail::is_fp_field<typename FieldValueType::field_type>::value, GroupValueType>::type 
                        operator*(const FieldValueType &left, const GroupValueType &right) {

                        return right * left;
                    }
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SCALAR_MUL_HPP
