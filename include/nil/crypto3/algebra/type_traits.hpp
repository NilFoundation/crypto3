//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_TYPE_TRAITS_HPP
#define CRYPTO3_ALGEBRA_TYPE_TRAITS_HPP

#include <complex>

#include <boost/type_traits.hpp>
#include <boost/tti/tti.hpp>
#include <boost/mpl/placeholders.hpp>
#include <boost/type_traits/is_same.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {

            using namespace boost::mpl::placeholders;

            BOOST_TTI_HAS_TYPE(iterator)
            BOOST_TTI_HAS_TYPE(const_iterator)

            BOOST_TTI_HAS_TYPE(extension_policy)
            BOOST_TTI_HAS_TYPE(curve_type)
            BOOST_TTI_HAS_TYPE(underlying_field_type)
            BOOST_TTI_HAS_TYPE(value_type)
            BOOST_TTI_HAS_TYPE(modulus_type)
            BOOST_TTI_HAS_TYPE(base_field_type)
            BOOST_TTI_HAS_TYPE(number_type)
            BOOST_TTI_HAS_TYPE(scalar_field_type)
            BOOST_TTI_HAS_TYPE(g1_type)
            BOOST_TTI_HAS_TYPE(g2_type)
            BOOST_TTI_HAS_TYPE(gt_type)

            BOOST_TTI_HAS_TYPE(group_type)

            BOOST_TTI_HAS_STATIC_MEMBER_DATA(value_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(modulus_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(base_field_modulus)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(scalar_field_modulus)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(arity)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(p)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(q)

            BOOST_TTI_HAS_FUNCTION(to_affine)
            BOOST_TTI_HAS_FUNCTION(to_special)
            BOOST_TTI_HAS_FUNCTION(is_special)

            template<typename T>
            struct is_curve {
                static const bool value = has_type_base_field_type<T>::value && has_type_number_type<T>::value &&
                                          has_type_scalar_field_type<T>::value && has_type_g1_type<T>::value &&
                                          has_type_g2_type<T>::value && has_type_gt_type<T>::value &&
                                          has_type_number_type<T>::value &&
                                          has_static_member_data_p<T, const typename T::number_type>::value &&
                                          has_static_member_data_q<T, const typename T::number_type>::value;
                typedef T type;
            };

            // TODO: we should add some other params to curve group policy to identify it more clearly
            template<typename T>
            struct is_curve_group {
                static const bool value = has_type_value_type<T>::value && has_type_underlying_field_type<T>::value &&
                                          has_static_member_data_value_bits<T, const std::size_t>::value &&
                                          has_type_curve_type<T>::value;
                typedef T type;
            };

            template<typename T>
            struct is_field {
                static const bool value =
                    has_type_value_type<T>::value && has_static_member_data_value_bits<T, const std::size_t>::value &&
                    has_type_modulus_type<T>::value &&
                    has_static_member_data_modulus_bits<T, const std::size_t>::value &&
                    has_type_number_type<T>::value && has_static_member_data_arity<T, const std::size_t>::value;
                typedef T type;
            };

            template<typename T>
            struct is_extended_field {
                static const bool value = has_type_value_type<T>::value &&
                                          has_static_member_data_value_bits<T, const std::size_t>::value &&
                                          has_type_modulus_type<T>::value &&
                                          has_static_member_data_modulus_bits<T, const std::size_t>::value &&
                                          has_type_number_type<T>::value &&
                                          has_static_member_data_modulus_bits<T, const std::size_t>::value &&
                                          has_type_extension_policy<T>::value;
                typedef T type;
            };

            template<typename T>
            struct is_g1_group_element {
                static const bool value = boost::is_same<
                    typename T::group_type::curve_type::g1_type,
                    typename T::group_type>::value;
            };

            template<typename T>
            struct is_g2_group_element {
                static const bool value = boost::is_same<
                    typename T::group_type::curve_type::g2_type,
                    typename T::group_type>::value;
            };

            template<typename T>
            struct is_complex : std::false_type { };
            template<typename T>
            struct is_complex<std::complex<T>> : std::true_type { };
            template<typename T>
            constexpr bool is_complex_v = is_complex<T>::value;

            template<typename T>
            struct remove_complex {
                using type = T;
            };
            template<typename T>
            struct remove_complex<std::complex<T>> {
                using type = T;
            };
            template<typename T>
            using remove_complex_t = typename remove_complex<T>::type;
        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_TYPE_TRAITS_HPP
