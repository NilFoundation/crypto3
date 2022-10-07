//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_TYPE_TRAITS_HPP
#define CRYPTO3_TYPE_TRAITS_HPP

#include <complex>
#include <type_traits>

#include <boost/tti/tti.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {
            BOOST_TTI_HAS_TYPE(iterator)
            BOOST_TTI_HAS_TYPE(const_iterator)

            BOOST_TTI_HAS_TYPE(encoded_value_type)
            BOOST_TTI_HAS_TYPE(encoded_block_type)
            BOOST_TTI_HAS_TYPE(decoded_value_type)
            BOOST_TTI_HAS_TYPE(decoded_block_type)

            BOOST_TTI_HAS_TYPE(block_type)
            BOOST_TTI_HAS_TYPE(digest_type)
            BOOST_TTI_HAS_TYPE(key_type)
            BOOST_TTI_HAS_TYPE(key_schedule_type)
            BOOST_TTI_HAS_TYPE(word_type)

            BOOST_TTI_HAS_STATIC_MEMBER_DATA(encoded_value_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(encoded_block_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(decoded_value_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(decoded_block_bits)

            BOOST_TTI_HAS_STATIC_MEMBER_DATA(block_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(digest_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(key_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(min_key_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(max_key_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(key_schedule_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(word_bits)

            BOOST_TTI_HAS_STATIC_MEMBER_DATA(rounds)

            BOOST_TTI_HAS_MEMBER_FUNCTION(begin);
            BOOST_TTI_HAS_MEMBER_FUNCTION(end);

            BOOST_TTI_HAS_MEMBER_FUNCTION(encode);
            BOOST_TTI_HAS_MEMBER_FUNCTION(decode);

            BOOST_TTI_HAS_MEMBER_FUNCTION(encrypt);
            BOOST_TTI_HAS_MEMBER_FUNCTION(decrypt);

            BOOST_TTI_HAS_FUNCTION(generate)
            BOOST_TTI_HAS_FUNCTION(check)

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

            BOOST_TTI_HAS_STATIC_MEMBER_DATA(value_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(modulus_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(base_field_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(base_field_modulus)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(scalar_field_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(scalar_field_modulus)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(arity)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(p)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(q)

            BOOST_TTI_HAS_FUNCTION(to_affine)
            BOOST_TTI_HAS_FUNCTION(to_special)
            BOOST_TTI_HAS_FUNCTION(is_special)

            template<typename T>
            struct is_iterator {
                static char test(...);

                template<typename U, typename = typename std::iterator_traits<U>::difference_type,
                         typename = typename std::iterator_traits<U>::pointer,
                         typename = typename std::iterator_traits<U>::reference,
                         typename = typename std::iterator_traits<U>::value_type,
                         typename = typename std::iterator_traits<U>::iterator_category>
                static long test(U &&);

                constexpr static bool value = std::is_same<decltype(test(std::declval<T>())), long>::value;
            };

            template<typename Range>
            struct is_range {
                static const bool value = has_type_iterator<Range>::value &&
                                          has_member_function_begin<Range, typename Range::iterator>::value &&
                                          has_member_function_end<Range, typename Range::iterator>::value;
            };

            template<typename Container>
            struct is_container {
                static const bool value =
                    has_type_iterator<Container>::value &&
                    has_member_function_begin<Container, typename Container::iterator>::value &&
                    has_member_function_end<Container, typename Container::iterator>::value &&
                    has_type_const_iterator<Container>::value &&
                    has_member_function_begin<Container, typename Container::const_iterator>::value &&
                    has_member_function_end<Container, typename Container::const_iterator>::value;
            };

            template<typename T>
            struct is_codec {
                static const bool value = has_encoded_value_type<T>::value && has_encoded_value_bits<T>::value &&
                                          has_decoded_value_type<T>::value && has_decoded_value_bits<T>::value &&
                                          has_encoded_block_type<T>::value && has_encoded_block_bits<T>::value &&
                                          has_decoded_block_type<T>::value && has_decoded_block_bits<T>::value &&
                                          has_encode<T>::value && has_decode<T>::value;
                typedef T type;
            };

            template<typename T>
            struct is_block_cipher {
                static const bool value =
                    has_type_word_type<T>::value && has_static_member_data_word_bits<T, const std::size_t>::value &&
                    has_type_block_type<T>::value && has_static_member_data_block_bits<T, const std::size_t>::value &&
                    has_type_key_type<T>::value && has_static_member_data_key_bits<T, const std::size_t>::value &&
                    has_static_member_data_rounds<T, const std::size_t>::value &&
                    has_member_function_encrypt<T, typename T::block_type>::value &&
                    has_member_function_decrypt<T, typename T::block_type>::value;
                typedef T type;
            };

            template<typename T>
            struct is_hash {
            private:
                typedef char one;
                typedef struct {
                    char array[2];
                } two;

                template<typename C>
                static one test_construction_type(typename C::construction::type *);

                template<typename C>
                static two test_construction_type(...);

                template<typename C>
                static one test_construction_params(typename C::construction::params_type *);

                template<typename C>
                static two test_construction_params(...);

            public:
                static const bool value = has_type_digest_type<T>::value &&
                                          has_static_member_data_digest_bits<T, const std::size_t>::value &&
                                          sizeof(test_construction_type<T>(0)) == sizeof(one) &&
                                          sizeof(test_construction_params<T>(0)) == sizeof(one);
                typedef T type;
            };

            template<typename T>
            struct is_mac {
                static const bool value =
                    has_type_digest_type<T>::value && has_static_member_data_digest_bits<T, const std::size_t>::value &&
                    has_type_block_type<T>::value && has_static_member_data_block_bits<T, const std::size_t>::value &&
                    has_type_key_type<T>::value && has_static_member_data_key_bits<T, const std::size_t>::value;
                typedef T type;
            };

            template<typename T>
            struct is_kdf {
                static const bool value =
                    has_type_digest_type<T>::value && has_static_member_data_digest_bits<T, const std::size_t>::value &&
                    has_type_key_type<T>::value && has_static_member_data_max_key_bits<T, const std::size_t>::value &&
                    has_static_member_data_min_key_bits<T, const std::size_t>::value;

                typedef T type;
            };

            template<typename T>
            struct is_passhash {
                static const bool value = has_function_generate<T, void>::value && has_function_check<T, bool>::value;
                typedef T type;
            };

            template<typename T>
            struct is_curve {
                static const bool value = has_static_member_data_base_field_bits<T, const std::size_t>::value &&
                                          has_type_base_field_type<T>::value && has_type_number_type<T>::value &&

                                          has_static_member_data_scalar_field_bits<T, const std::size_t>::value &&
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
                                          has_type_extension_policy<T>::value;
                typedef T type;
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
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_TYPE_TRAITS_HPP
