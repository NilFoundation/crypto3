//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_MARSHALLING_HPP
#define CRYPTO3_ALGEBRA_MARSHALLING_HPP

#include <vector>
#include <tuple>

#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/stream_endian.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/algebra/curves/detail/marshalling.hpp>
#include <type_traits>

namespace nil {
    namespace marshalling {
        namespace bincode {
            template<typename FieldType>
            struct field {
                typedef FieldType field_type;
                typedef typename field_type::value_type field_value_type;

                typedef uint8_t chunk_type;
                constexpr static const size_t chunk_size = 8;

                constexpr static size_t modulus_chunks =
                    field_type::modulus_bits / chunk_size + (field_type::modulus_bits % chunk_size ? 1 : 0);
                constexpr static size_t field_octets_num = field_type::arity * modulus_chunks;

                constexpr static inline size_t get_element_size() {
                    return field_octets_num;
                }

                template<typename InputFieldValueIterator>
                static inline typename std::enable_if<
                    !algebra::is_extended_field<field_type>::value &&
                        std::is_same<chunk_type,
                                     typename std::iterator_traits<InputFieldValueIterator>::value_type>::value,
                    std::pair<bool, field_value_type>>::type
                    field_element_from_bytes(InputFieldValueIterator first, InputFieldValueIterator last) {
                    BOOST_ASSERT(field_octets_num == std::distance(first, last));

                    typename FieldType::integral_type result;
                    ::nil::crypto3::multiprecision::import_bits(result, first, last, chunk_size, false);

                    return std::make_pair(result < FieldType::modulus, field_value_type(result));
                }

                template<typename InputFieldValueIterator>
                static inline typename std::enable_if<
                    algebra::is_extended_field<field_type>::value &&
                        std::is_same<chunk_type,
                                     typename std::iterator_traits<InputFieldValueIterator>::value_type>::value,
                    std::pair<bool, field_value_type>>::type
                    field_element_from_bytes(InputFieldValueIterator first, InputFieldValueIterator last) {
                    constexpr size_t data_dimension = field_type::arity / field_type::underlying_field_type::arity;
                    BOOST_ASSERT(field_octets_num == std::distance(first, last));

                    typename field_value_type::data_type data;
                    bool bres = true;
                    for (size_t n = 0; n < data_dimension; ++n) {
                        std::pair<bool, typename field_type::underlying_field_type::value_type> valid_coord =
                            field<typename field_type::underlying_field_type>::field_element_from_bytes(
                                first + n * field_type::underlying_field_type::arity * modulus_chunks,
                                first + (n + 1) * field_type::underlying_field_type::arity * modulus_chunks);
                        bres = bres && valid_coord.first;
                        data[n] = valid_coord.second;
                    }

                    return std::make_pair(bres, field_value_type(data));
                }

                template<typename OutputIterator>
                static inline typename std::enable_if<
                    !algebra::is_extended_field<field_type>::value &&
                        std::is_same<chunk_type, typename std::iterator_traits<OutputIterator>::value_type>::value,
                    size_t>::type
                    field_element_to_bytes(const field_value_type &element, OutputIterator out_first,
                                           OutputIterator out_last) {
                    BOOST_ASSERT(field_octets_num == std::distance(out_first, out_last));

                    ::nil::crypto3::multiprecision::export_bits(
                        element.data.template convert_to<typename FieldType::integral_type>(), out_first, chunk_size,
                        false);

                    return field_octets_num;
                }

                template<typename OutputIterator>
                static inline typename std::enable_if<
                    algebra::is_extended_field<field_type>::value &&
                        std::is_same<chunk_type, typename std::iterator_traits<OutputIterator>::value_type>::value,
                    size_t>::type
                    field_element_to_bytes(const field_value_type &element, OutputIterator out_first,
                                           OutputIterator out_last) {
                    BOOST_ASSERT(field_octets_num == std::distance(out_first, out_last));

                    size_t offset = 0;
                    for (auto data_it = element.data.begin(); data_it != element.data.end(); ++data_it) {
                        offset += field<typename field_type::underlying_field_type>::field_element_to_bytes(
                            *data_it, out_first + offset,
                            out_first + offset + field_type::underlying_field_type::arity * modulus_chunks);
                    }

                    return field_octets_num;
                }
            };

            template<typename CurveType>
            class curve;

            template<>
            class curve<algebra::curves::bls12<381>> {
            public:

                typedef algebra::curves::bls12<381> curve_type;
                typedef typename curve_type::base_field_type fp_type;
                typedef typename curve_type::scalar_field_type fr_type;
                typedef typename curve_type::template g1_type<> g1_type;
                typedef typename curve_type::template g2_type<> g2_type;
                typedef typename curve_type::gt_type gt_type;

                typedef uint8_t chunk_type;
                constexpr static const size_t chunk_size = 8;

                constexpr static size_t fp_octets_num =
                    curve_type::base_field_type::modulus_bits / chunk_size + 1;
                constexpr static size_t fr_octets_num =
                    curve_type::scalar_field_type::modulus_bits / chunk_size + 1;
                static_assert(curve_element_serializer<curve_type>::sizeof_field_element == fp_octets_num);

                constexpr static size_t g1_octets_num = fp_octets_num;
                constexpr static size_t g2_octets_num = 2 * fp_octets_num;
                constexpr static size_t gt_octets_num = gt_type::arity * fp_octets_num;

                // template<typename FieldType>
                // constexpr static inline std::size_t get_field_element_size() {
                //     return (FieldType::modulus_bits / chunk_size + (FieldType::modulus_bits % chunk_size ? 1 : 0)) *
                //            FieldType::arity;
                // }

                template<typename FieldType>
                constexpr static inline typename std::enable_if<std::is_same<fr_type, FieldType>::value, size_t>::type
                    element_size() {
                    return fr_octets_num;
                }

                template<typename FieldType>
                constexpr static inline typename std::enable_if<std::is_same<fp_type, FieldType>::value, size_t>::type
                    element_size() {
                    return fp_octets_num;
                }

                template<typename FieldType>
                constexpr static inline typename std::enable_if<std::is_same<gt_type, FieldType>::value, size_t>::type
                    element_size() {
                    return gt_octets_num;
                }

                template<typename GroupType>
                constexpr static inline typename std::enable_if<std::is_same<g1_type, GroupType>::value, size_t>::type
                    element_size() {
                    return g1_octets_num;
                }

                template<typename GroupType>
                constexpr static inline typename std::enable_if<std::is_same<g2_type, GroupType>::value, size_t>::type
                    element_size() {
                    return g2_octets_num;
                }

                template<typename FieldType, typename InputFieldValueIterator>
                static inline typename std::enable_if<
                    !algebra::is_extended_field<FieldType>::value &&
                        std::is_same<chunk_type,
                                     typename std::iterator_traits<InputFieldValueIterator>::value_type>::value &&
                        (std::is_same<fp_type, FieldType>::value || std::is_same<fr_type, FieldType>::value),
                    std::pair<bool, typename FieldType::value_type>>::type
                    field_element_from_bytes(InputFieldValueIterator first, InputFieldValueIterator last) {
                    return field<FieldType>::field_element_from_bytes(first, last);
                }

                template<typename FieldType, typename InputFieldValueIterator>
                static inline typename std::enable_if<
                    algebra::is_extended_field<FieldType>::value &&
                        std::is_same<chunk_type,
                                     typename std::iterator_traits<InputFieldValueIterator>::value_type>::value,
                    std::pair<bool, typename FieldType::value_type>>::type
                    field_element_from_bytes(InputFieldValueIterator first, InputFieldValueIterator last) {
                    return field<FieldType>::field_element_from_bytes(first, last);
                }

                template<typename InputG1Iterator>
                static inline typename std::enable_if<
                    std::is_same<chunk_type, typename std::iterator_traits<InputG1Iterator>::value_type>::value,
                    typename g1_type::value_type>::type
                    g1_point_from_bytes(InputG1Iterator first, InputG1Iterator last) {
                    BOOST_ASSERT(g1_octets_num == std::distance(first, last));

                    typename curve_element_serializer<curve_type>::compressed_g1_octets input_array;
                    auto it1 = first;
                    auto it2 = input_array.begin();
                    while (it1 != last && it2 != input_array.end()) {
                        *it2++ = *it1++;
                    }

                    return curve_element_serializer<curve_type>::octets_to_g1_point(input_array);
                }

                template<typename InputG2Iterator>
                static inline typename std::enable_if<
                    std::is_same<chunk_type, typename std::iterator_traits<InputG2Iterator>::value_type>::value,
                    typename g2_type::value_type>::type
                    g2_point_from_bytes(InputG2Iterator first, InputG2Iterator last) {
                    BOOST_ASSERT(g2_octets_num == std::distance(first, last));

                    typename curve_element_serializer<curve_type>::compressed_g2_octets input_array;
                    auto it1 = first;
                    auto it2 = input_array.begin();
                    while (it1 != last && it2 != input_array.end()) {
                        *it2++ = *it1++;
                    }

                    return curve_element_serializer<curve_type>::octets_to_g2_point(input_array);
                }

                template<typename FieldType, typename OutputIterator>
                static inline typename std::enable_if<
                    !algebra::is_extended_field<FieldType>::value &&
                        (std::is_same<fp_type, FieldType>::value || std::is_same<fr_type, FieldType>::value) &&
                        std::is_same<chunk_type, typename std::iterator_traits<OutputIterator>::value_type>::value,
                    size_t>::type
                    field_element_to_bytes(const typename FieldType::value_type &element, OutputIterator out_first,
                                           OutputIterator out_last) {
                    return field<FieldType>::field_element_to_bytes(element, out_first, out_last);
                }

                template<typename FieldType, typename OutputIterator>
                static inline typename std::enable_if<
                    algebra::is_extended_field<FieldType>::value &&
                        std::is_same<chunk_type, typename std::iterator_traits<OutputIterator>::value_type>::value,
                    size_t>::type
                    field_element_to_bytes(const typename FieldType::value_type &element, OutputIterator out_first,
                                           OutputIterator out_last) {
                    return field<FieldType>::field_element_to_bytes(element, out_first, out_last);
                }

                template<typename GroupType, typename OutputIterator>
                static inline typename std::enable_if<std::is_same<g1_type, GroupType>::value, size_t>::type
                    point_to_bytes(const typename GroupType::value_type &point, OutputIterator out_first,
                                   OutputIterator out_last) {
                    BOOST_ASSERT(g1_octets_num == std::distance(out_first, out_last));

                    auto out_array = curve_element_serializer<curve_type>::point_to_octets_compress(point);
                    std::copy(out_array.begin(), out_array.end(), out_first);
                    return out_array.size();
                }

                template<typename GroupType, typename OutputIterator>
                static inline typename std::enable_if<std::is_same<g2_type, GroupType>::value, size_t>::type
                    point_to_bytes(const typename GroupType::value_type &point, OutputIterator out_first,
                                   OutputIterator out_last) {
                    BOOST_ASSERT(g2_octets_num == std::distance(out_first, out_last));

                    auto out_array = curve_element_serializer<curve_type>::point_to_octets_compress(point);
                    std::copy(out_array.begin(), out_array.end(), out_first);
                    return out_array.size();
                }
            };
        }    // namespace bincode

    }    // namespace marshalling
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_MARSHALLING_HPP
