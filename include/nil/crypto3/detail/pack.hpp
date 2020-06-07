//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DETAIL_PACK_HPP
#define CRYPTO3_DETAIL_PACK_HPP

#include <nil/crypto3/detail/type_traits.hpp>
#include <nil/crypto3/detail/stream_endian.hpp>
#include <nil/crypto3/detail/exploder.hpp>
#include <nil/crypto3/detail/imploder.hpp>
#include <nil/crypto3/detail/reverser.hpp>

#include <boost/static_assert.hpp>
#include <boost/utility/enable_if.hpp>
#include <boost/predef/other/endian.h>
#include <boost/type_traits/is_same.hpp>

#include <algorithm>
#include <iterator>
#include <climits>

namespace nil {
    namespace crypto3 {
        namespace detail {

            template<int UnitBits, int ValueBits, typename InT, typename OutT>
            struct host_can_memcpy {
                constexpr static const bool value = !(UnitBits % CHAR_BIT) && ValueBits >= UnitBits &&
                                                    sizeof(InT) * CHAR_BIT == ValueBits &&
                                                    sizeof(OutT) * CHAR_BIT == ValueBits;
            };

            template<typename Endianness, int ValueBits, typename InT, typename OutT>
            struct can_memcpy {
                constexpr static const bool value = sizeof(InT) == sizeof(OutT);
            };

            template<int UnitBits, int ValueBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::host_unit<UnitBits>, ValueBits, InT, OutT> 
                : host_can_memcpy<UnitBits, ValueBits, InT, OutT> { };

#ifdef CRYPTO3_TARGET_CPU_IS_LITTLE_ENDIAN
            template<int UnitBits, int ValueBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::little_unit_big_bit<UnitBits>, ValueBits, InT, OutT>
                : host_can_memcpy<UnitBits, ValueBits, InT, OutT> { };
            template<int UnitBits, int ValueBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::little_unit_little_bit<UnitBits>, ValueBits, InT, OutT>
                : host_can_memcpy<UnitBits, ValueBits, InT, OutT> { };

#elif defined(CRYPTO3_TARGET_CPU_IS_BIG_ENDIAN)
            template<int UnitBits, int ValueBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::big_unit_big_bit<UnitBits>, ValueBits, InT, OutT>
                : host_can_memcpy<UnitBits, ValueBits, InT, OutT> { };
            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::big_unit_little_bit<UnitBits>, ValueBits, InT, OutT>
                : host_can_memcpy<UnitBits, ValueBits, InT, OutT> { };
#endif

            template<typename InputIterator, typename OutputIterator>
            struct can_memcpy_itr {
                constexpr static bool const value = 
                    boost::is_same<typename std::iterator_traits<InputIterator>::iterator_category, 
                    std::random_access_iterator_tag>::value && 
                    boost::is_same<typename std::iterator_traits<OutputIterator>::iterator_category, 
                    std::random_access_iterator_tag>::value;
            };

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits,
                     bool Implode = (InputValueBits < OutputValueBits),
                     bool Explode = (InputValueBits > OutputValueBits)>
            struct packer { };

            template<int UnitBits, template<int> class Endian, std::size_t ValueBits>
            struct packer<Endian<UnitBits>, Endian<UnitBits>, ValueBits, ValueBits, false, false> {

                typedef Endian<UnitBits> Endianness;

                template<typename InputType, typename OutputType, typename Dummy = void>
                inline static typename boost::enable_if_c<
                    can_memcpy<Endianness, ValueBits, InputType, OutputType>::value, Dummy>::type
                    pack_n(InputType const *in, size_t n, OutputType *out) {
                    std::memcpy(out, in, n * sizeof(InputType));
                }

                template<typename InputType, typename OutputType, typename Dummy = void>
                inline static typename boost::enable_if_c<
                    can_memcpy<Endianness, ValueBits, InputType, OutputType>::value, Dummy>::type
                    pack_n(InputType *in, size_t n, OutputType *out) {
                    std::memcpy(out, in, n * sizeof(InputType));
                }

                template<typename InputIterator, typename OutputIterator, typename Dummy = void>
                inline static typename boost::enable_if_c<
                    can_memcpy<Endianness, ValueBits, typename std::iterator_traits<InputIterator>::value_type,
                               typename std::iterator_traits<OutputIterator>::value_type>::value &&
                    can_memcpy_itr<InputIterator, OutputIterator>::value, Dummy>::type
                    pack(InputIterator first, InputIterator last, OutputIterator out) {
                    return pack_n(&(*first), std::distance(first, last), &(*out));
                }

                template<typename InputIterator, typename OutputIterator, typename Dummy = void>
                inline static typename boost::enable_if_c<
                    !can_memcpy<Endianness, ValueBits, typename std::iterator_traits<InputIterator>::value_type,
                               typename std::iterator_traits<OutputIterator>::value_type>::value || 
                    !can_memcpy_itr<InputIterator, OutputIterator>::value, Dummy>::type 
                    pack(InputIterator first, InputIterator last, OutputIterator out) {
                    std::copy(first, last, out);
                }
            };

            template<int UnitBits, template<int> class InputEndian, 
                     template<int> class OutputEndian, std::size_t ValueBits>
            struct packer<InputEndian<UnitBits>, OutputEndian<UnitBits>, ValueBits, ValueBits, false, false> {

                typedef InputEndian<UnitBits> InputEndianness;
                typedef OutputEndian<UnitBits> OutputEndianness;

                typedef unit_reverser<InputEndianness, OutputEndianness, UnitBits> units_reverser;
                typedef bit_reverser<InputEndianness, OutputEndianness, UnitBits> bits_reverser;

                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator first, InputIterator last, OutputIterator out) {
                    std::transform(first, last, out, 
                        [](typename std::iterator_traits<InputIterator>::value_type const &elem) {
                        return units_reverser::reverse(bits_reverser::reverse(elem));});
                }
            };

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits>
            struct packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, true, false> {

                BOOST_STATIC_ASSERT(!(OutputValueBits % InputValueBits));

                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator first, InputIterator last, OutputIterator out) {
                    typedef typename std::iterator_traits<OutputIterator>::value_type OutValue;
                    typedef detail::imploder<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>
                        imploder;

                    while (first != last) {
                        OutValue value = OutValue();
                        imploder::implode(first, value);
                        *out++ = value;
                    }
                }
            };

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits>
            struct packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, false, true> {

                BOOST_STATIC_ASSERT(!(InputValueBits % OutputValueBits));

                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator first, InputIterator last, OutputIterator out) {
                    typedef typename std::iterator_traits<InputIterator>::value_type InValue;
                    typedef detail::exploder<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>
                        exploder;

                    while (first != last) {
                        InValue const value = *first++;
                        exploder::explode(value, out);
                    }
                }
            };

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits, 
                     std::size_t OutputValueBits, typename InputIterator, typename OutputIterator>
            inline void pack(InputIterator first, InputIterator last, OutputIterator out) {
                typedef packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits> packer;
                packer::pack(first, last, out);
            }

            template<typename OutputEndianness, std::size_t InputValueBits, std::size_t OutputValueBits, 
                     typename InputIterator, typename OutputIterator>
            inline void pack_to(InputIterator first, InputIterator last, OutputIterator out) {

#ifdef BOOST_ENDIAN_BIG_BYTE_AVAILABLE
                typedef packer<stream_endian::big_octet_big_bit, OutputEndianness, 
                        InputValueBits, OutputValueBits> packer;
#elif defined(BOOST_ENDIAN_LITTLE_BYTE_AVAILABLE)
                typedef packer<stream_endian::little_octet_big_bit, OutputEndianness, 
                        InputValueBits, OutputValueBits> packer;
#elif defined(BOOST_ENDIAN_BIG_WORD_AVAILABLE)
                typedef packer<stream_endian::big_unit_big_bit<CRYPTO3_MP_WORD_BITS>, OutputEndianness, 
                        InputValueBits, OutputValueBits> packer;
#elif defined(BOOST_ENDIAN_LITTLE_WORD_AVAILABLE)
                typedef packer<stream_endian::little_unit_big_bit<CRYPTO3_MP_WORD_BITS>, OutputEndianness, 
                        InputValueBits, OutputValueBits> packer;
#else
#error "Unknown endianness"
#endif

                packer::pack(first, last, out);
            }


            template<typename InputEndianness, std::size_t InputValueBits, std::size_t OutputValueBits, 
                     typename InputIterator, typename OutputIterator>
            inline void pack_from(InputIterator first, InputIterator last, OutputIterator out) {

#ifdef BOOST_ENDIAN_BIG_BYTE_AVAILABLE
                typedef packer<InputEndianness, stream_endian::big_octet_big_bit, 
                        InputValueBits, OutputValueBits> packer;
#elif defined(BOOST_ENDIAN_LITTLE_BYTE_AVAILABLE)
                typedef packer<InputEndianness, stream_endian::little_octet_big_bit, 
                        InputValueBits, OutputValueBits> packer;
#elif defined(BOOST_ENDIAN_BIG_WORD_AVAILABLE)
                typedef packer<InputEndianness, stream_endian::big_unit_big_bit<CRYPTO3_MP_WORD_BITS>, 
                        InputValueBits, OutputValueBits> packer;
#elif defined(BOOST_ENDIAN_LITTLE_WORD_AVAILABLE)
                typedef packer<InputEndianness, stream_endian::little_unit_big_bit<CRYPTO3_MP_WORD_BITS>, 
                        InputValueBits, OutputValueBits> packer;
#else
#error "Unknown endianness"
#endif

                packer::pack(first, last, out); 
            }

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_PACK_HPP