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
                     bool SameEndianness = boost::is_same<InputEndianness, OutputEndianness>::value,
                     bool Implode = (InputValueBits < OutputValueBits),
                     bool Explode = (InputValueBits > OutputValueBits)>
            struct packer { };

            template<typename Endianness, std::size_t ValueBits>
            struct packer<Endianness, Endianness, ValueBits, ValueBits, true, false, false> {

                template<typename InputType, typename OutputType, typename Dummy = void>
                inline static typename boost::enable_if_c<
                    can_memcpy<Endianness, ValueBits, InputType, OutputType>::value, Dummy>::type
                    pack_n(InputType const *in, std::size_t n, OutputType *out) {
                    std::memcpy(out, in, n * sizeof(InputType));
                }

                template<typename InputType, typename OutputType, typename Dummy = void>
                inline static typename boost::enable_if_c<
                    can_memcpy<Endianness, ValueBits, InputType, OutputType>::value, Dummy>::type
                    pack_n(InputType *in, std::size_t n, OutputType *out) {
                    std::memcpy(out, in, n * sizeof(InputType));
                }

                template<typename InputIterator, typename OutputIterator>
                inline static void pack_n(InputIterator in, std::size_t in_n, OutputIterator out) {
                    std::copy(in, in + in_n, out);
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
            struct packer<InputEndian<UnitBits>, OutputEndian<UnitBits>, ValueBits, ValueBits, false, false, false> {

                typedef InputEndian<UnitBits> InputEndianness;
                typedef OutputEndian<UnitBits> OutputEndianness;

                typedef unit_reverser<InputEndianness, OutputEndianness, UnitBits> units_reverser;
                typedef bit_reverser<InputEndianness, OutputEndianness, UnitBits> bits_reverser;

                template<typename InputIterator, typename OutputIterator>
                inline static void pack_n(InputIterator in, std::size_t in_n, OutputIterator out) {
                    std::transform(in, in + in_n, out, 
                        [](typename std::iterator_traits<InputIterator>::value_type const &elem) {
                        return units_reverser::reverse(bits_reverser::reverse(elem));});
                }

                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator first, InputIterator last, OutputIterator out) {
                    std::transform(first, last, out, 
                        [](typename std::iterator_traits<InputIterator>::value_type const &elem) {
                        return units_reverser::reverse(bits_reverser::reverse(elem));});
                }
            };

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, bool Dummy>
            struct packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, Dummy, true, false> {

                BOOST_STATIC_ASSERT(!(OutputValueBits % InputValueBits));

                typedef detail::imploder<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>
                    imploder;

                template<typename InputIterator, typename OutputIterator>
                inline static void pack_n(InputIterator in, std::size_t in_n, OutputIterator out) {
                    typedef typename std::iterator_traits<OutputIterator>::value_type OutValue;
                    std::size_t out_n = in_n / (OutputValueBits / InputValueBits);
                    
                    while (out_n--) {
                        OutValue value = OutValue();
                        imploder::implode(in, value);
                        *out++ = value;
                    }
                }

                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator first, InputIterator last, OutputIterator out) {
                    typedef typename std::iterator_traits<OutputIterator>::value_type OutValue;

                    while (first != last) {
                        OutValue value = OutValue();
                        imploder::implode(first, value);
                        *out++ = value;
                    }
                }
            };

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, bool Dummy>
            struct packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, Dummy, false, true> {

                BOOST_STATIC_ASSERT(!(InputValueBits % OutputValueBits));

                typedef detail::exploder<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>
                    exploder;

                template<typename InputIterator, typename OutputIterator>
                inline static void pack_n(InputIterator in, std::size_t in_n, OutputIterator out) {
                    typedef typename std::iterator_traits<InputIterator>::value_type InValue;

                    while (in_n--) {
                        InValue const value = *in++;
                        exploder::explode(value, out);
                    }
                }

                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator first, InputIterator last, OutputIterator out) {
                    typedef typename std::iterator_traits<InputIterator>::value_type InValue;

                    while (first != last) {
                        InValue const value = *first++;
                        exploder::explode(value, out);
                    }
                }
            };

            /*template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits, 
                     std::size_t OutputValueBits, typename InputIterator, typename OutputIterator>
            inline void pack(InputIterator first, InputIterator last, OutputIterator out) {
                typedef packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits> packer_type;
                packer_type::pack(first, last, out);
            }*/

            template<typename OutputEndianness, std::size_t InputValueBits, std::size_t OutputValueBits, 
                     typename InputIterator, typename OutputIterator>
            inline void pack_to(InputIterator first, InputIterator last, OutputIterator out) {

#ifdef BOOST_ENDIAN_BIG_BYTE_AVAILABLE
                typedef packer<stream_endian::big_octet_big_bit, OutputEndianness, 
                        InputValueBits, OutputValueBits> packer_type;
#elif defined(BOOST_ENDIAN_LITTLE_BYTE_AVAILABLE)
                typedef packer<stream_endian::little_octet_big_bit, OutputEndianness, 
                        InputValueBits, OutputValueBits> packer_type;
#elif defined(BOOST_ENDIAN_BIG_WORD_AVAILABLE)
                typedef packer<stream_endian::big_unit_big_bit<CRYPTO3_MP_WORD_BITS>, OutputEndianness, 
                        InputValueBits, OutputValueBits> packer_type;
#elif defined(BOOST_ENDIAN_LITTLE_WORD_AVAILABLE)
                typedef packer<stream_endian::little_unit_big_bit<CRYPTO3_MP_WORD_BITS>, OutputEndianness, 
                        InputValueBits, OutputValueBits> packer_type;
#else
#error "Unknown endianness"
#endif

                packer_type::pack(first, last, out);
            }

            template<typename InputEndianness, std::size_t InputValueBits, std::size_t OutputValueBits, 
                     typename InputIterator, typename OutputIterator>
            inline void pack_from(InputIterator first, InputIterator last, OutputIterator out) {

#ifdef BOOST_ENDIAN_BIG_BYTE_AVAILABLE
                typedef packer<InputEndianness, stream_endian::big_octet_big_bit, 
                        InputValueBits, OutputValueBits> packer_type;
#elif defined(BOOST_ENDIAN_LITTLE_BYTE_AVAILABLE)
                typedef packer<InputEndianness, stream_endian::little_octet_big_bit, 
                        InputValueBits, OutputValueBits> packer_type;
#elif defined(BOOST_ENDIAN_BIG_WORD_AVAILABLE)
                typedef packer<InputEndianness, stream_endian::big_unit_big_bit<CRYPTO3_MP_WORD_BITS>, 
                        InputValueBits, OutputValueBits> packer_type;
#elif defined(BOOST_ENDIAN_LITTLE_WORD_AVAILABLE)
                typedef packer<InputEndianness, stream_endian::little_unit_big_bit<CRYPTO3_MP_WORD_BITS>, 
                        InputValueBits, OutputValueBits> packer_type;
#else
#error "Unknown endianness"
#endif

                packer_type::pack(first, last, out); 
            }

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits, 
                     std::size_t OutputValueBits, typename InputIterator, typename OutputIterator>
            inline void pack_n(InputIterator in, std::size_t in_n, OutputIterator out) {
                typedef packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits> packer_type;
                packer_type::pack_n(in, in_n, out);
            }
            
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits, 
                     std::size_t OutputValueBits, typename InputIterator, typename OutputIterator>
            inline void pack_n(InputIterator in, std::size_t in_n, OutputIterator out, std::size_t out_n) {
                BOOST_ASSERT(in_n * InputValueBits == out_n * OutputValueBits);
                pack_n<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>(in, in_n, out);
            }

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits, 
                     std::size_t OutputValueBits, typename InputIterator, typename OutputIterator>
            inline void pack(InputIterator first, InputIterator last, std::random_access_iterator_tag, 
                OutputIterator out) { 
                pack_n<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>(first, last - first, out);
            }

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits, 
                     std::size_t OutputValueBits, typename InputIterator, typename InCatT, typename OutputIterator,
                     typename boost::enable_if_c<detail::is_iterator<InputIterator>::value, int>::type = 0,
                     typename boost::enable_if_c<detail::is_iterator<OutputIterator>::value, int>::type = 0>
            inline void pack(InputIterator first, InputIterator last, InCatT, OutputIterator out) {
                typedef packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits> packer_type;
                packer_type::pack(first, last, out);
            }

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits, 
                     std::size_t OutputValueBits, typename InputIterator, typename OutputIterator,
                     typename boost::enable_if_c<detail::is_iterator<OutputIterator>::value, int>::type = 0>
            inline void pack(InputIterator first, InputIterator last, OutputIterator out) {
                typedef typename std::iterator_traits<InputIterator>::iterator_category in_cat;
                pack<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>(first, last, in_cat(), out);
            }

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits, 
                     std::size_t OutputValueBits, typename InputIterator, typename OutputIterator>
            inline void pack(InputIterator in_first, InputIterator in_last, std::random_access_iterator_tag, 
                OutputIterator out_first, OutputIterator out_last, std::random_access_iterator_tag) {
                pack_n<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>(
                    in_first, in_last - in_first, out_first, out_last - out_first);
            }

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits, 
                     std::size_t OutputValueBits, typename InputIterator, typename InCatT, 
                     typename OutputIterator, typename OutCatT>
            inline void pack(InputIterator in_first, InputIterator in_last, InCatT, OutputIterator out, 
                OutputIterator, OutCatT) {
                pack<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>(in_first, in_last, out);
            }

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits, 
                     std::size_t OutputValueBits, typename InputIterator, typename OutputIterator>
            inline void pack(InputIterator in_first, InputIterator in_last, 
                OutputIterator out_first, OutputIterator out_last) {
                typedef typename std::iterator_traits<InputIterator>::iterator_category in_cat;
                typedef typename std::iterator_traits<OutputIterator>::iterator_category out_cat;
                pack<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>(
                    in_first, in_last, in_cat(), out_first, out_last, out_cat());
            }

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits, 
                     std::size_t OutputValueBits, typename InputType, typename OutputType>
            inline void pack(const InputType &in, OutputType &out) {
                pack_n<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>(
                    in.begin(), in.size(), out.begin(), out.size());
            }

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits, 
                     std::size_t OutputValueBits, typename InputIterator, typename OutputType,
                     typename boost::enable_if_c<!std::is_arithmetic<OutputType>::value, int>::type = 0>
            inline void pack(InputIterator first, InputIterator last, OutputType &out) {
                pack_n<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>(
                    first, std::distance(first, last), out.begin(), out.size());
            }

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_PACK_HPP