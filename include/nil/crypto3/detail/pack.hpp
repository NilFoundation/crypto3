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
#include <boost/endian/conversion.hpp>

#include <algorithm>
#include <iterator>
#include <type_traits>
#include <climits>

#include <iostream>

namespace nil {
    namespace crypto3 {
        namespace detail { /*
 #ifndef CRYPTO3_NO_OPTIMIZATION

             template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
             struct host_can_memcpy {
                 constexpr static const bool value = !(UnitBits % CHAR_BIT) && InputBits >= UnitBits &&
                                                     OutputBits >= UnitBits && sizeof(InT) * CHAR_BIT == InputBits &&
                                                     sizeof(OutT) * CHAR_BIT == OutputBits;
             };

             template<typename Endianness, int InputBits, int OutputBits, typename InT, typename OutT>
             struct can_memcpy {
                 constexpr static const bool value = InputBits == OutputBits && sizeof(InT) == sizeof(OutT);
             };

             template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
             struct can_memcpy<stream_endian::host_unit<UnitBits>, InputBits, OutputBits, InT, OutT>
                 : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> { };

 #ifdef CRYPTO3_TARGET_CPU_IS_LITTLE_ENDIAN
             template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
             struct can_memcpy<stream_endian::little_unit_big_bit<UnitBits>, InputBits, OutputBits, InT, OutT>
                 : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> { };
             template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
             struct can_memcpy<stream_endian::little_unit_little_bit<UnitBits>, InputBits, OutputBits, InT, OutT>
                 : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> { };
 #endif

 #ifdef CRYPTO3_TARGET_CPU_IS_BIG_ENDIAN
             template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
             struct can_memcpy<stream_endian::big_unit_big_bit<UnitBits>, InputBits, OutputBits, InT, OutT>
                 : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> { };
             template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
             struct can_memcpy<stream_endian::big_unit_little_bit<UnitBits>, InputBits, OutputBits, InT, OutT>
                 : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> { };
 #endif

 #endif

             template<typename Endianness, int InputBits, int OutputBits, bool Explode = (InputBits > OutputBits),
                      bool Implode = (InputBits < OutputBits)>
             struct real_packer;

             template<typename Endianness, int Bits>
             struct real_packer<Endianness, Bits, Bits, false, false> {

                 template<typename InputIterator, typename OutputIterator>
                 inline static void pack_n(InputIterator in, size_t in_n, OutputIterator out) {
                     std::copy(in, in + in_n, out);
                 }

                 template<typename InputIterator, typename OutputIterator>
                 inline static void pack(InputIterator in, InputIterator in_e, OutputIterator out) {
                     std::copy(in, in_e, out);
                 }
             };

             template<typename Endianness, int InputBits, int OutputBits>
             struct real_packer<Endianness, InputBits, OutputBits, true, false> {

                 BOOST_STATIC_ASSERT(InputBits % OutputBits == 0);

                 template<typename InputIterator, typename OutputIterator>
                 inline static void pack_n(InputIterator in, size_t in_n, OutputIterator out) {
                     while (in_n--) {
                         typedef typename std::iterator_traits<InputIterator>::value_type InValue;
                         InValue const value = *in++;
                         detail::exploder<Endianness, InputBits, OutputBits>::explode(value, out);
                     }
                 }

                 template<typename InputIterator, typename OutputIterator>
                 inline static void pack(InputIterator in, InputIterator in_e, OutputIterator out) {
                     while (in != in_e) {
                         typedef typename std::iterator_traits<InputIterator>::value_type InValue;
                         InValue const value = *in++;
                         detail::exploder<Endianness, InputBits, OutputBits>::explode(value, out);
                     }
                 }
             };

             template<typename Endianness, int InputBits, int OutputBits>
             struct real_packer<Endianness, InputBits, OutputBits, false, true> {

                 BOOST_STATIC_ASSERT(OutputBits % InputBits == 0);

                 template<typename InputIterator, typename OutputIterator>
                 inline static void pack_n(InputIterator in, size_t in_n, OutputIterator out) {
                     size_t out_n = in_n / (OutputBits / InputBits);
                     while (out_n--) {
                         typedef typename detail::outvalue_helper<OutputIterator, OutputBits>::type OutValue;
                         OutValue value = OutValue();
                         detail::imploder<Endianness, InputBits, OutputBits>::implode(in, value);
                         *out++ = value;
                     }
                 }

                 template<typename InputIterator, typename OutputIterator>
                 inline static void pack(InputIterator in, InputIterator in_e, OutputIterator out) {
                     while (in != in_e) {
                         typedef typename detail::outvalue_helper<OutputIterator, OutputBits>::type OutValue;
                         OutValue value = OutValue();
                         detail::imploder<Endianness, InputBits, OutputBits>::implode(in, value);
                         *out++ = value;
                     }
                 }
             };

             template<typename Endianness, int InputBits, int OutputBits>
             struct packer : real_packer<Endianness, InputBits, OutputBits> {

 #ifndef CRYPTO3_NO_OPTIMIZATION

                 using real_packer<Endianness, InputBits, OutputBits>::pack_n;

                 template<typename InT, typename OutT>
                 inline static
                     typename std::enable_if<can_memcpy<Endianness, InputBits, OutputBits, InT, OutT>::value>::type
                     pack_n(InT const *in, size_t n, OutT *out) {
                     std::memcpy(out, in, n * sizeof(InT));
                 }

                 template<typename InT, typename OutT>
                 inline static
                     typename std::enable_if<can_memcpy<Endianness, InputBits, OutputBits, InT, OutT>::value>::type
                     pack_n(InT *in, size_t n, OutT *out) {
                     std::memcpy(out, in, n * sizeof(InT));
                 }

 #endif
             };

             template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator1,
                      typename InputIterator2>
             inline void pack_n(InputIterator1 in, size_t in_n, InputIterator2 out) {
                 typedef packer<Endianness, InValueBits, OutValueBits> packer_type;
                 packer_type::pack_n(in, in_n, out);
             }

             template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator1,
                      typename InputIterator2>
             inline void pack_n(InputIterator1 in, size_t in_n, InputIterator2 out, size_t out_n) {
                 BOOST_ASSERT(in_n * InValueBits == out_n * OutValueBits);
                 pack_n<Endianness, InValueBits, OutValueBits>(in, in_n, out);
             }

             template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator1,
                      typename InputIterator2>
             inline void pack(InputIterator1 b1, InputIterator1 e1, std::random_access_iterator_tag, InputIterator2 b2)
 { pack_n<Endianness, InValueBits, OutValueBits>(b1, e1 - b1, b2);
             }

             template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator1, typename CatT1,
                      typename InputIterator2,
                      typename = typename std::enable_if<detail::is_iterator<InputIterator1>::value>::type,
                      typename = typename std::enable_if<detail::is_iterator<InputIterator2>::value>::type>
             inline void pack(InputIterator1 b1, InputIterator1 e1, CatT1, InputIterator2 b2) {
                 typedef packer<Endianness, InValueBits, OutValueBits> packer_type;
                 packer_type::pack(b1, e1, b2);
             }

             template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator1,
                      typename InputIterator2,
                      typename = typename std::enable_if<detail::is_iterator<InputIterator2>::value>::type>
             inline void pack(InputIterator1 b1, InputIterator1 e1, InputIterator2 b2) {
                 typedef typename std::iterator_traits<InputIterator1>::iterator_category cat1;

                 pack<Endianness, InValueBits, OutValueBits>(b1, e1, cat1(), b2);
             }

             template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator1,
                      typename InputIterator2>
             inline void pack(InputIterator1 b1, InputIterator1 e1, std::random_access_iterator_tag, InputIterator2 b2,
                              InputIterator2 e2, std::random_access_iterator_tag) {
                 pack_n<Endianness, InValueBits, OutValueBits>(b1, e1 - b1, b2, e2 - b2);
             }

             template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator1, typename CatT1,
                      typename InputIterator2, typename CatT2>
             inline void pack(InputIterator1 b1, InputIterator1 e1, CatT1, InputIterator2 b2, InputIterator2, CatT2) {
                 pack<Endianness, InValueBits, OutValueBits>(b1, e1, b2);
             }

             template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator1,
                      typename InputIterator2>
             inline void pack(InputIterator1 b1, InputIterator1 e1, InputIterator2 b2, InputIterator2 e2) {
                 typedef typename std::iterator_traits<InputIterator1>::iterator_category cat1;
                 typedef typename std::iterator_traits<InputIterator2>::iterator_category cat2;
                 pack<Endianness, InValueBits, OutValueBits>(b1, e1, cat1(), b2, e2, cat2());
             }

             template<typename Endianness, int InValueBits, int OutValueBits, typename InputType, typename OutputType>
             inline void pack(const InputType &in, OutputType &out) {
                 pack_n<Endianness, InValueBits, OutValueBits>(in.begin(), in.size(), out.begin(), out.size());
             }

             template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator,
                      typename OutputType,
                      typename = typename std::enable_if<!std::is_arithmetic<OutputType>::value>::type>
             inline void pack(InputIterator first, InputIterator last, OutputType &out) {
                 pack_n<Endianness, InValueBits, OutValueBits>(first, std::distance(first, last), out.begin(),
                                                               out.size());
             }
             */

            /* This module contains functions that deal with byte endianness
               Handling the case of bit endianness is to be done */

            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct host_can_memcpy {
                constexpr static const bool value = !(UnitBits % CHAR_BIT) && InputBits >= UnitBits &&
                                                    OutputBits >= UnitBits && sizeof(InT) * CHAR_BIT == InputBits &&
                                                    sizeof(OutT) * CHAR_BIT == OutputBits;
            };

            template<typename InputEndianness, typename OutputEndianness, int InputBits, int OutputBits, typename InT,
                     typename OutT>
            struct can_memcpy {
                constexpr static const bool value = InputBits == OutputBits && sizeof(InT) == sizeof(OutT);
            };

            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::host_unit<UnitBits>, stream_endian::host_unit<UnitBits>, InputBits,
                              OutputBits, InT, OutT> : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> { };

#ifdef CRYPTO3_TARGET_CPU_IS_LITTLE_ENDIAN
            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::little_unit_big_bit<UnitBits>, InputBits, OutputBits, InT, OutT>
                : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> { };
            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::little_unit_little_bit<UnitBits>, InputBits, OutputBits, InT, OutT>
                : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> { };
#endif

#ifdef CRYPTO3_TARGET_CPU_IS_BIG_ENDIAN
            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::big_unit_big_bit<UnitBits>, InputBits, OutputBits, InT, OutT>
                : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> { };
            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::big_unit_little_bit<UnitBits>, InputBits, OutputBits, InT, OutT>
                : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> { };
#endif

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits,
                     bool Implode = (InputValueBits < OutputValueBits),
                     bool Explode = (InputValueBits > OutputValueBits)>
            struct packer { };

            /*template<int UnitBits, template<int> class InputEndian, 
                     template<int> class OutputEndian, std::size_t ValueBits>
            struct packer<InputEndian<UnitBits>, OutputEndian<UnitBits>, ValueBits, ValueBits, false, false> {

                typedef InputEndian<UnitBits> InputEndianness;
                typedef OutputEndian<UnitBits> OutputEndianness;

                template<typename InputIterator, typename OutputIterator, typename Dummy = void>
                inline static typename std::enable_if<
                    is_same_bit<InputEndianness, OutputEndianness, UnitBits>::value, Dummy>::type 
                    bit_pack(InputIterator first, InputIterator last, OutputIterator out) {
                    // wrong when endians are same byte
                    std::transform(first, last, out, 
                        [](typename std::iterator_traits<InputIterator>::value_type const &elem) {
                        return boost::endian::endian_reverse(elem);});
                }

                template<typename InputIterator, typename OutputIterator, typename Dummy = void>
                inline static typename std::enable_if<
                    !is_same_bit<InputEndianness, OutputEndianness, UnitBits>::value, Dummy>::type 
                    bit_pack(InputIterator first, InputIterator last, OutputIterator out) {
                    // wrong when endians are same byte
                    std::transform(first, last, out, 
                        [](typename std::iterator_traits<InputIterator>::value_type const &elem) {
                        return boost::endian::endian_reverse(reverse_bits<UnitBits>(elem));});
                }

                template<typename InputIterator, typename OutputIterator, typename Dummy = void>
                inline static typename std::enable_if<
                    std::is_same<InputEndianness, OutputEndianness>::value, Dummy>::type 
                    pack(InputIterator first, InputIterator last, OutputIterator out) {
                    std::copy(first, last, out);
                }

                template<typename InputIterator, typename OutputIterator, typename Dummy = void>
                inline static typename std::enable_if<
                    !std::is_same<InputEndianness, OutputEndianness>::value, Dummy>::type 
                    pack(InputIterator first, InputIterator last, OutputIterator out) {
                    bit_pack(first, last, out);
                }
            };*/

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits>
            struct packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, true, false> {
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
            void pack(InputIterator first, InputIterator last, OutputIterator out) {
                typedef packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits> packer;
                packer::pack(first, last, out);
            }

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_PACK_HPP