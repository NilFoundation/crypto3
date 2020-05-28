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
#include <nil/crypto3/detail/octet.hpp>

#include <boost/static_assert.hpp>
#include <boost/endian/conversion.hpp>

#include <algorithm>
#include <iterator>
#include <type_traits>

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
                     bool EndiannessEquality = std::is_same<InputEndianness, OutputEndianness>::value,
                     bool Explode = (InputValueBits > OutputValueBits),
                     bool Implode = (InputValueBits < OutputValueBits)>
            struct packer { };

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits>
            struct packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, true, false, false> {
                template<typename InputType, typename OutputType>
                inline static typename std::enable_if<can_memcpy<InputEndianness, OutputEndianness, InputValueBits,
                                                                 OutputValueBits, InputType, OutputType>::value>::type
                    pack_n(InputType const *in, size_t n, OutputType *out) {
                    std::memcpy(out, in, n * sizeof(InputType));
                }

                template<typename InputType, typename OutputType>
                inline static typename std::enable_if<can_memcpy<InputEndianness, OutputEndianness, InputValueBits,
                                                                 OutputValueBits, InputType, OutputType>::value>::type
                    pack_n(InputType *in, size_t n, OutputType *out) {
                    std::memcpy(out, in, n * sizeof(InputType));
                }

                template<typename InputIterator, typename OutputIterator>
                inline static typename std::enable_if<
                    can_memcpy<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits,
                               typename std::iterator_traits<InputIterator>::value_type,
                               typename std::iterator_traits<OutputIterator>::value_type>::value>::type
                    pack(InputIterator first, InputIterator last, OutputIterator out) {
                    return pack_n(*first, std::distance(first, last), *out);
                }

                template<typename InputIterator, typename OutputIterator>
                inline void pack(InputIterator first, InputIterator last, OutputIterator out) {
                    std::copy(first, last, out);
                }
            };

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits>
            struct packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, true, false, true> { };

            template<typename OutputEndianness, std::size_t InputValueBits, std::size_t OutputValueBits>
            struct packer<stream_endian::little_octet_big_bit, OutputEndianness, InputValueBits, OutputValueBits, true,
                          false, true> {
                BOOST_STATIC_ASSERT(OutputValueBits % InputValueBits == 0);

                template<typename InputIterator, typename OutputIterator>
                inline static void pack_n(InputIterator in, size_t in_n, OutputIterator out) {
                    size_t out_n = in_n / (OutputValueBits / InputValueBits);
                    while (out_n--) {
                        typedef typename detail::outvalue_helper<OutputIterator, OutputValueBits>::type OutValue;
                        OutValue value = OutValue();
                        detail::imploder<OutputEndianness, InputValueBits, OutputValueBits>::implode(in, value);
                        *out++ = value;
                    }
                }

                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator in, InputIterator in_e, OutputIterator out) {
                    while (in != in_e) {
                        typedef typename detail::outvalue_helper<OutputIterator, OutputValueBits>::type OutValue;
                        OutValue value = OutValue();
                        detail::imploder<OutputEndianness, InputValueBits, OutputValueBits>::implode(in, value);
                        *out++ = value;
                    }
                }
            };

            template<typename OutputEndianness, std::size_t InputValueBits, std::size_t OutputValueBits>
            struct packer<stream_endian::big_octet_big_bit, OutputEndianness, InputValueBits, OutputValueBits, true,
                          false, true> {
                BOOST_STATIC_ASSERT(OutputValueBits % InputValueBits == 0);

                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator first, InputIterator last, OutputIterator out) {

                    typedef typename std::iterator_traits<OutputIterator>::value_type OutValue;
                    constexpr static const std::size_t out_invalues = OutputValueBits / InputValueBits;

                    while (first != last) {

                        OutValue out_val = OutValue();

                        for (size_t shift = OutputValueBits, i = 0; i != out_invalues; ++i) {
                            shift -= InputValueBits;
                            out_val |= unbounded_shl(low_bits<InputValueBits>(OutValue(*first)), shift);
                            ++first;
                        }

                        *out++ = out_val;
                    }
                }
            };

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits>
            struct packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, true, true, false> { };

            template<typename OutputEndianness, std::size_t InputValueBits, std::size_t OutputValueBits>
            struct packer<stream_endian::little_octet_big_bit, OutputEndianness, InputValueBits, OutputValueBits, true,
                          true, false> {
                BOOST_STATIC_ASSERT(InputValueBits % OutputValueBits == 0);

                template<typename InputIterator, typename OutputIterator>
                inline static void pack_n(InputIterator in, size_t in_n, OutputIterator out) {
                    while (in_n--) {
                        typedef typename std::iterator_traits<InputIterator>::value_type InValue;
                        InValue const value = *in++;
                        detail::exploder<OutputEndianness, InputValueBits, OutputValueBits>::explode(value, out);
                    }
                }

                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator in, InputIterator in_e, OutputIterator out) {
                    while (in != in_e) {
                        typedef typename std::iterator_traits<InputIterator>::value_type InValue;
                        InValue const value = *in++;
                        detail::exploder<OutputEndianness, InputValueBits, OutputValueBits>::explode(value, out);
                    }
                }
            };

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits>
            struct packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, true, true, true> {
                template<typename InputIterator, typename OutputIterator>
                inline void pack(InputIterator first, InputIterator last, OutputIterator out) {
                    std::copy(first, last, out);
                }
            };

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits>
            struct packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, false, false, false> {
                BOOST_STATIC_ASSERT(InputValueBits >= octet_bits);

                template<typename InputIterator, typename OutputIterator>
                inline void pack(InputIterator first, InputIterator last, OutputIterator out) {
                    std::transform(first, last, out, [&](typename std::iterator_traits<InputIterator>::value_type &v) {
                        return boost::endian::endian_reverse_inplace(v);
                    });
                }
            };

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits>
            struct packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, false, false, true> { };

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits>
            struct packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, false, true, false> { };

            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits>
            struct packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, false, true, true> {
                BOOST_STATIC_ASSERT(InputValueBits > octet_bits && !(InputValueBits % octet_bits));
                BOOST_STATIC_ASSERT(!(OutputValueBits % octet_bits));

                template<typename InputIterator, typename OutputIterator>
                inline void pack(InputIterator first, InputIterator last, OutputIterator out) {
                    std::transform(first, last, out, [&](typename std::iterator_traits<InputIterator>::value_type &v) {
                        return boost::endian::endian_reverse_inplace(v);
                    });
                }
            };

            template<typename InputEndianness, typename OutputEndianness, size_t InValBits, size_t OutValBits,
                     typename InputIterator, typename OutputIterator>
            static typename std::enable_if<(InValBits == octet_bits) && (InValBits < OutValBits)>::type
                pack(InputIterator in_b, InputIterator in_e, OutputIterator out) {

                BOOST_STATIC_ASSERT(!(OutValBits % octet_bits));

                typedef typename std::iterator_traits<OutputIterator>::value_type OutValue;
                constexpr static size_t const out_octets = OutValBits / octet_bits;

                while (in_b != in_e) {

                    OutValue out_val = OutValue();

                    for (size_t shift = OutValBits, i = 0; i != out_octets; ++i) {
                        shift -= octet_bits;
                        out_val |= unbounded_shl(low_bits<octet_bits>(OutValue(*in_b++)), shift);
                    }

                    *out++ = std::is_same<OutputEndianness, stream_endian::little_octet_big_bit>::value ?
                                 boost::endian::endian_reverse(out_val) :
                                 out_val;
                }
            }

            template<typename InputEndianness, typename OutputEndianness, size_t InValBits, size_t OutValBits,
                     typename InputIterator, typename OutputIterator>
            static
                typename std::enable_if<(InValBits > octet_bits) && (InValBits < OutValBits) &&
                                        std::is_same<InputEndianness, stream_endian::big_octet_big_bit>::value &&
                                        std::is_same<OutputEndianness, stream_endian::big_octet_big_bit>::value>::type
                pack(InputIterator in_b, InputIterator in_e, OutputIterator out) {

                BOOST_STATIC_ASSERT(!(OutValBits % InValBits));

                typedef typename std::iterator_traits<OutputIterator>::value_type OutValue;
                constexpr static size_t const out_invalues = OutValBits / InValBits;

                while (in_b != in_e) {

                    OutValue out_val = OutValue();

                    for (size_t shift = OutValBits, i = 0; i != out_invalues; ++i) {
                        shift -= InValBits;
                        out_val |= unbounded_shl(low_bits<InValBits>(OutValue(*in_b++)), shift);
                    }

                    *out++ = out_val;
                }
            }

            template<typename InputEndianness, typename OutputEndianness, size_t InValBits, size_t OutValBits,
                     typename InputIterator, typename OutputIterator>
            static
                typename std::enable_if<(InValBits > octet_bits) && (InValBits > OutValBits) &&
                                        std::is_same<InputEndianness, stream_endian::big_octet_big_bit>::value &&
                                        std::is_same<OutputEndianness, stream_endian::big_octet_big_bit>::value>::type
                pack(InputIterator in_b, InputIterator in_e, OutputIterator out) {

                BOOST_STATIC_ASSERT(!(InValBits % OutValBits));

                typedef typename std::iterator_traits<OutputIterator>::value_type OutValue;
                constexpr static size_t const in_outvalues = InValBits / OutValBits;

                for (; in_b != in_e; ++in_b)
                    for (size_t shift = InValBits, i = 0; i != in_outvalues; ++i) {
                        shift -= OutValBits;
                        *out++ = OutValue(low_bits<OutValBits>(unbounded_shr(*in_b, shift)));
                    }
            }

            template<typename InputEndianness, typename OutputEndianness, size_t InValBits, size_t OutValBits,
                     typename InputIterator, typename OutputIterator>
            static typename std::enable_if<
                (InValBits > octet_bits) && (InValBits < OutValBits) &&
                std::is_same<InputEndianness, stream_endian::little_octet_big_bit>::value &&
                std::is_same<OutputEndianness, stream_endian::little_octet_big_bit>::value>::type
                pack(InputIterator in_b, InputIterator in_e, OutputIterator out) {

                BOOST_STATIC_ASSERT(!(OutValBits % InValBits));

                typedef typename std::iterator_traits<OutputIterator>::value_type OutValue;
                constexpr static size_t const out_invalues = OutValBits / InValBits;

                while (in_b != in_e) {

                    OutValue out_val = OutValue();

                    for (size_t shift = 0, i = 0; i != out_invalues; shift += InValBits, ++i)
                        out_val |= unbounded_shl(low_bits<InValBits>(OutValue(*in_b++)), shift);

                    *out++ = out_val;
                }
            }

            template<typename InputEndianness, typename OutputEndianness, size_t InValBits, size_t OutValBits,
                     typename InputIterator, typename OutputIterator>
            static typename std::enable_if<
                (InValBits > octet_bits) && (InValBits > OutValBits) &&
                std::is_same<InputEndianness, stream_endian::little_octet_big_bit>::value &&
                std::is_same<OutputEndianness, stream_endian::little_octet_big_bit>::value>::type
                pack(InputIterator in_b, InputIterator in_e, OutputIterator out) {

                BOOST_STATIC_ASSERT(!(InValBits % OutValBits));

                typedef typename std::iterator_traits<OutputIterator>::value_type OutValue;
                constexpr static size_t const in_outvalues = InValBits / OutValBits;

                for (; in_b != in_e; ++in_b)
                    for (size_t shift = 0, i = 0; i != in_outvalues; shift += OutValBits, ++i)
                        *out++ = OutValue(low_bits<OutValBits>(unbounded_shr(*in_b, shift)));
            }

            template<typename InputEndianness, typename OutputEndianness, size_t InValBits, size_t OutValBits,
                     typename InputIterator, typename OutputIterator>
            static typename std::enable_if<
                (InValBits > octet_bits) && (InValBits < OutValBits) &&
                std::is_same<InputEndianness, stream_endian::big_octet_big_bit>::value &&
                std::is_same<OutputEndianness, stream_endian::little_octet_big_bit>::value>::type
                pack(InputIterator in_b, InputIterator in_e, OutputIterator out) {

                BOOST_STATIC_ASSERT(!(OutValBits % InValBits));

                typedef typename std::iterator_traits<OutputIterator>::value_type OutValue;
                constexpr static size_t const out_invalues = OutValBits / InValBits;

                while (in_b != in_e) {

                    OutValue out_val = OutValue();

                    for (size_t shift = OutValBits, i = 0; i != out_invalues; ++i) {
                        shift -= InValBits;
                        out_val |= unbounded_shl(low_bits<InValBits>(OutValue(*in_b++)), shift);
                    }

                    *out++ = boost::endian::endian_reverse(out_val);
                }
            }

            template<typename InputEndianness, typename OutputEndianness, size_t InValBits, size_t OutValBits,
                     typename InputIterator, typename OutputIterator>
            static typename std::enable_if<
                (InValBits > octet_bits) && (InValBits > OutValBits) &&
                std::is_same<InputEndianness, stream_endian::big_octet_big_bit>::value &&
                std::is_same<OutputEndianness, stream_endian::little_octet_big_bit>::value>::type
                pack(InputIterator in_b, InputIterator in_e, OutputIterator out) {

                BOOST_STATIC_ASSERT(!(InValBits % OutValBits));

                typedef typename std::iterator_traits<OutputIterator>::value_type OutValue;
                constexpr static size_t const in_outvalues = InValBits / OutValBits;

                for (; in_b != in_e; ++in_b)
                    for (size_t shift = InValBits, i = 0; i != in_outvalues; ++i) {
                        shift -= OutValBits;
                        *out = OutValue(low_bits<OutValBits>(unbounded_shr(*in_b, shift)));
                        boost::endian::endian_reverse_inplace(*out++);
                    }
            }

            template<typename InputEndianness, typename OutputEndianness, size_t InValBits, size_t OutValBits,
                     typename InputIterator, typename OutputIterator>
            static
                typename std::enable_if<(InValBits > octet_bits) && (InValBits < OutValBits) &&
                                        std::is_same<InputEndianness, stream_endian::little_octet_big_bit>::value &&
                                        std::is_same<OutputEndianness, stream_endian::big_octet_big_bit>::value>::type
                pack(InputIterator in_b, InputIterator in_e, OutputIterator out) {

                BOOST_STATIC_ASSERT(!(OutValBits % InValBits));

                typedef typename std::iterator_traits<InputIterator>::value_type InValue;
                typedef typename std::iterator_traits<OutputIterator>::value_type OutValue;
                constexpr static size_t const out_invalues = OutValBits / InValBits;

                while (in_b != in_e) {

                    OutValue out_val = OutValue();

                    for (size_t shift = OutValBits, i = 0; i != out_invalues; ++i) {
                        InValue in_val = boost::endian::endian_reverse(*in_b++);
                        shift -= InValBits;
                        out_val |= unbounded_shl(low_bits<InValBits>(OutValue(in_val)), shift);
                    }

                    *out++ = out_val;
                }
            }

            template<typename InputEndianness, typename OutputEndianness, size_t InValBits, size_t OutValBits,
                     typename InputIterator, typename OutputIterator>
            static
                typename std::enable_if<(InValBits > octet_bits) && (InValBits > OutValBits) &&
                                        std::is_same<InputEndianness, stream_endian::little_octet_big_bit>::value &&
                                        std::is_same<OutputEndianness, stream_endian::big_octet_big_bit>::value>::type
                pack(InputIterator in_b, InputIterator in_e, OutputIterator out) {

                BOOST_STATIC_ASSERT(!(InValBits % OutValBits));

                typedef typename std::iterator_traits<InputIterator>::value_type InValue;
                typedef typename std::iterator_traits<OutputIterator>::value_type OutValue;
                constexpr static size_t const in_outvalues = InValBits / OutValBits;

                for (; in_b != in_e; ++in_b) {

                    InValue in_val = boost::endian::endian_reverse(*in_b);

                    for (size_t shift = InValBits, i = 0; i != in_outvalues; ++i) {
                        shift -= OutValBits;
                        *out++ = OutValue(low_bits<OutValBits>(unbounded_shr(in_val, shift)));
                    }
                }
            }

            template<typename InputEndianness, typename OutputEndianness, size_t InValBits, size_t OutValBits,
                     typename InputIterator, typename OutputIterator>
            static typename std::enable_if<(InValBits < octet_bits) && (OutValBits == octet_bits) &&
                                           std::is_same<InputEndianness, OutputEndianness>::value &&
                                           std::is_same<InputEndianness, stream_endian::big_bit>::value>::type
                pack(InputIterator in_b, InputIterator in_e, OutputIterator out) {

                BOOST_STATIC_ASSERT(!(octet_bits % InValBits));

                constexpr static size_t const octet_invalues = octet_bits / InValBits;

                while (in_b != in_e) {

                    octet_type out_val = octet_type();

                    for (size_t shift = octet_bits, i = 0; i != octet_invalues; ++i) {
                        shift -= InValBits;
                        out_val |= unbounded_shl(low_bits<InValBits>(octet_type(*in_b++)), shift);
                    }

                    *out++ = out_val;
                }
            }
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_PACK_HPP