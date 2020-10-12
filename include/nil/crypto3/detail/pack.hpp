//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
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

#ifndef CRYPTO3_DETAIL_PACK_HPP
#define CRYPTO3_DETAIL_PACK_HPP

#include <nil/crypto3/detail/type_traits.hpp>
#include <nil/crypto3/detail/stream_endian.hpp>
#include <nil/crypto3/detail/exploder.hpp>
#include <nil/crypto3/detail/imploder.hpp>
#include <nil/crypto3/detail/reverser.hpp>
#include <nil/crypto3/detail/predef.hpp>

#include <boost/static_assert.hpp>
#include <boost/predef/other/endian.h>
#include <boost/predef/architecture.h>

#include <algorithm>
#include <climits>
#include <iterator>
#include <type_traits>

namespace nil {
    namespace crypto3 {
        namespace detail {

            /*!
             * @defgroup pack Pack functions
             */

            /*!
             * @brief The group of traits below is used to determine the possibility of fast data copy.
             * By fast data copy we mean that the data is stored contiguously in the memory, so it can be
             * copied faster byte-by-byte. Currently, fast data copy is implemented by memcpy function call.
             */

            /*!
             * @brief host_can_memcpy trait checks whether the data to be copied and the container to be copied to
             * are byte-aligned. Parameter types InT and OutT may refer to pointed data types or to iterator types.
             *
             * @ingroup pack
             *
             * @tparam UnitBits
             * @tparam ValueBits
             * @tparam InT
             * @tparam OutT
             */
            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct host_can_memcpy {
                constexpr static const bool value = !(UnitBits % CHAR_BIT) && InputBits >= UnitBits &&
                                                    OutputBits >= UnitBits && sizeof(InT) * CHAR_BIT == InputBits &&
                                                    sizeof(OutT) * CHAR_BIT == OutputBits;
            };

            /*!
             * @brief can_memcpy trait is derived from host_can_memcpy trait and is invoked depending on
             * data endianness. Note that there is a single endianness template parameter since otherwise
             * we have to transform data in accordance with endianness conversion rules.
             *
             * @ingroup pack
             *
             * @tparam Endianness
             * @tparam ValueBits
             * @tparam InT
             * @tparam OutT
             */
            template<typename Endianness, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy {
                constexpr static const bool value = InputBits == OutputBits && sizeof(InT) == sizeof(OutT);
            };

            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::host_unit<UnitBits>, InputBits, OutputBits, InT, OutT>
                : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> { };

#ifdef BOOST_ENDIAN_LITTLE_BYTE_AVAILABLE
            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::little_unit_big_bit<UnitBits>, InputBits, OutputBits, InT, OutT>
                : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> { };

            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::little_unit_little_bit<UnitBits>, InputBits, OutputBits, InT, OutT>
                : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> { };

#elif defined(BOOST_ENDIAN_BIG_BYTE_AVAILABLE)
            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::big_unit_big_bit<UnitBits>, ValueBits, InT, OutT>
                : host_can_memcpy<UnitBits, InputBits, OutputBits, InT, OutT> { };
            template<int UnitBits, int InputBits, int OutputBits, typename InT, typename OutT>
            struct can_memcpy<stream_endian::big_unit_little_bit<UnitBits>, ValueBits, InT, OutT>
                : host_can_memcpy<UnitBits, InputBits, OutputBits, , InT, OutT> { };
#endif

            /*!
             * @brief Real_packer is used to transform input data divided into chunks of the bit size InputValueBits
             * represented in input endianness (InputEndianness)
             * into output data (of the same bit length) divided into chunks of the bit size OutputValueBits
             * represented in output endianness (OutputEndianness).
             *
             * The choice of packer depends on the following conditions:
             * 1. input and output chunk size relation (equal, less, or greater);
             * 2. input and output endianness relation (same or different);
             * 3. the possibility of fast data copy using memcpy.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputType
             * @tparam OutputType
             * @tparam SameEndianness
             * @tparam Implode
             * @tparam Explode
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, typename InputType, typename OutputType,
                     bool SameEndianness = std::is_same<InputEndianness, OutputEndianness>::value,
                     bool Implode = (InputValueBits < OutputValueBits),
                     bool Explode = (InputValueBits > OutputValueBits)>
            struct real_packer { };

            /*!
             * @brief This real_packer deals with the case of equal sizes (i.e. InputValueBits == OutputValueBits)
             * and same endianness representations (i.e., speaking informally,
             * InputEndianness == OutputEndianness). It packs input elements with ValueBits size represented
             * in Endianness endianness into output elements with the same ValueBits size represented in the
             * same Endianness endianness.
             *
             * @ingroup pack
             *
             * @tparam Endianness
             * @tparam ValueBits
             * @tparam InputType
             * @tparam OutputType
             */
            template<typename Endianness, std::size_t ValueBits, typename InputType, typename OutputType>
            struct real_packer<Endianness, Endianness, ValueBits, ValueBits, InputType, OutputType, true, false,
                               false> {
                /*!
                 * @brief Packs n InputType elements pointed by constant pointer in
                 * (which, hence, cannot be iterated) into OutType elements pointed by out.
                 * This function is invoked only if memcpy call is possible.
                 *
                 * @ingroup pack
                 *
                 * @param in
                 * @param n
                 * @param out
                 *
                 * @return
                 */
                template<std::size_t InputValueBits, std::size_t OutputValueBits>
                inline static typename std::enable_if<
                    can_memcpy<Endianness, InputValueBits, OutputValueBits, InputType, OutputType>::value>::type
                    pack_n(InputType const *in, std::size_t n, OutputType *out) {
                    std::memcpy(out, in, n * sizeof(InputType));
                }

                /*!
                 * @brief Packs n InputType elements pointed by pointer in into OutType elements pointed by out.
                 * This function is invoked only if memcpy call is possible.
                 *
                 * @ingroup pack
                 *
                 * @param in
                 * @param n
                 * @param out
                 *
                 * @return
                 */
                template<std::size_t InputValueBits, std::size_t OutputValueBits>
                inline static typename std::enable_if<
                    can_memcpy<Endianness, InputValueBits, OutputValueBits, InputType, OutputType>::value>::type
                    pack_n(InputType *in, std::size_t n, OutputType *out) {
                    std::memcpy(out, in, n * sizeof(InputType));
                }

                /*!
                 * @brief Packs in_n elements iterated by in into elements iterated by out.
                 *
                 * @ingroup pack
                 *
                 * @tparam InputIterator
                 * @tparam OutputIterator
                 *
                 * @param in
                 * @param in_n
                 * @param out
                 *
                 * @return
                 */
                template<typename InputIterator, typename OutputIterator>
                inline static void pack_n(InputIterator in, std::size_t in_n, OutputIterator out) {
                    std::copy(in, in + in_n, out);
                }

                /*!
                 * @brief Packs elements in range [first, last) into elements iterated by out.
                 * This function is invoked only if input and output iterators meet RandomAccessIterator
                 * requirements. However, the restriction can be weakened to ContiguousIterator usage.
                 *
                 * @ingroup pack
                 *
                 * @tparam InputIterator
                 * @tparam OutputIterator
                 *
                 * @param first
                 * @param last
                 * @param random_access_iterator_tag
                 * @param out
                 * @param random_access_iterator_tag
                 *
                 * @return
                 */
                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator first, InputIterator last, std::random_access_iterator_tag,
                                        OutputIterator out, std::random_access_iterator_tag) {
                    pack_n(first, std::distance(first, last), out);
                }

                /*!
                 * @brief Packs elements in range [first, last) into elements iterated by out.
                 * This function is invoked only if input or output iterator doesn't meet RandomAccessIterator
                 * requirements.
                 *
                 * @ingroup pack
                 *
                 * @tparam InputIterator
                 * @tparam InCatT
                 * @tparam OutputIterator
                 * @tparam OutCatT
                 *
                 * @param first
                 * @param last
                 * @param InCatT
                 * @param out
                 * @param OutCatT
                 *
                 * @return
                 */
                template<typename InputIterator, typename InCatT, typename OutputIterator, typename OutCatT>
                inline static void pack(InputIterator first, InputIterator last, InCatT, OutputIterator out, OutCatT) {
                    std::copy(first, last, out);
                }

                /*!
                 * @brief Generic function that chooses pack function depending on input and output iterator category.
                 *
                 * @ingroup pack
                 *
                 * @tparam InputIterator
                 * @tparam OutputIterator
                 *
                 * @param first
                 * @param last
                 * @param out
                 *
                 * @return
                 */
                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator first, InputIterator last, OutputIterator out) {

                    typedef typename std::iterator_traits<InputIterator>::iterator_category in_cat;
                    typedef typename std::iterator_traits<OutputIterator>::iterator_category out_cat;

                    pack(first, last, in_cat(), out, out_cat());
                }
            };

            /*!
             * @brief This real_packer deals with the case of equal sizes (i.e. InputValueBits == OutputValueBits)
             * and different endianness representations (or, speaking informally,
             * InputEndianness != OutputEndianness). It invokes functions which pack input elements
             * with ValueBits size represented in InputEndianness endianness into output elements
             * with the same ValueBits size represented in another OutputEndianness endianness.
             *
             * @ingroup pack
             *
             * @tparam UnitBits
             * @tparam InputEndian
             * @tparam OutputEndian
             * @tparam ValueBits
             * @tparam InputType
             * @tparam OutputType
             */
            template<int UnitBits, template<int> class InputEndian, template<int> class OutputEndian,
                     std::size_t ValueBits, typename InputType, typename OutputType>
            struct real_packer<InputEndian<UnitBits>, OutputEndian<UnitBits>, ValueBits, ValueBits, InputType,
                               OutputType, false, false, false> {

                typedef InputEndian<UnitBits> InputEndianness;
                typedef OutputEndian<UnitBits> OutputEndianness;

                typedef unit_reverser<InputEndianness, OutputEndianness, UnitBits> units_reverser;
                typedef bit_reverser<InputEndianness, OutputEndianness, UnitBits> bits_reverser;

                template<typename InputIterator, typename OutputIterator>
                inline static void pack_n(InputIterator in, std::size_t in_n, OutputIterator out) {

                    std::transform(in, in + in_n, out, [](InputType const &elem) {
                        return units_reverser::reverse(bits_reverser::reverse(elem));
                    });
                }

                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator first, InputIterator last, OutputIterator out) {

                    std::transform(first, last, out, [](InputType const &elem) {
                        return units_reverser::reverse(bits_reverser::reverse(elem));
                    });
                }
            };

            /*!
             * @brief This real_packer deals with case InputValueBits < OutputValueBits and invokes implode function,
             * which, in its turn, packs input elements with InputValueBits size represented in InputEndianness
             * endianness into output elements with OutputValueBits size represented in OutputEndianness
             * endianness.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputType
             * @tparam OutputType
             * @tparam SameEndianness
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, typename InputType, typename OutputType, bool SameEndianness>
            struct real_packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, InputType,
                               OutputType, SameEndianness, true, false> {

                BOOST_STATIC_ASSERT(!(OutputValueBits % InputValueBits));

                typedef detail::imploder<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits> imploder;

                template<typename InputIterator, typename OutputIterator>
                inline static void pack_n(InputIterator in, std::size_t in_n, OutputIterator out) {
                    std::size_t out_n = in_n / (OutputValueBits / InputValueBits);

                    while (out_n--) {
                        OutputType value = OutputType();
                        imploder::implode(in, value);
                        *out++ = value;
                    }
                }

                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator first, InputIterator last, OutputIterator out) {
                    while (first != last) {
                        OutputType value = OutputType();
                        imploder::implode(first, value);
                        *out++ = value;
                    }
                }
            };

            /*!
             * @brief This real_packer deals with case InputValueBits > OutputValueBits and invokes explode function,
             * which, in its turn, packs input elements with InputValueBits size represented in InputEndianness
             * endianness into output elements with OutputValueBits size represented in OutputEndianness
             * endianness.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputType
             * @tparam OutputType
             * @tparam SameEndianness
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, typename InputType, typename OutputType, bool SameEndianness>
            struct real_packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, InputType,
                               OutputType, SameEndianness, false, true> {

                BOOST_STATIC_ASSERT(!(InputValueBits % OutputValueBits));

                typedef detail::exploder<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits> exploder;

                template<typename InputIterator, typename OutputIterator>
                inline static void pack_n(InputIterator in, std::size_t in_n, OutputIterator out) {
                    while (in_n--) {
                        InputType const value = *in++;
                        exploder::explode(value, out);
                    }
                }

                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator first, InputIterator last, OutputIterator out) {
                    while (first != last) {
                        InputType const value = *first++;
                        exploder::explode(value, out);
                    }
                }
            };

            /*!
             * @brief This packer deals with arbitrary input and output (but not bool) data elements.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputType
             * @tparam OutputType
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, typename InputType, typename OutputType>
            struct packer {

                template<typename InputIterator, typename OutputIterator>
                inline static void pack_n(InputIterator in, std::size_t n, OutputIterator out) {
                    typedef real_packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, InputType,
                                        OutputType>
                        packer_type;

                    packer_type::pack_n(in, n, out);
                }

                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator first, InputIterator last, OutputIterator out) {
                    typedef real_packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, InputType,
                                        OutputType>
                        packer_type;

                    packer_type::pack(first, last, out);
                }
            };

            /*!
             * @brief This packer deals with bool input and output data elements.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits>
            struct packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, bool, bool> {

                template<typename InputIterator, typename OutputIterator>
                inline static void pack_n(InputIterator in, std::size_t n, OutputIterator out) {
                    typedef real_packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, bool, bool>
                        packer_type;

                    packer_type::pack_n(in, n, out);
                }

                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator first, InputIterator last, OutputIterator out) {
                    typedef real_packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, bool, bool>
                        packer_type;

                    packer_type::pack(first, last, out);
                }
            };

            /*!
             * @brief This packer deals with bool input data and arbitrary (but not bool) output data elements.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam OutputType
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, typename OutputType>
            struct packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, bool, OutputType> {

                template<typename InputIterator, typename OutputIterator>
                inline static void pack_n(InputIterator in, std::size_t n, OutputIterator out) {
                    typedef real_packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, bool,
                                        OutputType>
                        packer_type;

                    packer_type::pack_n(in, n, out);
                }

                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator first, InputIterator last, OutputIterator out) {
                    typedef real_packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, bool,
                                        OutputType>
                        packer_type;

                    packer_type::pack(first, last, out);
                }
            };

            /*!
             * @brief This packer deals with arbitrary (but not bool) input data and bool output data elements.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputType
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, typename InputType>
            struct packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, InputType, bool> {

                template<typename InputIterator, typename OutputIterator>
                inline static void pack_n(InputIterator in, std::size_t n, OutputIterator out) {
                    typedef real_packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, InputType,
                                        bool>
                        packer_type;

                    packer_type::pack_n(in, n, out);
                }

                template<typename InputIterator, typename OutputIterator>
                inline static void pack(InputIterator first, InputIterator last, OutputIterator out) {
                    typedef real_packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, InputType,
                                        bool>
                        packer_type;

                    packer_type::pack(first, last, out);
                }
            };

            /*!
             * @brief Packs elements from range [first, last) represented in machine-dependent endianness
             * into elements starting from out represented in OutputEndianness endianness.
             *
             * @ingroup pack
             *
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputIterator
             * @tparam OutputIterator
             *
             * @param first
             * @param last
             * @param out
             *
             * @return
             */
            template<typename OutputEndianness, std::size_t InputValueBits, std::size_t OutputValueBits,
                     typename InputIterator, typename OutputIterator>
            inline void pack_to(InputIterator first, InputIterator last, OutputIterator out) {

                typedef typename std::iterator_traits<InputIterator>::value_type InputType;
                typedef typename std::iterator_traits<OutputIterator>::value_type OutputType;

#ifdef BOOST_ENDIAN_BIG_BYTE_AVAILABLE
                typedef packer<stream_endian::big_octet_big_bit, OutputEndianness, InputValueBits, OutputValueBits,
                               InputType, OutputType>
                    packer_type;
#elif defined(BOOST_ENDIAN_LITTLE_BYTE_AVAILABLE)
                typedef packer<stream_endian::little_octet_big_bit, OutputEndianness, InputValueBits, OutputValueBits,
                               InputType, OutputType>
                    packer_type;
#elif defined(BOOST_ENDIAN_BIG_WORD_AVAILABLE)
                typedef packer<stream_endian::big_unit_big_bit<BOOST_ARCH_CURRENT_WORD_BITS>, OutputEndianness,
                               InputValueBits, OutputValueBits, InputType, OutputType>
                    packer_type;
#elif defined(BOOST_ENDIAN_LITTLE_WORD_AVAILABLE)
                typedef packer<stream_endian::little_unit_big_bit<BOOST_ARCH_CURRENT_WORD_BITS>, OutputEndianness,
                               InputValueBits, OutputValueBits, InputType, OutputType>
                    packer_type;
#else
#error "Unknown endianness"
#endif

                packer_type::pack(first, last, out);
            }

            /*!
             * @brief Packs elements from range [first, last) represented in InputEndianness endianness
             * into elements starting from out represented in machine-dependent endianness.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputIterator
             * @tparam OutputIterator
             *
             * @param first
             * @param last
             * @param out
             *
             * @return
             */
            template<typename InputEndianness, std::size_t InputValueBits, std::size_t OutputValueBits,
                     typename InputIterator, typename OutputIterator>
            inline void pack_from(InputIterator first, InputIterator last, OutputIterator out) {

                typedef typename std::iterator_traits<InputIterator>::value_type InputType;
                typedef typename std::iterator_traits<OutputIterator>::value_type OutputType;

#ifdef BOOST_ENDIAN_BIG_BYTE_AVAILABLE
                typedef packer<InputEndianness, stream_endian::big_octet_big_bit, InputValueBits, OutputValueBits,
                               InputType, OutputType>
                    packer_type;
#elif defined(BOOST_ENDIAN_LITTLE_BYTE_AVAILABLE)
                typedef packer<InputEndianness, stream_endian::little_octet_big_bit, InputValueBits, OutputValueBits,
                               InputType, OutputType>
                    packer_type;
#elif defined(BOOST_ENDIAN_BIG_WORD_AVAILABLE)
                typedef packer<InputEndianness, stream_endian::big_unit_big_bit<BOOST_ARCH_CURRENT_WORD_BITS>,
                               InputValueBits, OutputValueBits, InputType, OutputType>
                    packer_type;
#elif defined(BOOST_ENDIAN_LITTLE_WORD_AVAILABLE)
                typedef packer<InputEndianness, stream_endian::little_unit_big_bit<BOOST_ARCH_CURRENT_WORD_BITS>,
                               InputValueBits, OutputValueBits, InputType, OutputType>
                    packer_type;
#else
#error "Unknown endianness"
#endif

                packer_type::pack(first, last, out);
            }

            /*!
             * @brief Packs elements from range [first, last) represented in machine-dependent endianness
             * into elements starting from out represented in OutputEndianness endianness.
             *
             * @ingroup pack
             *
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputIterator
             * @tparam OutputIterator
             *
             * @param first
             * @param last
             * @param out
             *
             * @return
             */
            template<typename OutputEndianness, std::size_t InputValueBits, std::size_t OutputValueBits,
                     typename InputRange, typename OutputIterator>
            inline void pack_to(const InputRange &r, OutputIterator out) {

                typedef typename std::iterator_traits<typename InputRange::iterator>::value_type InputType;
                typedef typename std::iterator_traits<OutputIterator>::value_type OutputType;

#ifdef BOOST_ENDIAN_BIG_BYTE_AVAILABLE
                typedef packer<stream_endian::big_octet_big_bit, OutputEndianness, InputValueBits, OutputValueBits,
                               InputType, OutputType>
                    packer_type;
#elif defined(BOOST_ENDIAN_LITTLE_BYTE_AVAILABLE)
                typedef packer<stream_endian::little_octet_big_bit, OutputEndianness, InputValueBits, OutputValueBits,
                               InputType, OutputType>
                    packer_type;
#elif defined(BOOST_ENDIAN_BIG_WORD_AVAILABLE)
                typedef packer<stream_endian::big_unit_big_bit<BOOST_ARCH_CURRENT_WORD_BITS>, OutputEndianness,
                               InputValueBits, OutputValueBits, InputType, OutputType>
                    packer_type;
#elif defined(BOOST_ENDIAN_LITTLE_WORD_AVAILABLE)
                typedef packer<stream_endian::little_unit_big_bit<BOOST_ARCH_CURRENT_WORD_BITS>, OutputEndianness,
                               InputValueBits, OutputValueBits, InputType, OutputType>
                    packer_type;
#else
#error "Unknown endianness"
#endif

                packer_type::pack(std::begin(r), std::end(r), out);
            }

            /*!
             * @brief Packs elements from range [first, last) represented in InputEndianness endianness
             * into elements starting from out represented in machine-dependent endianness.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputIterator
             * @tparam OutputIterator
             *
             * @param first
             * @param last
             * @param out
             *
             * @return
             */
            template<typename InputEndianness, std::size_t InputValueBits, std::size_t OutputValueBits,
                     typename InputRange, typename OutputIterator>
            inline void pack_from(const InputRange &r, OutputIterator out) {

                typedef typename std::iterator_traits<typename InputRange::iterator>::value_type InputType;
                typedef typename std::iterator_traits<OutputIterator>::value_type OutputType;

#ifdef BOOST_ENDIAN_BIG_BYTE_AVAILABLE
                typedef packer<InputEndianness, stream_endian::big_octet_big_bit, InputValueBits, OutputValueBits,
                               InputType, OutputType>
                    packer_type;
#elif defined(BOOST_ENDIAN_LITTLE_BYTE_AVAILABLE)
                typedef packer<InputEndianness, stream_endian::little_octet_big_bit, InputValueBits, OutputValueBits,
                               InputType, OutputType>
                    packer_type;
#elif defined(BOOST_ENDIAN_BIG_WORD_AVAILABLE)
                typedef packer<InputEndianness, stream_endian::big_unit_big_bit<BOOST_ARCH_CURRENT_WORD_BITS>,
                               InputValueBits, OutputValueBits, InputType, OutputType>
                    packer_type;
#elif defined(BOOST_ENDIAN_LITTLE_WORD_AVAILABLE)
                typedef packer<InputEndianness, stream_endian::little_unit_big_bit<BOOST_ARCH_CURRENT_WORD_BITS>,
                               InputValueBits, OutputValueBits, InputType, OutputType>
                    packer_type;
#else
#error "Unknown endianness"
#endif

                packer_type::pack(std::begin(r), std::end(r), out);
            }

            /*!
             * @brief Packs in_n input elements starting from in into output elements beginning from out.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputIterator
             * @tparam OutputIterator
             *
             * @param in
             * @param in_n
             * @param out
             *
             * @return
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, typename InputIterator, typename OutputIterator>
            inline void pack_n(InputIterator in, std::size_t in_n, OutputIterator out) {
                typedef typename std::iterator_traits<InputIterator>::value_type InputType;
                typedef typename std::iterator_traits<OutputIterator>::value_type OutputType;
                typedef packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, InputType,
                               OutputType>
                    packer_type;

                packer_type::pack_n(in, in_n, out);
            }

            /*!
             * @brief Packs in_n input elements starting from in into in_out elements beginning from out.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputIterator
             * @tparam OutputIterator
             *
             * @param in
             * @param in_n
             * @param out
             * @param out_n
             *
             * @return
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, typename InputIterator, typename OutputIterator>
            inline void pack_n(InputIterator in, std::size_t in_n, OutputIterator out, std::size_t out_n) {
                BOOST_ASSERT(in_n * InputValueBits == out_n * OutputValueBits);

                pack_n<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>(in, in_n, out);
            }

            /*!
             * @brief Packs elements from the range [first, last) into elements starting from out.
             * Works for input containers meeting RandomAccessIterator requirements.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputIterator
             * @tparam OutputIterator
             *
             * @param first
             * @param last
             * @param random_access_iterator_tag
             * @param out
             *
             * @return
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, typename InputIterator, typename OutputIterator>
            inline void pack(InputIterator first, InputIterator last, std::random_access_iterator_tag,
                             OutputIterator out) {
                pack_n<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>(first, last - first, out);
            }

            /*!
             * @brief Packs elements from the range [first, last) into elements starting from out.
             * Works for input containers meeting InCatT category requirements and output containers
             * meeting OutputIterator requirements.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputIterator
             * @tparam InCatT
             * @tparam OutputIterator
             *
             * @param first
             * @param last
             * @param InCatT
             * @param out
             *
             * @return
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, typename InputIterator, typename InCatT, typename OutputIterator,
                     typename = typename std::enable_if<detail::is_iterator<InputIterator>::value>::type,
                     typename = typename std::enable_if<detail::is_iterator<OutputIterator>::value>::type>
            inline void pack(InputIterator first, InputIterator last, InCatT, OutputIterator out) {
                typedef typename std::iterator_traits<InputIterator>::value_type InputType;
                typedef typename std::iterator_traits<OutputIterator>::value_type OutputType;
                typedef packer<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits, InputType,
                               OutputType>
                    packer_type;

                packer_type::pack(first, last, out);
            }

            /*!
             * @brief Generic function that chooses pack function depending on input iterator category.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputIterator
             * @tparam OutputIterator
             *
             * @param first
             * @param last
             * @param out
             *
             * @return
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, typename InputIterator, typename OutputIterator,
                     typename = typename std::enable_if<detail::is_iterator<OutputIterator>::value>::type>
            inline void pack(InputIterator first, InputIterator last, OutputIterator out) {
                typedef typename std::iterator_traits<InputIterator>::iterator_category in_cat;

                pack<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>(first, last, in_cat(), out);
            }

            /*!
             * @brief Packs elements from the range [first, last) into elements starting from out.
             * Works for input and output containers meeting RandomAccessIterator requirements.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputIterator
             * @tparam OutputIterator
             *
             * @param in_first
             * @param in_last
             * @param random_access_iterator_tag
             * @param out_first
             * @param out_last
             * @param random_access_iterator_tag
             *
             * @return
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, typename InputIterator, typename OutputIterator>
            inline void pack(InputIterator in_first, InputIterator in_last, std::random_access_iterator_tag,
                             OutputIterator out_first, OutputIterator out_last, std::random_access_iterator_tag) {
                pack_n<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>(
                    in_first, in_last - in_first, out_first, out_last - out_first);
            }

            /*!
             * @brief Packs elements from the range [first, last) into elements starting from out.
             * Works for input containers meeting InCatT category requirements and output containers
             * meeting OutCatT category requirements.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputIterator
             * @tparam InCatT
             * @tparam OutputIterator
             * @tparam OutCatT
             *
             * @param in_first
             * @param in_last
             * @param InCatT
             * @param out
             * @param OutputIterator
             * @param OutCatT
             *
             * @return
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, typename InputIterator, typename InCatT, typename OutputIterator,
                     typename OutCatT>
            inline void pack(InputIterator in_first, InputIterator in_last, InCatT, OutputIterator out, OutputIterator,
                             OutCatT) {
                pack<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>(in_first, in_last, out);
            }

            /*!
             * @brief Generic function that chooses pack function depending on input and output iterator category.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputIterator
             * @tparam OutputIterator
             *
             * @param in_first
             * @param in_last
             * @param out_first
             * @param out_last
             *
             * @return
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, typename InputIterator, typename OutputIterator>
            inline void pack(InputIterator in_first, InputIterator in_last, OutputIterator out_first,
                             OutputIterator out_last) {
                typedef typename std::iterator_traits<InputIterator>::iterator_category in_cat;
                typedef typename std::iterator_traits<OutputIterator>::iterator_category out_cat;

                pack<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>(
                    in_first, in_last, in_cat(), out_first, out_last, out_cat());
            }

            /*!
             * @brief Packs immutable data referenced by in into data referenced by out.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputType
             * @tparam OutputType
             *
             * @param in
             * @param out
             *
             * @return
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, typename InputType, typename OutputType>
            inline void pack(const InputType &in, OutputType &out) {
                pack_n<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>(in.begin(), in.size(),
                                                                                           out.begin(), out.size());
            }

            /*!
             * @brief Packs elements from range [first, last) into data referenced by out with
             * non-arithmetic value type.
             *
             * @ingroup pack
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputValueBits
             * @tparam OutputValueBits
             * @tparam InputType
             * @tparam OutputType
             *
             * @param in
             * @param out
             *
             * @return
             */
            template<typename InputEndianness, typename OutputEndianness, std::size_t InputValueBits,
                     std::size_t OutputValueBits, typename InputIterator, typename OutputType,
                     typename = typename std::enable_if<!std::is_arithmetic<OutputType>::value>::type>
            inline void pack(InputIterator first, InputIterator last, OutputType &out) {
                pack_n<InputEndianness, OutputEndianness, InputValueBits, OutputValueBits>(
                    first, std::distance(first, last), out.begin(), out.size());
            }

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_PACK_HPP