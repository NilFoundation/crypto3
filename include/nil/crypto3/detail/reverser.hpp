//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
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

#ifndef CRYPTO3_DETAIL_REVERSER_HPP
#define CRYPTO3_DETAIL_REVERSER_HPP

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>
#include <boost/endian/conversion.hpp>

#include <nil/crypto3/detail/unbounded_shift.hpp>
#include <nil/crypto3/detail/stream_endian.hpp>
#include <nil/crypto3/detail/predef.hpp>

#include <climits>

namespace nil {
    namespace crypto3 {
        namespace detail {

            /*!
             * @defgroup reverser Reverser functions
             */

            typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;

            /*!
             * @brief This function reverses bit order in the byte b depending on the machine word size.
             * The underlying algorithms used in this function are described in
             * http://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith32Bits and in
             * http://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith64BitsDiv .
             *
             * @ingroup reverser
             *
             * @param b
             *
             * @return
             */
            inline void reverse_byte(byte_type &b) {

#if (BOOST_ARCH_CURRENT_WORD_BITS == 32)
                b = unbounded_shr<16>(((b * 0x0802LU & 0x22110LU) | (b * 0x8020LU & 0x88440LU)) * 0x10101LU);
#elif (BOOST_ARCH_CURRENT_WORD_BITS == 64)
                b = (b * 0x0202020202ULL & 0x010884422010ULL) % 1023;
#else
#error "BOOST_ARCH_CURRENT_WORD_BITS not set"
#endif
            }

            /*!
             * @brief bit_in_unit_byte_reverser transforms the sequence of bits in each byte of
             * the input unit into reversed sequence of bits in each byte of the output unit.
             * The function reverse is recursively invoked and the parameter k is used to track
             * the number of already processed input bytes. The recursion ends, when all input
             * bytes have been processed, i.e. when k == UnitBits.
             *
             * @ingroup reverser
             *
             * @tparam UnitBits
             * @tparam k
             */
            template<int UnitBits, int k = 0>
            struct bit_in_unit_byte_reverser {

                BOOST_STATIC_ASSERT(!(UnitBits % CHAR_BIT));

                typedef bit_in_unit_byte_reverser<UnitBits, k + CHAR_BIT> next_type;
                typedef typename boost::uint_t<UnitBits>::exact UnitType;

                inline static void reverse(UnitType &in, UnitType &out) {
                    int const shift = UnitBits - (CHAR_BIT + k);
                    byte_type byte = byte_type(low_bits<CHAR_BIT>(unbounded_shr(in, shift)));
                    reverse_byte(byte);
                    out |= unbounded_shl(low_bits<CHAR_BIT>(UnitType(byte)), shift);

                    next_type::reverse(in, out);
                }
            };

            template<int UnitBits>
            struct bit_in_unit_byte_reverser<UnitBits, UnitBits> {
                inline static void reverse(typename boost::uint_t<UnitBits>::exact &,
                                           typename boost::uint_t<UnitBits>::exact &) {
                }
            };

            /*!
             * @brief The functions listed below deal with bit reversal in a unit.
             */

            /*!
             * @brief This function deals with the case of UnitBits > CHAR_BIT. To reverse
             * the order of bits, first, it reverses the byte order of unit, and then, it
             * invokes bit_in_unit_byte_reverser to reverse bits in each byte of unit.
             *
             * @ingroup reverser
             *
             * @tparam UnitType
             * @tparam UnitBits
             *
             * @param unit
             *
             * @return
             */
            template<typename UnitType,
                     int UnitBits = sizeof(UnitType) * CHAR_BIT,
                     typename std::enable_if<(UnitBits > CHAR_BIT), int>::type = 0>
            inline void reverse_bits(UnitType &unit) {
                boost::endian::endian_reverse_inplace(unit);
                UnitType out = UnitType();
                bit_in_unit_byte_reverser<UnitBits>::reverse(unit, out);
                unit = out;
            }
            /*!
             * @brief This function deals with the special case of UnitBits == CHAR_BIT,
             * it just reverses the bit order in the byte.
             * @ingroup reverser
             *
             * @tparam UnitType
             * @tparam UnitBits
             *
             * @param unit
             *
             * @return
             */
            template<typename UnitType,
                     int UnitBits = sizeof(UnitType) * CHAR_BIT,
                     typename std::enable_if<(UnitBits == CHAR_BIT), int>::type = 0>
            inline void reverse_bits(UnitType &unit) {
                reverse_byte(unit);
            }

            /*!
             * @brief bit_in_unit_reverser transforms the sequence of bits in each unit of
             * the input value into reversed sequence of bytes in each unit of the output value.
             * The function reverse is recursively invoked and the parameter k is used to track
             * the number of already processed input units. The recursion ends, when all input
             * units have been processed, i.e. when k == InputBits.
             *
             * @ingroup reverser
             *
             * @tparam InputBits
             * @tparam UnitBits
             * @tparam k
             */
            template<int InputBits, int UnitBits, int k = 0>
            struct bit_in_unit_reverser {

                BOOST_STATIC_ASSERT(!(InputBits % UnitBits) && !(UnitBits % CHAR_BIT));

                typedef bit_in_unit_reverser<InputBits, UnitBits, k + UnitBits> next_type;
                typedef typename boost::uint_t<UnitBits>::exact UnitType;

                template<typename ValueType>
                inline static void reverse(ValueType &in, ValueType &out) {
                    int const shift = InputBits - (UnitBits + k);
                    UnitType unit = UnitType(low_bits<UnitBits>(unbounded_shr(in, shift)));
                    reverse_bits(unit);
                    out |= unbounded_shl(low_bits<UnitBits>(ValueType(unit)), shift);

                    next_type::reverse(in, out);
                }
            };

            template<int InputBits, int UnitBits>
            struct bit_in_unit_reverser<InputBits, UnitBits, InputBits> {
                template<typename ValueType>
                inline static void reverse(ValueType &, ValueType &) {
                }
            };

            /*!
             * @brief The group of traits below is used to determine the order of bits defined
             * by the endianness.
             */

            /*!
             * @brief Trait to determine whether the order of bits defined by Endianness endianness
             * is big.
             *
             * @ingroup reverser
             *
             * @tparam Endianness
             * @tparam UnitBits
             */
            template<typename Endianness, int UnitBits>
            struct is_big_bit {
                constexpr static const bool value =
                    std::is_same<Endianness, stream_endian::big_unit_big_bit<UnitBits>>::value ||
                    std::is_same<Endianness, stream_endian::little_unit_big_bit<UnitBits>>::value;
            };

            /*!
             * @brief Trait to determine whether the order of bits defined by Endianness endianness
             * is little.
             *
             * @ingroup reverser
             *
             * @tparam Endianness
             * @tparam UnitBits
             */
            template<typename Endianness, int UnitBits>
            struct is_little_bit {
                constexpr static const bool value =
                    std::is_same<Endianness, stream_endian::big_unit_little_bit<UnitBits>>::value ||
                    std::is_same<Endianness, stream_endian::little_unit_little_bit<UnitBits>>::value;
            };

            /*!
             * @brief Trait to determine whether the orders of bits defined by Endianness1 endianness
             * and Endianness2 endianness are the same.
             *
             * @ingroup reverser
             *
             * @tparam Endianness1
             * @tparam Endianness2
             * @tparam UnitBits
             */
            template<typename Endianness1, typename Endianness2, int UnitBits>
            struct is_same_bit {
                constexpr static const bool value =
                    (is_big_bit<Endianness1, UnitBits>::value && is_big_bit<Endianness2, UnitBits>::value) ||
                    (is_little_bit<Endianness1, UnitBits>::value && is_little_bit<Endianness2, UnitBits>::value);
            };

            /*!
             * @brief bit_reverser reverses the sequence of bits in each unit of the given value,
             * if InputEndianness and OutputEndianness endiannesses have different bit orders, and
             * does nothing, otherwise.
             *
             * @ingroup reverser
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam UnitBits
             * @tparam IsSameBit
             */
            template<typename InputEndianness,
                     typename OutputEndianness,
                     int UnitBits,
                     bool IsSameBit = is_same_bit<InputEndianness, OutputEndianness, UnitBits>::value>
            struct bit_reverser;

            /*!
             * @brief This bit_reverser is a dummy and deals with the case of the endiannesses with
             * the same order of bits.
             *
             * @ingroup reverser
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam UnitBits
             */
            template<typename InputEndianness, typename OutputEndianness, int UnitBits>
            struct bit_reverser<InputEndianness, OutputEndianness, UnitBits, true> {
                template<typename ValueType>
                inline static void reverse(ValueType &) {
                }

                template<typename ValueType>
                inline static ValueType reverse(ValueType const &val) {
                    return val;
                }
            };

            /*!
             * @brief This bit_reverser deals with the case of the endiannesses with different order of
             * bits and invokes bit_in_unit_reverser which reverses bits in each unit of the input value.
             *
             * @ingroup reverser
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam UnitBits
             */
            template<typename InputEndianness, typename OutputEndianness, int UnitBits>
            struct bit_reverser<InputEndianness, OutputEndianness, UnitBits, false> {
                template<typename ValueType, int ValueBits = sizeof(ValueType) * CHAR_BIT>
                inline static void reverse(ValueType &val) {
                    ValueType out = ValueType();
                    bit_in_unit_reverser<ValueBits, UnitBits>::reverse(val, out);
                    val = out;
                }

                template<typename ValueType, int ValueBits = sizeof(ValueType) * CHAR_BIT>
                inline static ValueType reverse(ValueType const &val) {
                    ValueType tmp = val;
                    ValueType out = ValueType();
                    bit_in_unit_reverser<ValueBits, UnitBits>::reverse(tmp, out);
                    return out;
                }
            };

            /*!
             * @brief byte_in_unit_reverser transforms the sequence of bytes in each unit of
             * the input value into reversed sequence of bytes in each unit of the output value.
             * The function reverse is recursively invoked and the parameter k is used to track
             * the number of already processed input units. The recursion ends, when all input
             * units have been processed, i.e. when k == InputBits.
             *
             * @ingroup reverser
             *
             * @tparam InputBits
             * @tparam UnitBits
             * @tparam k
             */
            template<int InputBits, int UnitBits, int k = 0>
            struct byte_in_unit_reverser {

                BOOST_STATIC_ASSERT(!(InputBits % UnitBits) && !(UnitBits % CHAR_BIT));

                typedef byte_in_unit_reverser<InputBits, UnitBits, k + UnitBits> next_type;
                typedef typename boost::uint_t<UnitBits>::exact UnitType;

                template<typename ValueType>
                inline static void reverse(ValueType &in, ValueType &out) {
                    int const shift = InputBits - (UnitBits + k);
                    UnitType unit = UnitType(low_bits<UnitBits>(unbounded_shr(in, shift)));
                    boost::endian::endian_reverse_inplace(unit);
                    out |= unbounded_shl(low_bits<UnitBits>(ValueType(unit)), shift);

                    next_type::reverse(in, out);
                }
            };

            template<int InputBits, int UnitBits>
            struct byte_in_unit_reverser<InputBits, UnitBits, InputBits> {
                template<typename ValueType>
                inline static void reverse(ValueType &, ValueType &) {
                }
            };

            /*!
             * @brief The group of traits below is used to determine the order of units defined
             * by the endianness.
             */

            /*!
             * @brief Trait to determine whether the order of units defined by Endianness endianness
             * is big.
             *
             * @ingroup reverser
             *
             * @tparam Endianness
             * @tparam UnitBits
             */
            template<typename Endianness, int UnitBits>
            struct is_big_unit {
                constexpr static const bool value =
                    std::is_same<Endianness, stream_endian::big_unit_big_bit<UnitBits>>::value ||
                    std::is_same<Endianness, stream_endian::big_unit_little_bit<UnitBits>>::value;
            };

            /*!
             * @brief Trait to determine whether the order of units defined by Endianness endianness
             * is little.
             *
             * @ingroup reverser
             *
             * @tparam Endianness
             * @tparam UnitBits
             */
            template<typename Endianness, int UnitBits>
            struct is_little_unit {
                constexpr static const bool value =
                    std::is_same<Endianness, stream_endian::little_unit_big_bit<UnitBits>>::value ||
                    std::is_same<Endianness, stream_endian::little_unit_little_bit<UnitBits>>::value;
            };

            /*!
             * @brief Trait to determine whether the orders of units defined by Endianness1 endianness
             * and Endianness2 endianness are the same.
             *
             * @ingroup reverser
             *
             * @tparam Endianness1
             * @tparam Endianness2
             * @tparam UnitBits
             */
            template<typename Endianness1, typename Endianness2, int UnitBits>
            struct is_same_unit {
                constexpr static const bool value =
                    (is_big_unit<Endianness1, UnitBits>::value && is_big_unit<Endianness2, UnitBits>::value) ||
                    (is_little_unit<Endianness1, UnitBits>::value && is_little_unit<Endianness2, UnitBits>::value);
            };

            /*!
             * @brief unit_reverser reverses the sequence of units in the given value, if InputEndianness
             * and OutputEndianness endiannesses have different unit orders, and does nothing, otherwise.
             *
             * @ingroup reverser
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam UnitBits
             * @tparam Enable
             */
            template<typename InputEndianness, typename OutputEndianness, int UnitBits, typename Enable = void>
            struct unit_reverser;

            /*!
             * @brief This unit_reverser is a dummy and deals with the case of the endiannesses with
             * the same order of units.
             *
             * @ingroup reverser
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam UnitBits
             */
            template<typename InputEndianness, typename OutputEndianness, int UnitBits>
            struct unit_reverser<
                InputEndianness,
                OutputEndianness,
                UnitBits,
                typename std::enable_if<is_same_unit<InputEndianness, OutputEndianness, UnitBits>::value>::type> {
                template<typename ValueType>
                inline static void reverse(ValueType &) {
                }

                template<typename ValueType>
                inline static ValueType reverse(ValueType const &val) {
                    return val;
                }
            };

            /*!
             * @brief This unit_reverser deals with the case of UnitBits == CHAR_BIT. This case is
             * special since it is sufficient to reverse the order of bytes in an input value.
             *
             * @ingroup reverser
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam UnitBits
             */
            template<typename InputEndianness, typename OutputEndianness, int UnitBits>
            struct unit_reverser<
                InputEndianness,
                OutputEndianness,
                UnitBits,
                typename std::enable_if<!is_same_unit<InputEndianness, OutputEndianness, UnitBits>::value &&
                                        UnitBits == CHAR_BIT>::type> {
                template<typename ValueType>
                inline static void reverse(ValueType &val) {
                    boost::endian::endian_reverse_inplace(val);
                }

                template<typename ValueType>
                inline static ValueType reverse(ValueType const &val) {
                    return boost::endian::endian_reverse(val);
                }
            };

            /*!
             * @brief This unit_reverser deals with the case of UnitBits > CHAR_BIT. To reverse the
             * order of units, first, it reverses the byte order in an input value, and then, it
             * invokes byte_in_unit_reverser to reverse the byte order in each unit of the input value.
             *
             * @ingroup reverser
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam UnitBits
             */
            template<typename InputEndianness, typename OutputEndianness, int UnitBits>
            struct unit_reverser<
                InputEndianness,
                OutputEndianness,
                UnitBits,
                typename std::enable_if<!is_same_unit<InputEndianness, OutputEndianness, UnitBits>::value &&
                                        (UnitBits > CHAR_BIT)>::type> {
                template<typename ValueType, int ValueBits = sizeof(ValueType) * CHAR_BIT>
                inline static void reverse(ValueType &val) {
                    boost::endian::endian_reverse_inplace(val);
                    ValueType out = ValueType();
                    byte_in_unit_reverser<ValueBits, UnitBits>::reverse(val, out);
                    val = out;
                }

                template<typename ValueType, int ValueBits = sizeof(ValueType) * CHAR_BIT>
                inline static ValueType reverse(ValueType const &val) {
                    ValueType tmp = boost::endian::endian_reverse(val);
                    ValueType out = ValueType();
                    byte_in_unit_reverser<ValueBits, UnitBits>::reverse(tmp, out);
                    return out;
                }
            };
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_REVERSER_HPP
