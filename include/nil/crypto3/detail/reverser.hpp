//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DETAIL_REVERSER_HPP
#define CRYPTO3_DETAIL_REVERSER_HPP

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/utility/enable_if.hpp>
#include <boost/type_traits/is_same.hpp>

#include <nil/crypto3/detail/unbounded_shift.hpp>
#include <nil/crypto3/detail/stream_endian.hpp>

#include <climits>

namespace nil {
    namespace crypto3 {
        namespace detail {

            typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;

            // Reverses bits in a byte
            // http://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith64BitsDiv
            inline void reverse_b64(byte_type &b) {
                b = (b * 0x0202020202ULL & 0x010884422010ULL) % 1023;
            }

            // http://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith32Bits
            inline void reverse_b32(byte_type &b) {
                b = unbounded_shr<16>(((b * 0x0802LU & 0x22110LU) | (b * 0x8020LU & 0x88440LU)) * 0x10101LU);
            }

            /* bit_in_one_unit_reverser reverses sequence of bits in a unit bigger than byte */

            template<int UnitBits, int k = 0>
            struct bit_in_one_unit_reverser {

                BOOST_STATIC_ASSERT(!(UnitBits % CHAR_BIT));

                typedef bit_in_one_unit_reverser<UnitBits, k + CHAR_BIT> next_type;
                typedef typename boost::uint_t<UnitBits>::exact UnitType;

                inline static void reverse(UnitType &in, UnitType &out) {
                    int const shift = UnitBits - (CHAR_BIT + k);
                    byte_type byte = byte_type(low_bits<CHAR_BIT>(unbounded_shr(in, shift)));
                    reverse_b64(byte);
                    out |= unbounded_shl(low_bits<CHAR_BIT>(UnitType(byte)), shift);

                    next_type::reverse(in, out);
                }
            };

            template<int UnitBits>
            struct bit_in_one_unit_reverser<UnitBits, UnitBits> {
                inline static void reverse(typename boost::uint_t<UnitBits>::exact &,
                    typename boost::uint_t<UnitBits>::exact &) {
                }
            };

            // Case of unit bigger than byte
            template<typename UnitType, int UnitBits = sizeof(UnitType) * CHAR_BIT, 
                     typename boost::enable_if_c<(UnitBits > CHAR_BIT), int>::type = 0>
            inline void reverse_bits(UnitType &unit) {
                boost::endian::endian_reverse_inplace(unit);
                UnitType out = UnitType();
                bit_in_one_unit_reverser<UnitBits>::reverse(unit, out);
                unit = out;
            }

            // Case of byte unit
            template<typename UnitType, int UnitBits = sizeof(UnitType) * CHAR_BIT, 
                     typename boost::enable_if_c<(UnitBits == CHAR_BIT), int>::type = 0>
            inline void reverse_bits(UnitType &unit) {
                reverse_b64(unit); // choose between reverse_b32 depending on architecture
            }

            /* bit_in_unit_reverser reverses sequence of bits in each unit */

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

            /* Traits to determine certain bit order */

            template<typename Endianness, int UnitBits>
            struct is_big_bit {
                constexpr static const bool value = 
                    boost::is_same<Endianness, stream_endian::big_unit_big_bit<UnitBits>>::value || 
                    boost::is_same<Endianness, stream_endian::little_unit_big_bit<UnitBits>>::value; 
            };

            template<typename Endianness, int UnitBits>
            struct is_little_bit {
                constexpr static const bool value = 
                    boost::is_same<Endianness, stream_endian::big_unit_little_bit<UnitBits>>::value || 
                    boost::is_same<Endianness, stream_endian::little_unit_little_bit<UnitBits>>::value; 
            };

            template<typename Endianness1, typename Endianness2, int UnitBits>
            struct is_same_bit {
                constexpr static const bool value = 
                    (is_big_bit<Endianness1, UnitBits>::value && is_big_bit<Endianness2, UnitBits>::value) || 
                    (is_little_bit<Endianness1, UnitBits>::value && is_little_bit<Endianness2, UnitBits>::value); 
            };

            template<typename InputEndianness, typename OutputEndianness, int UnitBits, 
            bool IsSameBit = is_same_bit<InputEndianness, OutputEndianness, UnitBits>::value>
            struct bit_reverser;

            // If bit order is the same, do nothing
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

            /* byte_in_unit_reverser reverses sequence of bytes in each unit */

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

            /* Traits to determine certain order of units */

            template<typename Endianness, int UnitBits>
            struct is_big_unit {
                constexpr static const bool value = 
                    boost::is_same<Endianness, stream_endian::big_unit_big_bit<UnitBits>>::value || 
                    boost::is_same<Endianness, stream_endian::big_unit_little_bit<UnitBits>>::value; 
            };

            template<typename Endianness, int UnitBits>
            struct is_little_unit {
                constexpr static const bool value = 
                    boost::is_same<Endianness, stream_endian::little_unit_big_bit<UnitBits>>::value || 
                    boost::is_same<Endianness, stream_endian::little_unit_little_bit<UnitBits>>::value; 
            };

            template<typename Endianness1, typename Endianness2, int UnitBits>
            struct is_same_unit {
                constexpr static const bool value = 
                    (is_big_unit<Endianness1, UnitBits>::value && is_big_unit<Endianness2, UnitBits>::value) || 
                    (is_little_unit<Endianness1, UnitBits>::value && is_little_unit<Endianness2, UnitBits>::value); 
            };

            /* unit_reverser reverses sequence of units */

            template<typename InputEndianness, typename OutputEndianness, int UnitBits, typename Enable = void>
            struct unit_reverser;

            // If unit is the same, do nothing
            template<typename InputEndianness, typename OutputEndianness, int UnitBits>
            struct unit_reverser<InputEndianness, OutputEndianness, UnitBits, 
                typename boost::enable_if_c<is_same_unit<InputEndianness, OutputEndianness, 
                                            UnitBits>::value>::type> {
                template<typename ValueType>
                inline static void reverse(ValueType &) {
                }

                template<typename ValueType>
                inline static ValueType reverse(ValueType const &val) {
                    return val;
                }
            };

            // Case of byte unit
            template<typename InputEndianness, typename OutputEndianness, int UnitBits>
            struct unit_reverser<InputEndianness, OutputEndianness, UnitBits, 
                typename boost::enable_if_c<!is_same_unit<InputEndianness, OutputEndianness, UnitBits>::value 
                                            && UnitBits == CHAR_BIT>::type> {
                template<typename ValueType>
                inline static void reverse(ValueType &val) {
                    boost::endian::endian_reverse_inplace(val);
                }

                template<typename ValueType>
                inline static ValueType reverse(ValueType const &val) {
                    return boost::endian::endian_reverse(val);
                }
            };

            // Case of unit bigger than byte
            template<typename InputEndianness, typename OutputEndianness, int UnitBits>
            struct unit_reverser<InputEndianness, OutputEndianness, UnitBits, 
                typename boost::enable_if_c<!is_same_unit<InputEndianness, OutputEndianness, UnitBits>::value 
                                            && (UnitBits > CHAR_BIT)>::type> {
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
