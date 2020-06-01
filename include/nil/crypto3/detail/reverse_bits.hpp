//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DETAIL_REVERSE_BITS_HPP
#define CRYPTO3_DETAIL_REVERSE_BITS_HPP

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>
#include <boost/endian/conversion.hpp>

#include <nil/crypto3/detail/unbounded_shift.hpp>

#include <climits>

namespace nil {
    namespace crypto3 {
        namespace detail {

            typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;

            // Reverses bits in a byte
            // http://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith64BitsDiv
            static inline byte_type reverse_b64(byte_type const &b) {
                return (b * 0x0202020202ULL & 0x010884422010ULL) % 1023;
            }

            static inline void reverse_b64_inplace(byte_type &b) {
                b = (b * 0x0202020202ULL & 0x010884422010ULL) % 1023;
            }

            // http://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith32Bits
            static inline byte_type reverse_b32(byte_type const &b) {
                return unbounded_shr<16>(((b * 0x0802LU & 0x22110LU) | (b * 0x8020LU & 0x88440LU)) * 0x10101LU);
            }

            static inline void reverse_b32_inplace(byte_type &b) {
                b = unbounded_shr<16>(((b * 0x0802LU & 0x22110LU) | (b * 0x8020LU & 0x88440LU)) * 0x10101LU);
            }


            static inline byte_type reverse_unit(byte_type const &unit) {
                return reverse_b64(unit);
            }

            // Now is not called, but possibly can
            template<size_t UnitBits, typename UnitType>
            static UnitType reverse_unit(UnitType const &unit) {
                BOOST_STATIC_ASSERT(UnitBits > CHAR_BIT); // choose with enable_if instead

                UnitType tmp = UnitType();
                UnitType const byte_mask = low_bits<CHAR_BIT>(~UnitType());
                for (size_t shift = 0; shift != UnitBits; shift += CHAR_BIT)
                    tmp |= unbounded_shl(UnitType(reverse_b64(unbounded_shr(unit, shift) & byte_mask)), shift);
                return boost::endian::endian_reverse(tmp);
            }


            template<size_t UnitBits, typename T>
            static T reverse_bits(T const &x) {
                constexpr static const size_t bit_size = sizeof(T) * CHAR_BIT;
                BOOST_STATIC_ASSERT(!(bit_size % UnitBits) && !(UnitBits % CHAR_BIT));

                typedef typename boost::uint_t<UnitBits>::exact UnitType;
                
                T tmp = T();
                UnitType const unit_mask = low_bits<UnitBits>(~UnitType());
                for (size_t shift = 0; shift != bit_size; shift += UnitBits)
                    tmp |= unbounded_shl(T(reverse_unit(unbounded_shr(x, shift) & unit_mask)), shift);

                return tmp;
            }

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_REVERSE_BITS_HPP
