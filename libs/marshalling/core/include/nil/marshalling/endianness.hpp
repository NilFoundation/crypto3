//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

/// @file nil/marshalling/endianness.hpp
/// This file contains all the classes necessary to properly
/// define message traits.

#ifndef MARSHALLING_ENDIANNESS_HPP
#define MARSHALLING_ENDIANNESS_HPP

#include <climits>

#include <boost/static_assert.hpp>

namespace nil {
    namespace marshalling {
        namespace endian {

            // General versions; There should be no need to use these directly
            template<int UnitBits>
            struct big_unit_big_bit { };
            template<int UnitBits>
            struct little_unit_little_bit { };
            template<int UnitBits>
            struct big_unit_little_bit { };
            template<int UnitBits>
            struct little_unit_big_bit { };
            template<int UnitBits>
            struct host_unit {
                BOOST_STATIC_ASSERT(UnitBits % CHAR_BIT == 0);
            };

            // Typical, useful instantiations

            typedef big_unit_big_bit<1> big_bit;
            typedef big_unit_big_bit<CHAR_BIT> big_byte_big_bit;
            typedef big_unit_big_bit<8> big_octet_big_bit;

            typedef little_unit_little_bit<1> little_bit;
            typedef little_unit_little_bit<CHAR_BIT> little_byte_little_bit;
            typedef little_unit_little_bit<8> little_octet_little_bit;

            typedef big_unit_little_bit<CHAR_BIT> big_byte_little_bit;
            typedef big_unit_little_bit<8> big_octet_little_bit;

            typedef little_unit_big_bit<CHAR_BIT> little_byte_big_bit;
            typedef little_unit_big_bit<8> little_octet_big_bit;

            typedef host_unit<CHAR_BIT> host_byte;

            /// @brief Empty class used in traits to indicate big endian.
            using big_endian = big_octet_big_bit;

            /// @brief Empty class used in traits to indicate little endian.
            using little_endian = little_octet_big_bit;

        }    // namespace endian
    }            // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_ENDIANNESS_HPP
