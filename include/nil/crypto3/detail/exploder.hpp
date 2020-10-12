//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_DETAIL_EXPLODER_HPP
#define CRYPTO3_DETAIL_EXPLODER_HPP

#include <nil/crypto3/detail/stream_endian.hpp>
#include <nil/crypto3/detail/unbounded_shift.hpp>

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>

#include <iterator>

#include <climits>
#include <cstring>

namespace nil {
    namespace crypto3 {
        namespace detail {

            // By definition, for all exploders, InputBits > OutputBits,
            // so we're taking one value and splitting it into many smaller values

            template<typename OutIter, int OutBits, typename T = typename std::iterator_traits<OutIter>::value_type>
            struct outvalue_helper {
                typedef T type;
            };
            template<typename OutIter, int OutBits>
            struct outvalue_helper<OutIter, OutBits, void> {
                typedef typename boost::uint_t<OutBits>::least type;
            };

            template<typename Endianness, int InputBits, int OutputBits, int k>
            struct exploder_step;

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct exploder_step<stream_endian::big_unit_big_bit<UnitBits>, InputBits, OutputBits, k> {
                template<typename InputValue, typename OutIter>
                static void step(InputValue const &x, OutIter &out) {
                    int const shift = InputBits - (OutputBits + k);
                    typedef typename outvalue_helper<OutIter, OutputBits>::type OutValue;
                    InputValue y = unbounded_shr<shift>(x);
                    *out++ = OutValue(low_bits<OutputBits>(y));
                }
            };

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct exploder_step<stream_endian::little_unit_big_bit<UnitBits>, InputBits, OutputBits, k> {
                template<typename InputValue, typename OutIter>
                static void step(InputValue const &x, OutIter &out) {
                    int const kb = (k % UnitBits);
                    int const ku = k - kb;
                    int const shift =
                        OutputBits >= UnitBits ?
                            k :
                            InputBits >= UnitBits ? ku + (UnitBits - (OutputBits + kb)) : InputBits - (OutputBits + kb);
                    typedef typename outvalue_helper<OutIter, OutputBits>::type OutValue;
                    InputValue y = unbounded_shr<shift>(x);
                    *out++ = OutValue(low_bits<OutputBits>(y));
                }
            };

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct exploder_step<stream_endian::big_unit_little_bit<UnitBits>, InputBits, OutputBits, k> {
                template<typename InputValue, typename OutIter>
                static void step(InputValue const &x, OutIter &out) {
                    int const kb = (k % UnitBits);
                    int const ku = k - kb;
                    int const shift = OutputBits >= UnitBits ?
                                          InputBits - (OutputBits + k) :
                                          InputBits >= UnitBits ? InputBits - (UnitBits + ku) + kb : kb;
                    typedef typename outvalue_helper<OutIter, OutputBits>::type OutValue;
                    InputValue y = unbounded_shr<shift>(x);
                    *out++ = OutValue(low_bits<OutputBits>(y));
                }
            };

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct exploder_step<stream_endian::little_unit_little_bit<UnitBits>, InputBits, OutputBits, k> {
                template<typename InputValue, typename OutIter>
                static void step(InputValue const &x, OutIter &out) {
                    int const shift = k;
                    typedef typename outvalue_helper<OutIter, OutputBits>::type OutValue;
                    InputValue y = unbounded_shr<shift>(x);
                    *out++ = OutValue(low_bits<OutputBits>(y));
                }
            };

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct exploder_step<stream_endian::host_unit<UnitBits>, InputBits, OutputBits, k> {
                template<typename InputValue, typename OutIter>
                static void step(InputValue const &x, OutIter &out) {
                    typedef typename outvalue_helper<OutIter, OutputBits>::type OutValue;
                    BOOST_STATIC_ASSERT(sizeof(InputValue) * CHAR_BIT == InputBits);
                    BOOST_STATIC_ASSERT(sizeof(OutValue) * CHAR_BIT == OutputBits);
                    OutValue value;
                    std::memcpy(&value, (char *)&x + k / CHAR_BIT, OutputBits / CHAR_BIT);
                    *out++ = value;
                }
            };

            template<typename Endianness, int InputBits, int OutputBits, int k = 0>
            struct exploder;

            template<template<int> class Endian, int UnitBits, int InputBits, int OutputBits, int k>
            struct exploder<Endian<UnitBits>, InputBits, OutputBits, k> {

                // To keep the implementation managable, input and output sizes must
                // be multiples or factors of the unit size.
                // If one of these is firing, you may want a bit-only stream_endian
                // rather than one that mentions bytes or octets.
                BOOST_STATIC_ASSERT(!(InputBits % UnitBits && UnitBits % InputBits));
                BOOST_STATIC_ASSERT(!(OutputBits % UnitBits && UnitBits % OutputBits));

                typedef Endian<UnitBits> Endianness;
                typedef exploder_step<Endianness, InputBits, OutputBits, k> step_type;
                typedef exploder<Endianness, InputBits, OutputBits, k + OutputBits> next_type;

                template<typename InputValue, typename OutIter>
                static void explode(InputValue const &x, OutIter &out) {
                    step_type::step(x, out);
                    next_type::explode(x, out);
                }
            };

            template<template<int> class Endian, int UnitBits, int InputBits, int OutputBits>
            struct exploder<Endian<UnitBits>, InputBits, OutputBits, InputBits> {
                template<typename InputValue, typename OutIter>
                static void explode(InputValue const &, OutIter &) {
                }
            };

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_DETAIL_EXPLODER_HPP
