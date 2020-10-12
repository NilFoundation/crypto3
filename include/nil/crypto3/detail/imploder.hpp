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

#ifndef CRYPTO3_DETAIL_IMPLODER_HPP
#define CRYPTO3_DETAIL_IMPLODER_HPP

#include <nil/crypto3/detail/stream_endian.hpp>
#include <nil/crypto3/detail/unbounded_shift.hpp>

#include <boost/static_assert.hpp>

#include <climits>
#include <cstring>

namespace nil {
    namespace crypto3 {
        namespace detail {

            // By definition, for all imploders, InputBits < OutputBits,
            // so we're taking many smaller values and combining them into one value

            template<typename Endianness, int InputBits, int OutputBits, int k>
            struct imploder_step;

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct imploder_step<stream_endian::big_unit_big_bit<UnitBits>, InputBits, OutputBits, k> {
                template<typename InputValue, typename OutputValue>
                static void step(InputValue z, OutputValue &x) {
                    int const shift = OutputBits - (InputBits + k);
                    OutputValue y = low_bits<InputBits>(OutputValue(z));
                    x |= unbounded_shl<shift>(y);
                }
            };

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct imploder_step<stream_endian::little_unit_big_bit<UnitBits>, InputBits, OutputBits, k> {
                template<typename InputValue, typename OutputValue>
                static void step(InputValue z, OutputValue &x) {
                    int const kb = (k % UnitBits);
                    int const ku = k - kb;
                    int const shift =
                        InputBits >= UnitBits ?
                            k :
                            OutputBits >= UnitBits ? ku + (UnitBits - (InputBits + kb)) : OutputBits - (InputBits + kb);
                    OutputValue y = low_bits<InputBits>(OutputValue(z));
                    x |= unbounded_shl<shift>(y);
                }
            };

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct imploder_step<stream_endian::big_unit_little_bit<UnitBits>, InputBits, OutputBits, k> {
                template<typename InputValue, typename OutputValue>
                static void step(InputValue z, OutputValue &x) {
                    int const kb = (k % UnitBits);
                    int const ku = k - kb;
                    int const shift = InputBits >= UnitBits ?
                                          OutputBits - (InputBits + k) :
                                          OutputBits >= UnitBits ? OutputBits - (UnitBits + ku) + kb : kb;
                    OutputValue y = low_bits<InputBits>(OutputValue(z));
                    x |= unbounded_shl<shift>(y);
                }
            };

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct imploder_step<stream_endian::little_unit_little_bit<UnitBits>, InputBits, OutputBits, k> {
                template<typename InputValue, typename OutputValue>
                static void step(InputValue z, OutputValue &x) {
                    int const shift = k;
                    OutputValue y = low_bits<InputBits>(OutputValue(z));
                    x |= unbounded_shl<shift>(y);
                }
            };

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct imploder_step<stream_endian::host_unit<UnitBits>, InputBits, OutputBits, k> {
                template<typename InputValue, typename OutputValue>
                static void step(InputValue z, OutputValue &x) {
                    BOOST_STATIC_ASSERT(sizeof(InputValue) * CHAR_BIT == InputBits);
                    BOOST_STATIC_ASSERT(sizeof(OutputValue) * CHAR_BIT == OutputBits);
                    std::memcpy((char *)&x + k / CHAR_BIT, &z, InputBits / CHAR_BIT);
                }
            };

            template<typename Endianness, int InputBits, int OutputBits, int k = 0>
            struct imploder;

            template<template<int> class Endian, int UnitBits, int InputBits, int OutputBits, int k>
            struct imploder<Endian<UnitBits>, InputBits, OutputBits, k> {

                // To keep the implementation managable, input and output sizes must
                // be multiples or factors of the unit size.
                // If one of these is firing, you may want a bit-only stream_endian
                // rather than one that mentions bytes or octets.
                BOOST_STATIC_ASSERT(!(InputBits % UnitBits && UnitBits % InputBits));
                BOOST_STATIC_ASSERT(!(OutputBits % UnitBits && UnitBits % OutputBits));

                typedef Endian<UnitBits> Endianness;
                typedef imploder_step<Endianness, InputBits, OutputBits, k> step_type;
                typedef imploder<Endianness, InputBits, OutputBits, k + InputBits> next_type;

                template<typename InIter, typename OutputValue>
                static void implode(InIter &in, OutputValue &x) {
                    step_type::step(*in++, x);
                    next_type::implode(in, x);
                }
            };

            template<template<int> class Endian, int UnitBits, int InputBits, int OutputBits>
            struct imploder<Endian<UnitBits>, InputBits, OutputBits, OutputBits> {
                template<typename InIter, typename OutputValue>
                static void implode(InIter &, OutputValue &) {
                }
            };

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_DETAIL_IMPLODER_HPP
