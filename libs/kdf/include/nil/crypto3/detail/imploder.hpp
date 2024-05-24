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

#ifndef CRYPTO3_DETAIL_IMPLODER_HPP
#define CRYPTO3_DETAIL_IMPLODER_HPP

#include <nil/crypto3/detail/stream_endian.hpp>
#include <nil/crypto3/detail/unbounded_shift.hpp>
#include <nil/crypto3/detail/reverser.hpp>

#include <boost/static_assert.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {

            // By definition, for all imploders, InputValueBits < OutputValueBits,
            // so we're taking many smaller values and combining them into one value

            /*!
             * @defgroup imploder Imploder functions
             */

            /*!
             * @brief imploder_shift trait is used to determine whether the input elements are packed into
             * an output element in reverse order. Since the input and output types are integral now, this
             * trait contains the shift indicating the position of input element in the output element when
             * k input bits have already been processed.
             *
             * @ingroup imploder
             *
             * @tparam OutputEndianness
             * @tparam UnitBits
             * @tparam InputBits
             * @tparam OutputBits
             * @tparam k
             * @tparam IsLittleUnit
             */
            template<typename OutputEndianness, int UnitBits, int InputBits, int OutputBits, int k,
                     bool IsLittleUnit = is_little_unit<OutputEndianness, UnitBits>::value>
            struct imploder_shift;

            template<typename OutputEndianness, int UnitBits, int InputBits, int OutputBits, int k>
            struct imploder_shift<OutputEndianness, UnitBits, InputBits, OutputBits, k, false> {
                constexpr static int const value = OutputBits - (InputBits + k);
            };

            template<typename OutputEndianness, int UnitBits, int InputBits, int OutputBits, int k>
            struct imploder_shift<OutputEndianness, UnitBits, InputBits, OutputBits, k, true> {
                constexpr static int const value = k;
            };

            /*!
             * @brief imploder_step packs an input value represented in InputEndianness endianness
             * into an output value represented in OutputEndianness endianness when k input bits
             * have already been processed. It uses unit_reverser and bit_reverser to deal with the
             * order of units and bits in the input value, respectively. Shift constant is determined
             * by the imploder_shift trait.
             *
             * @ingroup imploder
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam UnitBits
             * @tparam InputBits
             * @tparam OutputBits
             * @tparam k
             */
            template<typename InputEndianness, typename OutputEndianness, int UnitBits, int InputBits, int OutputBits,
                     int k>
            struct imploder_step {
                constexpr static int const shift =
                    imploder_shift<OutputEndianness, UnitBits, InputBits, OutputBits, k>::value;

                template<typename InputValue, typename OutputValue>
                inline static void step(InputValue &in, OutputValue &out) {
                    InputValue tmp = in;
                    unit_reverser<InputEndianness, OutputEndianness, UnitBits>::reverse(tmp);
                    bit_reverser<InputEndianness, OutputEndianness, UnitBits>::reverse(tmp);
                    out |= unbounded_shl<shift>(low_bits<InputBits>(OutputValue(tmp)));
                }
            };

            /*!
             * @brief imploder processes a sequence of input values represented in InputEndianness endianness
             * into an output value represented in OutputEndianness endianness. The function implode is
             * invoked recursively, and the parameter k is used to track the number of already processed
             * input values packed into the output value. The recursion ends when all elements the output
             * value can hold have already been processed, i.e. when k == OutputBits.
             *
             * @ingroup imploder
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputBits
             * @tparam OutputBits
             * @tparam k
             */
            template<typename InputEndianness, typename OutputEndianness, int InputBits, int OutputBits, int k = 0>
            struct imploder;

            template<template<int> class InputEndian, template<int> class OutputEndian, int UnitBits, int InputBits,
                     int OutputBits, int k>
            struct imploder<InputEndian<UnitBits>, OutputEndian<UnitBits>, InputBits, OutputBits, k> {

                // To keep the implementation managable, input and output sizes must
                // be multiples or factors of the unit size.
                // If one of these is firing, you may want a bit-only stream_endian
                // rather than one that mentions bytes or octets.
                BOOST_STATIC_ASSERT(!(InputBits % UnitBits && UnitBits % InputBits));
                BOOST_STATIC_ASSERT(!(OutputBits % UnitBits && UnitBits % OutputBits));

                typedef InputEndian<UnitBits> InputEndianness;
                typedef OutputEndian<UnitBits> OutputEndianness;
                typedef imploder_step<InputEndianness, OutputEndianness, UnitBits, InputBits, OutputBits, k> step_type;
                typedef imploder<InputEndianness, OutputEndianness, InputBits, OutputBits, k + InputBits> next_type;

                template<typename InIter, typename OutputValue>
                inline static void implode(InIter &in, OutputValue &x) {
                    step_type::step(*in++, x);
                    next_type::implode(in, x);
                }
            };

            template<template<int> class InputEndian, template<int> class OutputEndian, int UnitBits, int InputBits,
                     int OutputBits>
            struct imploder<InputEndian<UnitBits>, OutputEndian<UnitBits>, InputBits, OutputBits, OutputBits> {
                template<typename InIter, typename OutputValue>
                inline static void implode(InIter &, OutputValue &) {
                }
            };

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_IMPLODER_HPP