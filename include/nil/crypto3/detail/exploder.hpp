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

#ifndef CRYPTO3_DETAIL_EXPLODER_HPP
#define CRYPTO3_DETAIL_EXPLODER_HPP

#include <nil/crypto3/detail/stream_endian.hpp>
#include <nil/crypto3/detail/unbounded_shift.hpp>
#include <nil/crypto3/detail/reverser.hpp>

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>

#include <iterator>

namespace nil {
    namespace crypto3 {
        namespace detail {

            // By definition, for all exploders, InputValueBits > OutputValueBits,
            // so we're taking one value and splitting it into many smaller values

            /*!
             * @defgroup exploder Exploder functions
             */

            /*!
             * @brief outvalue_helper trait is used to determine the output value type.
             * If OutBits is not an exact power of two for which the type uint_t is defined, the type
             * with the least power of two bits greater than OutBits is taken. Due to current exploder
             * struct definition, this case is possible, when OutputBits is a factor of UnitBits less
             * than UnitBits, and UnitBits is no more than CHAR_BIT.
             *
             * @ingroup exploder
             *
             * @tparam OutIter
             * @tparam OutBits
             * @tparam T
             */
            template<typename OutIter, int OutBits, typename T = typename std::iterator_traits<OutIter>::value_type>
            struct outvalue_helper {
                typedef T type;
            };
            template<typename OutIter, int OutBits>
            struct outvalue_helper<OutIter, OutBits, void> {
                typedef typename boost::uint_t<OutBits>::least type;
            };

            /*!
             * @brief exploder_shift trait is used to determine whether the output elements are splitted
             * from an input element in reverse order. Since the input and output types are integral now,
             * this trait contains the shift indicating the position of output element derived from the
             * input element when k output bits have already been processed.
             *
             * @ingroup exploder
             *
             * @tparam InputEndianness
             * @tparam UnitBits
             * @tparam InputBits
             * @tparam OutputBits
             * @tparam k
             * @tparam IsLittleUnit
             */
            template<typename InputEndianness, int UnitBits, int InputBits, int OutputBits, int k,
                     bool IsLittleUnit = is_little_unit<InputEndianness, UnitBits>::value>
            struct exploder_shift;

            template<typename InputEndianness, int UnitBits, int InputBits, int OutputBits, int k>
            struct exploder_shift<InputEndianness, UnitBits, InputBits, OutputBits, k, false> {
                constexpr static int const value = InputBits - (OutputBits + k);
            };

            template<typename InputEndianness, int UnitBits, int InputBits, int OutputBits, int k>
            struct exploder_shift<InputEndianness, UnitBits, InputBits, OutputBits, k, true> {
                constexpr static int const value = k;
            };

            /*!
             * @brief exploder_step obtains an output value represented in OutputEndianness endianness
             * from an input value represented in InputEndianness endianness when k output bits
             * have already been processed. It uses unit_reverser and bit_reverser to deal with the
             * order of units and bits in the output value, respectively. Shift constant is determined
             * by the exploder_shift trait.
             *
             * @ingroup exploder
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
            struct exploder_step {
                constexpr static int const shift =
                    exploder_shift<InputEndianness, UnitBits, InputBits, OutputBits, k>::value;

                template<typename InputValue, typename OutputIterator>
                inline static void step(InputValue const &in, OutputIterator &out) {
                    typedef typename outvalue_helper<OutputIterator, OutputBits>::type OutValue;
                    OutValue tmp = OutValue(low_bits<OutputBits>(unbounded_shr<shift>(in)));
                    unit_reverser<InputEndianness, OutputEndianness, UnitBits>::reverse(tmp);
                    bit_reverser<InputEndianness, OutputEndianness, UnitBits>::reverse(tmp);
                    *out++ = tmp;
                }
            };

            /*!
             * @brief exploder forms a sequence of output values represented in OutputEndianness endianness
             * from an input value represented in InputEndianness endianness. The function explode is
             * invoked recursively, and the parameter k is used to track the number of already processed
             * output values derived from the input value. The recursion ends when all elements the input
             * value can hold have already been processed, i.e. when k == InputBits.
             *
             * @ingroup exploder
             *
             * @tparam InputEndianness
             * @tparam OutputEndianness
             * @tparam InputBits
             * @tparam OutputBits
             * @tparam k
             */
            template<typename InputEndianness, typename OutputEndianness, int InputBits, int OutputBits, int k = 0>
            struct exploder;

            template<template<int> class InputEndian, template<int> class OutputEndian, int UnitBits, int InputBits,
                     int OutputBits, int k>
            struct exploder<InputEndian<UnitBits>, OutputEndian<UnitBits>, InputBits, OutputBits, k> {

                // To keep the implementation managable, input and output sizes must
                // be multiples or factors of the unit size.
                // If one of these is firing, you may want a bit-only stream_endian
                // rather than one that mentions bytes or octets.
                BOOST_STATIC_ASSERT(!(InputBits % UnitBits && UnitBits % InputBits));
                BOOST_STATIC_ASSERT(!(OutputBits % UnitBits && UnitBits % OutputBits));

                typedef InputEndian<UnitBits> InputEndianness;
                typedef OutputEndian<UnitBits> OutputEndianness;
                typedef exploder_step<InputEndianness, OutputEndianness, UnitBits, InputBits, OutputBits, k> step_type;
                typedef exploder<InputEndianness, OutputEndianness, InputBits, OutputBits, k + OutputBits> next_type;

                template<typename InputValue, typename OutIter>
                inline static void explode(InputValue const &x, OutIter &out) {
                    step_type::step(x, out);
                    next_type::explode(x, out);
                }
            };

            template<template<int> class InputEndian, template<int> class OutputEndian, int UnitBits, int InputBits,
                     int OutputBits>
            struct exploder<InputEndian<UnitBits>, OutputEndian<UnitBits>, InputBits, OutputBits, InputBits> {
                template<typename InputValue, typename OutIter>
                inline static void explode(InputValue const &, OutIter &) {
                }
            };

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_EXPLODER_HPP
