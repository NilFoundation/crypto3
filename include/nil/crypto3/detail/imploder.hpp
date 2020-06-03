//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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

            // By definition, for all imploders, InputBits < OutputBits,
            // so we're taking many smaller values and combining them into one value

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

            template<typename InputEndianness, typename OutputEndianness, int UnitBits, 
                     int InputBits, int OutputBits, int k>
            struct imploder_step {
                constexpr static int const shift = 
                    imploder_shift<OutputEndianness, UnitBits, InputBits, OutputBits, k>::value;

                template<typename InputValue, typename OutputValue>
                static void step(InputValue &in, OutputValue &out) {
                    InputValue tmp = in;
                    unit_reverser<InputEndianness, OutputEndianness, UnitBits>::reverse(tmp);
                    bit_reverser<InputEndianness, OutputEndianness, UnitBits>::reverse(tmp);
                    out |= unbounded_shl<shift>(low_bits<InputBits>(OutputValue(tmp)));
                }
            };

            template<typename InputEndianness, typename OutputEndianness, int InputBits, int OutputBits, int k = 0>
            struct imploder;

            template<template<int> class InputEndian, template<int> class OutputEndian, int UnitBits, 
                     int InputBits, int OutputBits, int k>
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
                static void implode(InIter &in, OutputValue &x) {
                    step_type::step(*in++, x);
                    next_type::implode(in, x);
                }
            };

            template<template<int> class InputEndian, template<int> class OutputEndian, int UnitBits, 
                     int InputBits, int OutputBits>
            struct imploder<InputEndian<UnitBits>, OutputEndian<UnitBits>, InputBits, OutputBits, OutputBits> {
                template<typename InIter, typename OutputValue>
                static void implode(InIter &, OutputValue &) {
                }
            };

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_IMPLODER_HPP