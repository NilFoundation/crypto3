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
#include <nil/crypto3/detail/reverse_bits.hpp>

#include <boost/static_assert.hpp>
#include <boost/endian/conversion.hpp>

#include <iterator>
#include <climits>
#include <cstring>

namespace nil {
    namespace crypto3 {
        namespace detail {

            // By definition, for all imploders, InputBits < OutputBits,
            // so we're taking many smaller values and combining them into one value

            template<typename InputEndianness, typename OutputEndianness, int InputBits, int OutputBits, int k>
            struct imploder_step;

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct imploder_step<stream_endian::big_unit_big_bit<UnitBits>, 
                                 stream_endian::big_unit_big_bit<UnitBits>, InputBits, OutputBits, k> {

                template<typename InputValue, typename OutputValue>
                static void step(InputValue &in, OutputValue &out) {
                    int const shift = OutputBits - (InputBits + k);
                    OutputValue in_to_out = low_bits<InputBits>(OutputValue(in));
                    out |= unbounded_shl<shift>(in_to_out);
                }
            };

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct imploder_step<stream_endian::little_unit_big_bit<UnitBits>, 
                                 stream_endian::big_unit_big_bit<UnitBits>, InputBits, OutputBits, k> {

                template<typename InputValue, typename OutputValue>
                static void step(InputValue &in, OutputValue &out) {
                    int const shift = OutputBits - (InputBits + k);
                    OutputValue in_to_out = low_bits<InputBits>(OutputValue(boost::endian::endian_reverse(in)));
                    out |= unbounded_shl<shift>(in_to_out);
                }
            };

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct imploder_step<stream_endian::big_unit_little_bit<UnitBits>, 
                                 stream_endian::big_unit_big_bit<UnitBits>, InputBits, OutputBits, k> {

                template<typename InputValue, typename OutputValue>
                static void step(InputValue &in, OutputValue &out) {
                    int const shift = OutputBits - (InputBits + k);
                    OutputValue in_to_out = low_bits<InputBits>(OutputValue(reverse_bits<UnitBits>(in)));
                    out |= unbounded_shl<shift>(in_to_out);
                }
            };

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct imploder_step<stream_endian::big_unit_big_bit<UnitBits>, 
                                 stream_endian::little_unit_big_bit<UnitBits>, InputBits, OutputBits, k> {
                template<typename InputValue, typename OutputValue>
                static void step(InputValue &in, OutputValue &out) {
                    int const shift = k;
                    OutputValue in_to_out = low_bits<InputBits>(OutputValue(boost::endian::endian_reverse(in)));
                    out |= unbounded_shl<shift>(in_to_out);
                }
            };

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct imploder_step<stream_endian::little_unit_big_bit<UnitBits>,
                                 stream_endian::little_unit_big_bit<UnitBits>, InputBits, OutputBits, k> {
                template<typename InputValue, typename OutputValue>
                static void step(InputValue &in, OutputValue &out) {
                    int const shift = k;
                    OutputValue in_to_out = low_bits<InputBits>(OutputValue(in));
                    out |= unbounded_shl<shift>(in_to_out);
                }
            };

            /*template<int UnitBits, int InputBits, int OutputBits, int k>
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
            };*/

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
                typedef imploder_step<InputEndianness, OutputEndianness, InputBits, OutputBits, k> step_type;
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