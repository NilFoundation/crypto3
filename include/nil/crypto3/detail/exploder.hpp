//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DETAIL_EXPLODER_HPP
#define CRYPTO3_DETAIL_EXPLODER_HPP

#include <nil/crypto3/detail/stream_endian.hpp>
#include <nil/crypto3/detail/unbounded_shift.hpp>
#include <nil/crypto3/detail/reverser.hpp>

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>
#include <boost/endian/conversion.hpp>

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

            template<typename InputEndianness, typename OutputEndianness, int InputBits, int OutputBits, int k>
            struct exploder_step;

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct exploder_step<stream_endian::big_unit_big_bit<UnitBits>, 
                                 stream_endian::big_unit_big_bit<UnitBits>, InputBits, OutputBits, k> {
                template<typename InputValue, typename OutputIterator>
                static void step(InputValue const &in, OutputIterator &out) {
                    int const shift = InputBits - (OutputBits + k);
                    typedef typename outvalue_helper<OutputIterator, OutputBits>::type OutValue;  
                    InputValue in_to_out = unbounded_shr<shift>(in);
                    *out++ = OutValue(low_bits<OutputBits>(in_to_out));
                } 
            };

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct exploder_step<stream_endian::little_unit_big_bit<UnitBits>, 
                                 stream_endian::big_unit_big_bit<UnitBits>, InputBits, OutputBits, k> {
                template<typename InputValue, typename OutputIterator>
                static void step(InputValue const &in, OutputIterator &out) {
                    int const shift = k;
                    typedef typename outvalue_helper<OutputIterator, OutputBits>::type OutValue;  
                    InputValue in_to_out = unbounded_shr<shift>(in);
                    *out++ = boost::endian::endian_reverse(OutValue(low_bits<OutputBits>(in_to_out)));
                }
            };

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct exploder_step<stream_endian::big_unit_big_bit<UnitBits>, 
                                 stream_endian::little_unit_big_bit<UnitBits>, InputBits, OutputBits, k> {
                template<typename InputValue, typename OutputIterator>
                static void step(InputValue const &in, OutputIterator &out) {
                    int const shift = InputBits - (OutputBits + k);
                    typedef typename outvalue_helper<OutputIterator, OutputBits>::type OutValue;  
                    InputValue in_to_out = unbounded_shr<shift>(in);
                    *out++ = boost::endian::endian_reverse(OutValue(low_bits<OutputBits>(in_to_out)));
                }
            };

            template<int UnitBits, int InputBits, int OutputBits, int k>
            struct exploder_step<stream_endian::little_unit_big_bit<UnitBits>, 
                                 stream_endian::little_unit_big_bit<UnitBits>, InputBits, OutputBits, k> {
                template<typename InputValue, typename OutputIterator>
                static void step(InputValue const &in, OutputIterator &out) {
                    int const shift = k;
                    typedef typename outvalue_helper<OutputIterator, OutputBits>::type OutValue;  
                    InputValue in_to_out = unbounded_shr<shift>(in);
                    *out++ = OutValue(low_bits<OutputBits>(in_to_out));
                }
            };

            /*template<int UnitBits, int InputBits, int OutputBits, int k>
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
            };*/

            template<typename InputEndianness, typename OutputEndianness, int InputBits, int OutputBits, int k = 0>
            struct exploder;

            template<template<int> class InputEndian, template<int> class OutputEndian, int UnitBits, 
                     int InputBits, int OutputBits, int k>
            struct exploder<InputEndian<UnitBits>, OutputEndian<UnitBits>, InputBits, OutputBits, k> {

                // To keep the implementation managable, input and output sizes must
                // be multiples or factors of the unit size.
                // If one of these is firing, you may want a bit-only stream_endian
                // rather than one that mentions bytes or octets.
                BOOST_STATIC_ASSERT(!(InputBits % UnitBits && UnitBits % InputBits));
                BOOST_STATIC_ASSERT(!(OutputBits % UnitBits && UnitBits % OutputBits));

                typedef InputEndian<UnitBits> InputEndianness;
                typedef OutputEndian<UnitBits> OutputEndianness;
                typedef exploder_step<InputEndianness, OutputEndianness, InputBits, OutputBits, k> step_type;
                typedef exploder<InputEndianness, OutputEndianness, InputBits, OutputBits, k + OutputBits> next_type;

                template<typename InputValue, typename OutIter>
                static void explode(InputValue const &x, OutIter &out) {
                    step_type::step(x, out);
                    next_type::explode(x, out);
                }
            };

            template<template<int> class InputEndian, template<int> class OutputEndian, int UnitBits, 
                     int InputBits, int OutputBits>
            struct exploder<InputEndian<UnitBits>, OutputEndian<UnitBits>, InputBits, OutputBits, InputBits> {
                template<typename InputValue, typename OutIter>
                static void explode(InputValue const &, OutIter &) {
                }
            };

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_EXPLODER_HPP
