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

            template<typename InputEndianness, typename OutputEndianness, int UnitBits, 
                     int InputBits, int OutputBits, int k>
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
                typedef exploder_step<InputEndianness, OutputEndianness, UnitBits, InputBits, OutputBits, k> step_type;
                typedef exploder<InputEndianness, OutputEndianness, InputBits, OutputBits, k + OutputBits> next_type;

                template<typename InputValue, typename OutIter>
                inline static void explode(InputValue const &x, OutIter &out) {
                    step_type::step(x, out);
                    next_type::explode(x, out);
                }
            };

            template<template<int> class InputEndian, template<int> class OutputEndian, int UnitBits, 
                     int InputBits, int OutputBits>
            struct exploder<InputEndian<UnitBits>, OutputEndian<UnitBits>, InputBits, OutputBits, InputBits> {
                template<typename InputValue, typename OutIter>
                inline static void explode(InputValue const &, OutIter &) {
                }
            };

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_EXPLODER_HPP
