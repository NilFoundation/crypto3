//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DETAIL_PACK_HPP
#define CRYPTO3_DETAIL_PACK_HPP

#include <nil/crypto3/detail/stream_endian.hpp>
#include <nil/crypto3/detail/unbounded_shift.hpp>
#include <nil/crypto3/detail/type_traits.hpp>

#include <boost/static_assert.hpp>

#include <algorithm>

namespace nil {
    namespace crypto3 {
        namespace detail {

            template<typename Endianness1, typename Endianness2, int UnitBits1, int UnitBits2,
                    bool Implode = (UnitBits1 < UnitBits2), bool Explode = (UnitBits1 > UnitBits2)>
            struct new_packer;

            template<template<int> class Endian, int UnitBits>
            struct new_packer<Endian<UnitBits>, Endian<UnitBits>, UnitBits, UnitBits, false, false> {
            
                template<typename InIter, typename OutIter>
                static void pack_n(InIter in, size_t n, OutIter out) {
                    std::copy(in, in + n, out);
                }                

                template<typename InIter, typename OutIter>
                static void pack(InIter in_begin, InIter in_end, OutIter out) {
                    std::copy(in_begin, in_end, out);
                }
            };

            template<template<int> class Endian, int UnitBits1, int UnitBits2>
            struct new_packer<Endian<UnitBits1>, Endian<UnitBits2>, UnitBits1, UnitBits2, true, false> {
                
                BOOST_STATIC_ASSERT(!(UnitBits2 % UnitBits1));

                template<typename InIter, typename OutIter>
                static void pack_n(InIter in, size_t n, OutIter out) {

                    typedef typename std::iterator_traits<OutIter>::value_type OutValue;
                    int const in_units = UnitBits2 / UnitBits1;
                    InIter in_end = in + n;
                    
                    while (in != in_end) {

                        OutValue out_val = OutValue();

                        for (int shift = UnitBits2, i = 0; i != in_units; ++i) {
                            shift -= UnitBits1;
                            out_val |= unbounded_shl(low_bits<UnitBits1>(OutValue(*in++)), shift);
                        }

                        *out++ = out_val;
                    }
                }

                template<typename InIter, typename OutIter>
                static void pack(InIter in_begin, InIter in_end, OutIter out) {

                    typedef typename std::iterator_traits<OutIter>::value_type OutValue;
                    int const in_units = UnitBits2 / UnitBits1;
                    
                    while (in_begin != in_end) {

                        OutValue out_val = OutValue();

                        for (int shift = UnitBits2, i = 0; i != in_units; ++i) {
                            shift -= UnitBits1;
                            out_val |= unbounded_shl(low_bits<UnitBits1>(OutValue(*in_begin++)), shift);
                        }

                        *out++ = out_val;
                    }
                }
            };
                

            template<template<int> class Endian, int UnitBits1, int UnitBits2>
            struct new_packer<Endian<UnitBits1>, Endian<UnitBits2>, UnitBits1, UnitBits2, false, true> {

                BOOST_STATIC_ASSERT(!(UnitBits1 % UnitBits2));

                template<typename InIter, typename OutIter>
                static void pack_n(InIter in, size_t n, OutIter out) {

                    typedef typename std::iterator_traits<OutIter>::value_type OutValue;
                    int const in_units = UnitBits1 / UnitBits2;
                    InIter in_end = in + n;
                    
                    for (; in != in_end; ++in) {
                        for (int shift = UnitBits1, i = 0; i != in_units; ++i) {
                            shift -= UnitBits2;
                            *out++ = OutValue(low_bits<UnitBits2>(unbounded_shr(*in, shift)));
                        }
                    }
                }   

                template<typename InIter, typename OutIter>
                static void pack(InIter in_begin, InIter in_end, OutIter out) {

                    typedef typename std::iterator_traits<OutIter>::value_type OutValue;
                    int const in_units = UnitBits1 / UnitBits2;
                    
                    for (; in_begin != in_end; ++in_begin) {
                        for (int shift = UnitBits1, i = 0; i != in_units; ++i) {
                            shift -= UnitBits2;
                            *out++ = OutValue(low_bits<UnitBits2>(unbounded_shr(*in_begin, shift)));
                        }
                    }
                }                
            };


        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_PACK_HPP