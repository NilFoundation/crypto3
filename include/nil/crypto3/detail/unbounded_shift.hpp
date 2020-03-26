//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DETAIL_UNBOUNDED_SHIFT_HPP
#define CRYPTO3_DETAIL_UNBOUNDED_SHIFT_HPP

#include <boost/assert.hpp>

#include <nil/crypto3/detail/stream_endian.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {

            template<int Shift, typename T>
            struct unbounded_shifter {
                static T shl(T x) {
                    return unbounded_shifter<Shift - 1, T>::shl(T(x << 1));
                }

                static T shr(T x) {
                    return unbounded_shifter<Shift - 1, T>::shr(T(x >> 1));
                }
            };

            template<typename T>
            struct unbounded_shifter<0, T> {
                static T shl(T x) {
                    return x;
                }

                static T shr(T x) {
                    return x;
                }
            };

            template<int Shift, typename T>
            T unbounded_shl(T x) {
                return unbounded_shifter<Shift, T>::shl(x);
            }

            template<int Shift, typename T>
            T unbounded_shr(T x) {
                return unbounded_shifter<Shift, T>::shr(x);
            }

            template<typename T> 
            T unbounded_shl(T x, std::size_t n) {
                return x << n;
            }  

            template<typename T> 
            T unbounded_shr(T x, std::size_t n) {
                return x >> n;
            }            
            // FIXME: it wouldn't work when Shift == sizeof(T) * CHAR_BIT             
            template<int Shift, typename T>
            T low_bits(T x) {
                T highmask = unbounded_shl<Shift, T>(~T());
                return T(x & ~highmask);
            }

            template<size_t Shift, typename T, size_t TypeBits>
            T low_bits(T x) {
                constexpr size_t real_shift = TypeBits - Shift;
                T lowmask = ((bool) Shift) * unbounded_shr<real_shift, T>(~T());
                return x & lowmask;
            }

            template<typename T, size_t type_bits>
            T low_bits(T x, size_t shift) {
                T lowmask = ((bool) shift) * unbounded_shr<T>(~T(), type_bits - shift);
                return x & lowmask;
            }

            template<typename T, size_t type_bits>
            T high_bits(T x, size_t shift) {
                T highmask = ((bool) shift) * unbounded_shl<T>(~T(), type_bits - shift);
                return x & highmask;
            }

            /*
                template<typename Endianness>
                struct endian_shift;

                template<int UnitBits>
                struct endian_shift<stream_endian::big_unit_big_bit<UnitBits>> {
                    static word_type& to_msb(word_type &w, length_type shift) {
                        //shift to most significant bits according to endianness
                        w <<= shift;
                        return w;
                    }
                };

                template<int UnitBits>
                struct endian_shift<stream_endian::little_unit_big_bit<UnitBits>> {
                    static word_type& to_msb(word_type &w, length_type shift) {
                        //shift to most significant bits according to endianness
                        length_type shift_rem = shift % UnitBits;
                        length_type shift_unit_bits = shift - shift_rem;
                        
                        length_type sz[2] = {UnitBits - shift_rem, shift_rem};
                        length_type masks[2] = {low_bits<word_type, word_bits>(~word_type(), sz[0]) << shift_unit_bits, 
                        low_bits<word_type, word_bits>(~word_type(), sz[1]) << (shift_unit_bits + UnitBits + sz[0])};
                        length_type bits_left = word_bits - shift;
                        word_type w_combined = 0;
                        int ind = 0;

                        while (bits_left) {
                            w_combined |= (!ind ? ((w & masks[0]) << shift_rem) : ((w & masks[1]) >> (UnitBits + sz[0])));
                            bits_left -= sz[ind];
                            masks[ind] <<= UnitBits;
                            ind = 1 - ind;
                        }

                        w = w_combined >> shift_unit_bits;
                        return w;
                    }
                };

                template<int UnitBits>
                struct endian_shift<stream_endian::big_unit_little_bit<UnitBits>> {
                    static word_type& to_msb(word_type &w, length_type shift) {
                        //shift to most significant bits according to endianness
                        length_type shift_rem = shift % UnitBits;
                        length_type shift_unit_bits = shift - shift_rem;

                        length_type sz[2] = {UnitBits - shift_rem, shift_rem};
                        word_type masks[2] = {high_bits<word_type, word_bits>(~word_type(), sz[0]) >> shift_unit_bits, 
                        high_bits<word_type, word_bits>(~word_type(), sz[1]) >> (shift_unit_bits + UnitBits + sz[0])};

                        length_type bits_left = word_bits - shift;
                        word_type w_combined = 0;
                        int ind = 0;

                        while (bits_left) {
                            w_combined |= (!ind ? ((w & masks[0]) >> shift_rem) : ((w & masks[1]) << (UnitBits + sz[0])));
                            bits_left -= sz[ind];
                            masks[ind] >>= UnitBits;
                            ind = 1 - ind;
                        }

                        w = w_combined << shift_unit_bits;
                        return w;
                    }
                };

                template<int UnitBits> 
                struct endian_shift<stream_endian::little_unit_little_bit<UnitBits>> {
                    static word_type& to_msb(word_type &w, length_type shift) {
                        //shift to most significant bits according to endianness
                        w >>= shift;
                        return w;
                    }
                };
                */
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_DETAIL_UNBOUNDED_SHIFT_HPP
