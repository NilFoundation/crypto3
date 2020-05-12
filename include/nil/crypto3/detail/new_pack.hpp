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

#include <nil/crypto3/detail/unbounded_shift.hpp>
#include <nil/crypto3/detail/type_traits.hpp>
#include <nil/crypto3/detail/octet.hpp>

#include <boost/static_assert.hpp>
#include <boost/endian/conversion.hpp>

#include <algorithm>
#include <iterator>
#include <type_traits>

namespace nil {
    namespace crypto3 {
        namespace detail {

            /* This module contains functions that deal with byte endianness 
               Handling the case of bit endianness is to be done */
            
            template<typename InEndian, typename OutEndian, size_t InValBits, size_t OutValBits>
            struct packer {

                template<typename InIter, typename OutIter, typename Dummy = size_t>
                static typename std::enable_if<(std::is_same<InEndian, OutEndian>::value || (InValBits == octet_bits)) 
                    && (InValBits == OutValBits) && sizeof(Dummy)>::type 
                        pack(InIter in_b, InIter in_e, OutIter out) {
                        std::copy(in_b, in_e, out);
                    }

                template<typename InIter, typename OutIter, typename Dummy = size_t>
                static typename std::enable_if<(InValBits == octet_bits) && (InValBits < OutValBits)
                    && sizeof(Dummy)>::type pack(InIter in_b, InIter in_e, OutIter out) {
                    
                    BOOST_STATIC_ASSERT(!(OutValBits % InValBits));

                    typedef typename std::iterator_traits<OutIter>::value_type OutValue;
                    constexpr static size_t const out_invalues = OutValBits / InValBits;

                    while (in_b != in_e) {

                        OutValue out_val = OutValue();

                        for (size_t shift = OutValBits, i = 0; i != out_invalues; ++i) {
                            shift -= InValBits;
                            out_val |= unbounded_shl(low_bits<octet_bits>(OutValue(*in_b++)), shift);
                        }

                        *out++ = std::is_same<OutEndian, stream_endian::little_octet_big_bit>::value ?
                                boost::endian::endian_reverse(out_val): out_val;
                    }
                }
            };

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_PACK_HPP