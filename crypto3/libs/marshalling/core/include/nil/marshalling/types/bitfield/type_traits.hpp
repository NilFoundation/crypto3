//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef MARSHALLING_BASIC_BITFIELD_TYPE_TRAITS_HPP
#define MARSHALLING_BASIC_BITFIELD_TYPE_TRAITS_HPP

#include <type_traits>
#include <limits>

#include <nil/detail/type_traits.hpp>

#include <nil/marshalling/processing/tuple.hpp>
#include <nil/marshalling/processing/size_to_type.hpp>
#include <nil/marshalling/processing/access.hpp>
#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/marshalling/types/integral.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace detail {

                template<typename TField, bool THasFixedBitLength>
                struct bitfield_member_length_retrieve_helper;

                template<typename TField>
                struct bitfield_member_length_retrieve_helper<TField, true> {
                    static const std::size_t value = TField::parsed_options_type::fixed_bit_length;
                };

                template<typename TField>
                struct bitfield_member_length_retrieve_helper<TField, false> {
                    static const std::size_t value = std::numeric_limits<typename TField::value_type>::digits;
                };

                template<typename TField>
                struct bitfield_member_length_retriever {
                    static const std::size_t value = bitfield_member_length_retrieve_helper<
                        TField,
                        TField::parsed_options_type::has_fixed_bit_length_limit>::value;
                };

                template<std::size_t TRem, typename TMembers>
                class bitfield_bit_length_calc_helper {
                    static const std::size_t Idx = std::tuple_size<TMembers>::value - TRem;
                    using field_type = typename std::tuple_element<Idx, TMembers>::type;

                public:
                    static const std::size_t value = bitfield_bit_length_calc_helper<TRem - 1, TMembers>::value
                                                     + bitfield_member_length_retriever<field_type>::value;
                };

                template<typename TMembers>
                class bitfield_bit_length_calc_helper<0, TMembers> {
                public:
                    static const std::size_t value = 0;
                };

                template<typename TMembers>
                constexpr std::size_t calc_bit_length() {
                    return bitfield_bit_length_calc_helper<std::tuple_size<TMembers>::value, TMembers>::value;
                }

                template<std::size_t TIdx, typename TMembers>
                struct bitfield_pos_retrieve_helper {
                    static_assert(TIdx < std::tuple_size<TMembers>::value, "Invalid tuple element");
                    using field_type = typename std::tuple_element<TIdx - 1, TMembers>::type;

                    static const std::size_t PrevFieldSize = bitfield_member_length_retriever<field_type>::value;

                public:
                    static const std::size_t value
                        = bitfield_pos_retrieve_helper<TIdx - 1, TMembers>::value + PrevFieldSize;
                };

                template<typename TMembers>
                struct bitfield_pos_retrieve_helper<0, TMembers> {
                public:
                    static const std::size_t value = 0;
                };

                template<std::size_t TIdx, typename TMembers>
                constexpr std::size_t get_member_shift_pos() {
                    return bitfield_pos_retrieve_helper<TIdx, TMembers>::value;
                }

            }    // namespace detail
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_BASIC_BITFIELD_TYPE_TRAITS_HPP
