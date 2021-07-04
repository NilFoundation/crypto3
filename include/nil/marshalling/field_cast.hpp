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

/// @file
/// Contains definition of field_cast() function

#ifndef MARSHALLING_FIELD_CAST_HPP
#define MARSHALLING_FIELD_CAST_HPP

#include <cstdint>
#include <iterator>
#include <type_traits>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/fields.hpp>

namespace nil {
    namespace marshalling {
        namespace detail {
            template<typename TFieldTo, typename TFieldFrom, bool TFixedLength>
            struct field_cast_non_equal_helper;

            template<typename TFieldTo, typename TFieldFrom>
            struct field_cast_non_equal_helper<TFieldTo, TFieldFrom, true> {
                static TFieldTo cast(const TFieldFrom &field) {
                    static const auto MaxBufSize = TFieldFrom::max_length();
                    std::uint8_t buf[MaxBufSize] = {0};
                    auto *writeIter = &buf[0];
                    status_type es = field.write(writeIter, MaxBufSize);
                    MARSHALLING_ASSERT(es == status_type::success);
                    if (es != status_type::success) {
                        return TFieldTo();
                    }

                    auto len = static_cast<std::size_t>(std::distance(&buf[0], writeIter));
                    MARSHALLING_ASSERT(len <= MaxBufSize);

                    TFieldTo result;
                    const auto *readIter = &buf[0];
                    es = result.read(readIter, len);
                    static_cast<void>(es);
                    MARSHALLING_ASSERT(es == status_type::success);
                    return result;
                }
            };

            template<typename TFieldTo, typename TFieldFrom>
            struct field_cast_non_equal_helper<TFieldTo, TFieldFrom, false> {
                static TFieldTo cast(const TFieldFrom &field) {
                    static_cast<void>(field);
                    MARSHALLING_ASSERT(!"Casting between different fields of variable sizes is not supported.");
                    return TFieldTo();
                }
            };

            template<typename TFieldTo, typename TFieldFrom, bool TSameValue>
            struct field_cast_helper;

            template<typename TFieldTo, typename TFieldFrom>
            struct field_cast_helper<TFieldTo, TFieldFrom, true> {
                static constexpr TFieldTo cast(const TFieldFrom &field) {
                    return TFieldTo(field.value());
                }
            };

            template<typename TFieldTo, typename TFieldFrom>
            struct field_cast_helper<TFieldTo, TFieldFrom, false> {
                static TFieldTo cast(const TFieldFrom &field) {
                    return field_cast_non_equal_helper<TFieldTo, TFieldFrom,
                                                       TFieldFrom::min_length() == TFieldTo::max_length()>::cast(field);
                }
            };
        }    // namespace detail

        /// @brief Cast between fields.
        /// @details Sometimes the protocol may treat some specific field differently
        ///     based on indication bit in some other field. This function can be
        ///     used to cast one field to another type.
        /// @tparam TFieldTo Type to cast to.
        /// @tparam TFieldFrom Type to cast from.
        /// @param[in] field Original field
        /// @return field_type of the new type with internal value equivalent to one of the
        ///     original field.
        /// @pre Internal value_type type of both fields is the same.
        template<typename TFieldTo, typename TFieldFrom>
        TFieldTo field_cast(const TFieldFrom &field) {
            static const bool SameValues
                = std::is_same<typename TFieldTo::value_type, typename TFieldFrom::value_type>::value;
            return detail::field_cast_helper<TFieldTo, TFieldFrom, SameValues>::cast(field);
        }
    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_FIELD_CAST_HPP
