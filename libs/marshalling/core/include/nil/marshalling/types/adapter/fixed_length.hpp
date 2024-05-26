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

#ifndef MARSHALLING_FIXED_LENGTH_HPP
#define MARSHALLING_FIXED_LENGTH_HPP

#include <type_traits>
#include <limits>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/processing/size_to_type.hpp>
#include <nil/marshalling/status_type.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<std::size_t TLen, bool TSignExtend, typename TBase>
                class fixed_length : public TBase {
                    using base_impl_type = TBase;
                    using base_serialized_type = typename base_impl_type::serialized_type;

                public:
                    using value_type = typename base_impl_type::value_type;

                    static_assert(TLen <= sizeof(base_serialized_type), "The provided length limit is too big");

                    using serialized_type = typename std::conditional<
                        (TLen < sizeof(base_serialized_type)),
                        typename processing::
                            size_to_type<TLen, std::is_signed<base_serialized_type>::value>::type,
                        base_serialized_type>::type;

                    using endian_type = typename base_impl_type::endian_type;

                    fixed_length() = default;

                    explicit fixed_length(const value_type &val) : base_impl_type(val) {
                    }

                    fixed_length(const fixed_length &) = default;

                    fixed_length(fixed_length &&) = default;

                    fixed_length &operator=(const fixed_length &) = default;

                    fixed_length &operator=(fixed_length &&) = default;

                    static constexpr std::size_t length() {
                        return byte_length;
                    }

                    static constexpr std::size_t min_length() {
                        return length();
                    }

                    static constexpr std::size_t max_length() {
                        return length();
                    }

                    static constexpr serialized_type to_serialized(value_type val) {
                        return adjust_to_serialized(base_impl_type::to_serialized(val), conversion_tag());
                    }

                    static constexpr value_type from_serialized(serialized_type val) {
                        return base_impl_type::from_serialized(adjust_from_serialized(val, conversion_tag()));
                    }

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t size) {
                        if (size < length()) {
                            return status_type::not_enough_data;
                        }

                        read_no_status(iter);
                        return status_type::success;
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) {
                        serialized_type serializedValue = processing::read_data<serialized_type, byte_length>(
                            iter, endian_type());
                        base_impl_type::value() = from_serialized(serializedValue);
                    }

                    template<typename TIter>
                    status_type write(TIter &iter, std::size_t size) const {
                        if (size < length()) {
                            return status_type::buffer_overflow;
                        }

                        write_no_status(iter);
                        return status_type::success;
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        base_impl_type::template write_data<byte_length>(to_serialized(base_impl_type::value()), iter);
                    }

                private:
                    struct just_cast_tag { };
                    struct sign_extend_tag { };
                    struct unsigned_tag { };
                    struct signed_tag { };

                    using conversion_tag = typename std::
                        conditional<(TLen < sizeof(serialized_type)), sign_extend_tag, just_cast_tag>::type;

                    using has_sign_tag =
                        typename std::conditional<std::is_signed<serialized_type>::value && TSignExtend,
                                                  signed_tag,
                                                  unsigned_tag>::type;

                    using unsigned_serialized_type = typename std::make_unsigned<serialized_type>::type;

                    static constexpr serialized_type adjust_to_serialized(base_serialized_type val, just_cast_tag) {
                        return static_cast<serialized_type>(val);
                    }

                    static serialized_type adjust_to_serialized(base_serialized_type val, sign_extend_tag) {
                        unsigned_serialized_type valueTmp = 
                            static_cast<unsigned_serialized_type>(val) & UnsignedValueMask;

                        return sign_ext_unsigned_serialized(valueTmp, has_sign_tag());
                    }

                    static constexpr base_serialized_type adjust_from_serialized(serialized_type val, just_cast_tag) {
                        return static_cast<base_serialized_type>(val);
                    }

                    static base_serialized_type adjust_from_serialized(serialized_type val, sign_extend_tag) {
                        unsigned_serialized_type valueTmp = 
                            static_cast<unsigned_serialized_type>(val) & UnsignedValueMask;
                        return static_cast<base_serialized_type>(
                            sign_ext_unsigned_serialized(valueTmp, has_sign_tag()));
                    }

                    static constexpr serialized_type sign_ext_unsigned_serialized(unsigned_serialized_type val,
                                                                                  unsigned_tag) {
                        return static_cast<serialized_type>(val);
                    }

                    static serialized_type sign_ext_unsigned_serialized(unsigned_serialized_type val, signed_tag) {
                        static const unsigned_serialized_type SignExtMask
                            = ~((static_cast<unsigned_serialized_type>(1U) << bit_length) - 1);
                        static const unsigned_serialized_type SignMask = static_cast<unsigned_serialized_type>(1U)
                                                                         << (bit_length - 1);

                        if ((val & SignMask) != 0) {
                            val |= SignExtMask;
                        }
                        return static_cast<serialized_type>(val);
                    }

                    static const std::size_t byte_length = TLen;
                    static const std::size_t bits_in_byte = std::numeric_limits<std::uint8_t>::digits;
                    static const std::size_t bit_length = byte_length * bits_in_byte;

                    static const unsigned_serialized_type UnsignedValueMask
                        = static_cast<unsigned_serialized_type>((static_cast<std::uintmax_t>(1U) << bit_length) - 1);

                    static_assert(0 < byte_length, "length is expected to be greater than 0");
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_FIXED_LENGTH_HPP
