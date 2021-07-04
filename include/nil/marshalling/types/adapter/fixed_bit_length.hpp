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

#ifndef MARSHALLING_FIXED_BIT_LENGTH_HPP
#define MARSHALLING_FIXED_BIT_LENGTH_HPP

#include <type_traits>
#include <limits>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/processing/size_to_type.hpp>
#include <nil/marshalling/processing/bit_size_to_byte_size.hpp>
#include <nil/marshalling/status_type.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<std::size_t TLen, typename TBase>
                class fixed_bit_length : public TBase {
                    using base_impl_type = TBase;
                    using base_serialized_type = typename base_impl_type::serialized_type;

                    static const std::size_t bit_length = TLen;
                    static const std::size_t byte_length
                        = processing::bit_size_to_byte_size<bit_length>::value;

                    static_assert(0 < bit_length, "Bit length is expected to be greater than 0");
                    static_assert(byte_length <= sizeof(base_serialized_type), "The provided length limit is too big");

                public:
                    using value_type = typename base_impl_type::value_type;

                    using serialized_type = typename std::conditional<
                        (byte_length < sizeof(base_serialized_type)),
                        typename processing::
                            size_to_type<byte_length, std::is_signed<base_serialized_type>::value>::type,
                        base_serialized_type>::type;

                    using endian_type = typename base_impl_type::endian_type;

                    fixed_bit_length() = default;

                    explicit fixed_bit_length(const value_type &val) : base_impl_type(val) {
                    }

                    fixed_bit_length(const fixed_bit_length &) = default;

                    fixed_bit_length(fixed_bit_length &&) = default;

                    fixed_bit_length &operator=(const fixed_bit_length &) = default;

                    fixed_bit_length &operator=(fixed_bit_length &&) = default;

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
                        return adjust_to_serialized(base_impl_type::to_serialized(val), has_sign_tag());
                    }

                    static constexpr value_type from_serialized(serialized_type val) {
                        return base_impl_type::from_serialized(adjust_from_serialized(val, has_sign_tag()));
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
                        serialized_type serializedValue = 
                            processing::read_data<serialized_type, byte_length>(
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
                    struct unsigned_tag { };
                    struct signed_tag { };
                    struct no_sign_ext_tag { };
                    struct must_sign_ext_tag { };

                    using has_sign_tag = typename std::
                        conditional<std::is_signed<serialized_type>::value, signed_tag, unsigned_tag>::type;

                    using unsigned_serialized_type = typename std::make_unsigned<serialized_type>::type;

                    using sign_ext_tag =
                        typename std::conditional
                        < bit_length<static_cast<std::size_t>(std::numeric_limits<unsigned_serialized_type>::digits),
                                     must_sign_ext_tag,
                                     no_sign_ext_tag>::type;

                    static serialized_type adjust_to_serialized(base_serialized_type val, unsigned_tag) {
                        return static_cast<serialized_type>(val & UnsignedValueMask);
                    }

                    static serialized_type adjust_to_serialized(base_serialized_type val, signed_tag) {
                        unsigned_serialized_type valueTmp = 
                            static_cast<unsigned_serialized_type>(val) & UnsignedValueMask;

                        return sign_ext_unsigned_serialized(valueTmp);
                    }

                    static base_serialized_type adjust_from_serialized(serialized_type val, unsigned_tag) {
                        return static_cast<base_serialized_type>(val & UnsignedValueMask);
                    }

                    static base_serialized_type adjust_from_serialized(serialized_type val, signed_tag) {
                        unsigned_serialized_type valueTmp = 
                            static_cast<unsigned_serialized_type>(val) & UnsignedValueMask;
                        return static_cast<base_serialized_type>(sign_ext_unsigned_serialized(valueTmp));
                    }

                    static serialized_type sign_ext_unsigned_serialized(unsigned_serialized_type val) {
                        return sign_ext_unsigned_serialized_internal(val, sign_ext_tag());
                    }

                    static serialized_type sign_ext_unsigned_serialized_internal(unsigned_serialized_type val,
                                                                                 must_sign_ext_tag) {
                        static_assert(bit_length < std::numeric_limits<unsigned_serialized_type>::digits,
                                      "bit_length is expected to be less than number of bits in the value type");

                        static const unsigned_serialized_type SignExtMask
                            = ~((static_cast<unsigned_serialized_type>(1U) << bit_length) - 1);
                        static const unsigned_serialized_type SignMask = static_cast<unsigned_serialized_type>(1U)
                                                                         << (bit_length - 1);

                        if ((val & SignMask) != 0) {
                            val |= SignExtMask;
                        }
                        return static_cast<serialized_type>(val);
                    }

                    static serialized_type sign_ext_unsigned_serialized_internal(unsigned_serialized_type val,
                                                                                 no_sign_ext_tag) {
                        return static_cast<serialized_type>(val);
                    }

                private:
                    static const unsigned_serialized_type UnsignedValueMask
                        = (static_cast<unsigned_serialized_type>(1U) << bit_length) - 1;
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_FIXED_BIT_LENGTH_HPP
