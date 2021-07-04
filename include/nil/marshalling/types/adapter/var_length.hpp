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

#ifndef MARSHALLING_VAR_LENGTH_HPP
#define MARSHALLING_VAR_LENGTH_HPP

#include <type_traits>
#include <algorithm>
#include <limits>

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/processing/size_to_type.hpp>
#include <nil/marshalling/processing/access.hpp>
#include <nil/marshalling/status_type.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<std::size_t TMinLen, std::size_t TMaxLen, typename TBase>
                class var_length : public TBase {
                    using base_impl_type = TBase;
                    using base_serialized_type = typename base_impl_type::serialized_type;

                public:
                    using value_type = typename base_impl_type::value_type;

                    static_assert(TMaxLen <= sizeof(base_serialized_type), "The provided max length limit is too big");

                    using serialized_type =
                        typename std::conditional<(TMaxLen < sizeof(base_serialized_type)),
                                                  typename processing::size_to_type<
                                                      TMaxLen, std::is_signed<base_serialized_type>::value>::type,
                                                  base_serialized_type>::type;

                    using endian_type = typename base_impl_type::endian_type;

                    var_length() = default;

                    explicit var_length(const value_type &val) : base_impl_type(val) {
                    }

                    explicit var_length(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    var_length(const var_length &) = default;

                    var_length(var_length &&) = default;

                    var_length &operator=(const var_length &) = default;

                    var_length &operator=(var_length &&) = default;

                    std::size_t length() const {
                        auto serValue
                            = adjust_to_unsigned_serialized_var_length(to_serialized(base_impl_type::value()));
                        std::size_t len = 0U;
                        while (0 < serValue) {
                            serValue >>= var_length_shift;
                            ++len;
                        }

                        MARSHALLING_ASSERT(len <= max_length());
                        return std::max(std::size_t(min_length_), len);
                    }

                    static constexpr std::size_t min_length() {
                        return min_length_;
                    }

                    static constexpr std::size_t max_length() {
                        return max_length_;
                    }

                    static constexpr serialized_type to_serialized(value_type val) {
                        return sign_ext_unsigned_serialized(
                            adjust_to_unsigned_serialized_var_length(base_impl_type::to_serialized(val)),
                            has_sign_tag());
                    }

                    static constexpr value_type from_serialized(serialized_type val) {
                        return base_impl_type::from_serialized(
                            static_cast<base_serialized_type>(sign_ext_unsigned_serialized(
                                adjust_to_unsigned_serialized_var_length(val), has_sign_tag())));
                    }

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t size) {
                        unsigned_serialized_type val = 0;
                        std::size_t byteCount = 0;
                        while (true) {
                            if (size == 0) {
                                return status_type::not_enough_data;
                            }

                            auto byte = processing::read_data<std::uint8_t>(iter, endian_type());
                            auto byteValue = byte & var_length_value_bits_mask;
                            add_byte_to_serialized_value(byteValue, byteCount, val,
                                                         typename base_impl_type::endian_type());

                            ++byteCount;

                            if ((byte & var_length_continue_bit) == 0) {
                                break;
                            }

                            if (max_length_ <= byteCount) {
                                return status_type::protocol_error;
                            }
                            --size;
                        }

                        if (byteCount < min_length()) {
                            return status_type::protocol_error;
                        }

                        auto adjustedValue = sign_ext_unsigned_serialized(val, byteCount, has_sign_tag());
                        base_impl_type::value() = base_impl_type::from_serialized(adjustedValue);
                        return status_type::success;
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) = delete;

                    template<typename TIter>
                    status_type write(TIter &iter, std::size_t size) const {
                        auto val = adjust_to_unsigned_serialized_var_length(
                            base_impl_type::to_serialized(base_impl_type::value()));
                        std::size_t byteCount = 0;
                        bool lastByte = false;
                        auto minLen = std::max(length(), min_length());
                        while ((!lastByte) && (byteCount < max_length())) {
                            if (size == 0) {
                                return status_type::buffer_overflow;
                            }
                            auto byte
                                = remove_byte_from_serialized_value(val, byteCount, minLen, lastByte, endian_type());
                            if (!lastByte) {
                                MARSHALLING_ASSERT((byte & var_length_continue_bit) == 0);
                                byte |= var_length_continue_bit;
                            }

                            processing::write_data(byte, iter, endian_type());
                            ++byteCount;
                            MARSHALLING_ASSERT(byteCount <= max_length());
                            --size;
                        }

                        return status_type::success;
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        auto val = adjust_to_unsigned_serialized_var_length(
                            base_impl_type::to_serialized(base_impl_type::value()));
                        std::size_t byteCount = 0;
                        bool lastByte = false;
                        auto minLen = std::max(length(), min_length());
                        while ((!lastByte) && (byteCount < max_length())) {
                            auto byte
                                = remove_byte_from_serialized_value(val, byteCount, minLen, lastByte, endian_type());
                            if (!lastByte) {
                                MARSHALLING_ASSERT((byte & var_length_continue_bit) == 0);
                                byte |= var_length_continue_bit;
                            }

                            processing::write_data(byte, iter, endian_type());
                            ++byteCount;
                            MARSHALLING_ASSERT(byteCount <= max_length());
                        }
                    }

                private:
                    struct unsigned_tag { };
                    struct signed_tag { };

                    using has_sign_tag = typename std::conditional<std::is_signed<serialized_type>::value, signed_tag,
                                                                   unsigned_tag>::type;

                    using unsigned_serialized_type = typename std::make_unsigned<serialized_type>::type;

                    static unsigned_serialized_type adjust_to_unsigned_serialized_var_length(serialized_type val) {
                        static_assert(max_length_ <= sizeof(unsigned_serialized_type),
                                      "max_length is expected to be shorter than size of serialized type.");

                        static const auto ZeroBitsCount = ((sizeof(unsigned_serialized_type) - max_length_)
                                                           * std::numeric_limits<std::uint8_t>::digits)
                                                          + max_length_;

                        static const auto TotalBits
                            = sizeof(unsigned_serialized_type) * std::numeric_limits<std::uint8_t>::digits;

                        static const unsigned_serialized_type Mask
                            = (static_cast<unsigned_serialized_type>(1U) << (TotalBits - ZeroBitsCount)) - 1;

                        return static_cast<unsigned_serialized_type>(val) & Mask;
                    }

                    static void add_byte_to_serialized_value_big_endian(std::uint8_t byte,
                                                                        unsigned_serialized_type &val) {
                        MARSHALLING_ASSERT((byte & var_length_continue_bit) == 0);
                        val <<= var_length_shift;
                        val |= byte;
                    }

                    static void add_byte_to_serialized_value_little_endian(std::uint8_t byte, std::size_t byteCount,
                                                                           unsigned_serialized_type &val) {
                        MARSHALLING_ASSERT((byte & var_length_continue_bit) == 0);
                        auto shift = byteCount * var_length_shift;
                        val = (static_cast<serialized_type>(byte) << shift) | val;
                    }

                    static void add_byte_to_serialized_value(std::uint8_t byte, std::size_t byteCount,
                                                             unsigned_serialized_type &val,
                                                             nil::marshalling::endian::big_endian) {
                        static_cast<void>(byteCount);
                        add_byte_to_serialized_value_big_endian(byte, val);
                    }

                    static void add_byte_to_serialized_value(std::uint8_t byte, std::size_t byteCount,
                                                             unsigned_serialized_type &val,
                                                             nil::marshalling::endian::little_endian) {
                        add_byte_to_serialized_value_little_endian(byte, byteCount, val);
                    }

                    static std::uint8_t remove_byte_from_serialized_value_big_endian(unsigned_serialized_type &val,
                                                                                     std::size_t byteCount,
                                                                                     std::size_t min_length,
                                                                                     bool &lastByte) {
                        static const unsigned_serialized_type Mask
                            = ~(static_cast<unsigned_serialized_type>(var_length_value_bits_mask));

                        if ((byteCount + 1) < min_length) {
                            auto remLen = min_length - (byteCount + 1);
                            auto minValue = (static_cast<unsigned_serialized_type>(1U) << (var_length_shift * remLen));
                            if (val < minValue) {
                                lastByte = false;
                                return std::uint8_t(0);
                            }
                        }

                        auto valueTmp = val;
                        std::size_t shift = 0;
                        std::size_t count = 0;
                        while ((valueTmp & Mask) != 0) {
                            valueTmp >>= var_length_shift;
                            shift += var_length_shift;
                            ++count;
                        }

                        auto clearMask = ~(static_cast<unsigned_serialized_type>(var_length_value_bits_mask) << shift);
                        val &= clearMask;
                        lastByte = (0U == count);
                        return static_cast<std::uint8_t>(valueTmp);
                    }

                    static std::uint8_t remove_byte_from_serialized_value_little_endian(unsigned_serialized_type &val,
                                                                                        std::size_t byteCount,
                                                                                        std::size_t min_length,
                                                                                        bool &lastByte) {
                        auto byte = static_cast<std::uint8_t>(val & var_length_value_bits_mask);
                        val >>= var_length_shift;
                        lastByte = ((val == 0) && (min_length <= byteCount + 1));
                        return byte;
                    }

                    static std::uint8_t remove_byte_from_serialized_value(unsigned_serialized_type &val,
                                                                          std::size_t byteCount, std::size_t min_length,
                                                                          bool &lastByte,
                                                                          nil::marshalling::endian::big_endian) {
                        return remove_byte_from_serialized_value_big_endian(val, byteCount, min_length, lastByte);
                    }

                    static std::uint8_t remove_byte_from_serialized_value(unsigned_serialized_type &val,
                                                                          std::size_t byteCount, std::size_t min_length,
                                                                          bool &lastByte,
                                                                          nil::marshalling::endian::little_endian) {
                        return remove_byte_from_serialized_value_little_endian(val, byteCount, min_length, lastByte);
                    }

                    static constexpr serialized_type sign_ext_unsigned_serialized(unsigned_serialized_type val,
                                                                                  unsigned_tag) {
                        return static_cast<serialized_type>(val);
                    }

                    static constexpr serialized_type sign_ext_unsigned_serialized(unsigned_serialized_type val,
                                                                                  std::size_t, unsigned_tag) {
                        return static_cast<serialized_type>(val);
                    }

                    static serialized_type sign_ext_unsigned_serialized(unsigned_serialized_type val, signed_tag) {
                        static const auto ZeroBitsCount = ((sizeof(unsigned_serialized_type) - max_length_)
                                                           * std::numeric_limits<std::uint8_t>::digits)
                                                          + max_length_;

                        static const auto TotalBits
                            = sizeof(unsigned_serialized_type) * std::numeric_limits<std::uint8_t>::digits;

                        static const auto Mask
                            = (static_cast<unsigned_serialized_type>(1U) << (TotalBits - ZeroBitsCount)) - 1;

                        static const unsigned_serialized_type SignExtMask = ~Mask;

                        static const auto SignMask = (Mask + 1) >> 1;

                        if ((val & SignMask) != 0) {
                            val |= SignExtMask;
                        }
                        return static_cast<serialized_type>(val);
                    }

                    static serialized_type sign_ext_unsigned_serialized(unsigned_serialized_type val,
                                                                        std::size_t byteCount, signed_tag) {
                        auto zeroBitsCount = ((sizeof(unsigned_serialized_type) - byteCount)
                                              * std::numeric_limits<std::uint8_t>::digits)
                                             + max_length_;

                        static const auto TotalBits
                            = sizeof(unsigned_serialized_type) * std::numeric_limits<std::uint8_t>::digits;

                        auto mask = (static_cast<unsigned_serialized_type>(1U) << (TotalBits - zeroBitsCount)) - 1;

                        unsigned_serialized_type signExtMask = ~mask;

                        auto signMask = (mask + 1) >> 1;

                        if ((val & signMask) != 0) {
                            val |= signExtMask;
                        }
                        return static_cast<serialized_type>(val);
                    }

                    static const std::size_t min_length_ = TMinLen;
                    static const std::size_t max_length_ = TMaxLen;
                    static const std::size_t max_bit_length = max_length_ * std::numeric_limits<std::uint8_t>::digits;
                    static const std::size_t var_length_shift = 7;
                    static const std::uint8_t var_length_value_bits_mask
                        = (static_cast<std::uint8_t>(1U) << var_length_shift) - 1;
                    static const std::uint8_t var_length_continue_bit
                        = static_cast<std::uint8_t>(~(var_length_value_bits_mask));

                    static_assert(min_length_ > 0, "min_length is expected to be greater than 0");
                    static_assert(min_length_ <= max_length_,
                                  "min_length is expected to be no greater than max_length");
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_VAR_LENGTH_HPP
