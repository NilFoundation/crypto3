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

#ifndef MARSHALLING_BASIC_INTEGRAL_HPP
#define MARSHALLING_BASIC_INTEGRAL_HPP

#include <type_traits>

#include <nil/marshalling/status_type.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace detail {

                template<typename TFieldBase, typename T>
                class basic_integral : public TFieldBase {
                    static_assert(std::is_integral<T>::value, "T must be integral value");

                    using base_impl_type = TFieldBase;

                public:
                    using value_type = T;

                    using serialized_type = value_type;
                    using scaling_ratio_type = std::ratio<1, 1>;

                    basic_integral() = default;

                    explicit basic_integral(value_type val) : value_(val) {
                    }

                    basic_integral(const basic_integral &) = default;

                    basic_integral(basic_integral &&) = default;

                    ~basic_integral() noexcept = default;

                    basic_integral &operator=(const basic_integral &) = default;

                    basic_integral &operator=(basic_integral &&) = default;

                    const value_type &value() const {
                        return value_;
                    }

                    value_type &value() {
                        return value_;
                    }

                    static constexpr std::size_t length() {
                        return sizeof(serialized_type);
                    }

                    static constexpr std::size_t min_length() {
                        return length();
                    }

                    static constexpr std::size_t max_length() {
                        return length();
                    }

                    static constexpr serialized_type to_serialized(value_type val) {
                        return static_cast<serialized_type>(val);
                    }

                    static constexpr value_type from_serialized(serialized_type val) {
                        return static_cast<value_type>(val);
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
                        serialized_type serializedValue = base_impl_type::template read_data<serialized_type>(iter);
                        value_ = from_serialized(serializedValue);
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
                        base_impl_type::write_data(to_serialized(value_), iter);
                    }

                private:
                    value_type value_ = static_cast<value_type>(0);
                };

            }    // namespace detail
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_BASIC_INTEGRAL_HPP
