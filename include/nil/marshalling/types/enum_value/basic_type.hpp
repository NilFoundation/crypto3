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

#ifndef MARSHALLING_BASIC_ENUM_VALUE_HPP
#define MARSHALLING_BASIC_ENUM_VALUE_HPP

#include <type_traits>

#include <nil/marshalling/status_type.hpp>

#include <nil/marshalling/types/int_value/basic_type.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace basic {

                template<typename TFieldBase, typename T>
                class enum_value : public TFieldBase {
                    static_assert(std::is_enum<T>::value, "T must be enum");

                    using underlying_type = typename std::underlying_type<T>::type;

                    using base_impl_type = TFieldBase;

                    using int_value_field_type = int_value<base_impl_type, underlying_type>;

                    using int_value_type = typename int_value_field_type::value_type;

                public:
                    using value_type = T;

                    using serialized_type = typename int_value_field_type::value_type;

                    using scaling_ratio_type = typename int_value_field_type::scaling_ratio_type;

                    enum_value() = default;

                    explicit enum_value(value_type val) : value_(val) {
                    }

                    enum_value(const enum_value &) = default;

                    enum_value(enum_value &&) = default;

                    ~enum_value() noexcept = default;

                    enum_value &operator=(const enum_value &) = default;

                    enum_value &operator=(enum_value &&) = default;

                    const value_type &value() const {
                        return value_;
                    }

                    value_type &value() {
                        return value_;
                    }

                    static constexpr std::size_t length() {
                        return int_value_field_type::length();
                    }

                    static constexpr std::size_t min_length() {
                        return length();
                    }

                    static constexpr std::size_t max_length() {
                        return length();
                    }

                    static constexpr serialized_type to_serialized(value_type val) {
                        return int_value_field_type::to_serialized(static_cast<int_value_type>(val));
                    }

                    static constexpr value_type from_serialized(serialized_type val) {
                        return static_cast<value_type>(int_value_field_type::from_serialized(val));
                    }

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t size) {
                        int_value_field_type intField;
                        auto es = intField.read(iter, size);
                        if (es == status_type::success) {
                            value_ = static_cast<decltype(value_)>(intField.value());
                        }
                        return es;
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) {
                        int_value_field_type intField;
                        intField.read_no_status(iter);
                        value_ = static_cast<decltype(value_)>(intField.value());
                    }

                    template<typename TIter>
                    status_type write(TIter &iter, std::size_t size) const {
                        return int_value_field_type(static_cast<int_value_type>(value_)).write(iter, size);
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        int_value_field_type(static_cast<int_value_type>(value_)).write_no_status(iter);
                    }

                private:
                    value_type value_;
                };

            }    // namespace basic
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_BASIC_ENUM_VALUE_HPP
