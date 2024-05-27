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

#ifndef MARSHALLING_BASIC_NO_VALUE_HPP
#define MARSHALLING_BASIC_NO_VALUE_HPP

#include <type_traits>

#include <nil/marshalling/status_type.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace detail {

                template<typename TFieldBase>
                class basic_no_value : public TFieldBase {
                    using base_impl_type = TFieldBase;

                public:
                    using value_type = unsigned;
                    using serialized_type = value_type;

                    basic_no_value() = default;

                    basic_no_value(const basic_no_value &) = default;

                    basic_no_value(basic_no_value &&) = default;

                    ~basic_no_value() noexcept = default;

                    basic_no_value &operator=(const basic_no_value &) = default;

                    basic_no_value &operator=(basic_no_value &&) = default;

                    static value_type &value() {
                        static value_type value = value_type();
                        return value;
                    }

                    static constexpr std::size_t length() {
                        return 0U;
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
                    static status_type read(TIter &iter, std::size_t size) {
                        static_cast<void>(iter);
                        static_cast<void>(size);
                        return status_type::success;
                    }

                    template<typename TIter>
                    static void read_no_status(TIter &iter) {
                        static_cast<void>(iter);
                    }

                    template<typename TIter>
                    static status_type write(TIter &iter, std::size_t size) {
                        static_cast<void>(iter);
                        static_cast<void>(size);
                        return status_type::success;
                    }

                    template<typename TIter>
                    static void write_no_status(TIter &iter) {
                        static_cast<void>(iter);
                    }
                };

            }    // namespace detail
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_BASIC_NO_VALUE_HPP
