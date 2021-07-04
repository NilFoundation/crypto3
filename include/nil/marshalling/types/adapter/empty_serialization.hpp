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

#ifndef MARSHALLING_EMPTY_SERIALIZATION_HPP
#define MARSHALLING_EMPTY_SERIALIZATION_HPP

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<typename TBase>
                class empty_serialization : public TBase {
                    using base_impl_type = TBase;

                public:
                    using value_type = typename base_impl_type::value_type;

                    empty_serialization() = default;

                    explicit empty_serialization(const value_type &val) : base_impl_type(val) {
                    }

                    explicit empty_serialization(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    empty_serialization(const empty_serialization &) = default;

                    empty_serialization(empty_serialization &&) = default;

                    empty_serialization &operator=(const empty_serialization &) = default;

                    empty_serialization &operator=(empty_serialization &&) = default;

                    static constexpr std::size_t length() {
                        return 0U;
                    }

                    static constexpr std::size_t min_length() {
                        return length();
                    }

                    static constexpr std::size_t max_length() {
                        return length();
                    }

                    template<typename TIter>
                    static status_type read(TIter &, std::size_t) {
                        return status_type::success;
                    }

                    template<typename TIter>
                    static void read_no_status(TIter &) {
                    }

                    template<typename TIter>
                    static status_type write(TIter &, std::size_t) {
                        return status_type::success;
                    }

                    template<typename TIter>
                    static void write_no_status(TIter &) {
                    }
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_EMPTY_SERIALIZATION_HPP
