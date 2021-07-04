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

#ifndef MARSHALLING_SER_OFFSET_HPP
#define MARSHALLING_SER_OFFSET_HPP

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/processing/access.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<long long int TOffset, typename TBase>
                class ser_offset : public TBase {
                    using base_impl_type = TBase;
                    static const auto offset = TOffset;

                public:
                    using value_type = typename base_impl_type::value_type;
                    using serialized_type = typename base_impl_type::serialized_type;
                    using endian_type = typename base_impl_type::endian_type;

                    ser_offset() = default;

                    explicit ser_offset(const value_type &val) : base_impl_type(val) {
                    }

                    explicit ser_offset(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    ser_offset(const ser_offset &) = default;

                    ser_offset(ser_offset &&) = default;

                    ser_offset &operator=(const ser_offset &) = default;

                    ser_offset &operator=(ser_offset &&) = default;

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t size) {
                        if (size < base_impl_type::length()) {
                            return status_type::not_enough_data;
                        }

                        read_no_status(iter);
                        return status_type::success;
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) {
                        auto serializedValue
                            = processing::read_data<serialized_type>(iter, endian_type());
                        base_impl_type::value() = from_serialized(serializedValue);
                    }

                    template<typename TIter>
                    status_type write(TIter &iter, std::size_t size) const {
                        if (size < base_impl_type::length()) {
                            return status_type::buffer_overflow;
                        }

                        write_no_status(iter);
                        return status_type::success;
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        processing::write_data(to_serialized(base_impl_type::value()), iter,
                                                                 endian_type());
                    }

                    static constexpr serialized_type to_serialized(value_type val) {
                        return adjust_to_serialized(base_impl_type::to_serialized(val));
                    }

                    static constexpr value_type from_serialized(serialized_type val) {
                        return base_impl_type::from_serialized(adjust_from_serialized(val));
                    }

                private:
                    static serialized_type adjust_to_serialized(serialized_type val) {
                        return static_cast<serialized_type>(offset + val);
                    }

                    static serialized_type adjust_from_serialized(serialized_type val) {
                        return static_cast<serialized_type>((-offset) + val);
                    }
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_SER_OFFSET_HPP
