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

#ifndef MARSHALLING_SEQUENCE_SIZE_FIELD_PREFIX_HPP
#define MARSHALLING_SEQUENCE_SIZE_FIELD_PREFIX_HPP

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<typename TSizeField, typename TBase>
                class sequence_size_field_prefix : public TBase {
                    using base_impl_type = TBase;
                    using size_field_type = TSizeField;

                    static_assert(!size_field_type::is_version_dependent(),
                                  "Prefix fields must not be version dependent");

                public:
                    using value_type = typename base_impl_type::value_type;
                    using element_type = typename base_impl_type::element_type;

                    sequence_size_field_prefix() = default;

                    explicit sequence_size_field_prefix(const value_type &val) : base_impl_type(val) {
                    }

                    explicit sequence_size_field_prefix(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    sequence_size_field_prefix(const sequence_size_field_prefix &) = default;

                    sequence_size_field_prefix(sequence_size_field_prefix &&) = default;

                    sequence_size_field_prefix &operator=(const sequence_size_field_prefix &) = default;

                    sequence_size_field_prefix &operator=(sequence_size_field_prefix &&) = default;

                    std::size_t length() const {
                        using SizeValueType = typename size_field_type::value_type;
                        size_field_type sizeField;
                        sizeField.value() = static_cast<SizeValueType>(base_impl_type::value().size());
                        return sizeField.length() + base_impl_type::length();
                    }

                    static constexpr std::size_t min_length() {
                        return size_field_type::min_length() + base_impl_type::min_length();
                    }

                    static constexpr std::size_t max_length() {
                        return size_field_type::max_length() + base_impl_type::max_length();
                    }

                    bool valid() const {
                        using SizeValueType = typename size_field_type::value_type;
                        size_field_type sizeField;
                        sizeField.value() = static_cast<SizeValueType>(base_impl_type::value().size());
                        return sizeField.valid() && base_impl_type::valid();
                    }

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t len) {
                        size_field_type sizeField;
                        status_type es = sizeField.read(iter, len);
                        if (es != status_type::success) {
                            return es;
                        }

                        auto count = static_cast<std::size_t>(sizeField.value());
                        len -= sizeField.length();

                        return base_impl_type::read_n(count, iter, len);
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) {
                        size_field_type sizeField;
                        sizeField.read_no_status(iter);
                        auto count = static_cast<std::size_t>(sizeField.value());
                        base_impl_type::read_no_status_n(count, iter);
                    }

                    template<typename TIter>
                    status_type write(TIter &iter, std::size_t len) const {
                        using SizeValueType = typename size_field_type::value_type;
                        size_field_type sizeField;
                        sizeField.value() = static_cast<SizeValueType>(base_impl_type::value().size());
                        status_type es = sizeField.write(iter, len);
                        if (es != status_type::success) {
                            return es;
                        }

                        MARSHALLING_ASSERT(sizeField.length() <= len);
                        return base_impl_type::write(iter, len - sizeField.length());
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        using SizeValueType = typename size_field_type::value_type;
                        size_field_type sizeField;
                        sizeField.value() = static_cast<SizeValueType>(base_impl_type::value().size());
                        sizeField.write_no_status(iter);
                        base_impl_type::write_no_status(iter);
                    }
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_SEQUENCE_SIZE_FIELD_PREFIX_HPP
