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

#ifndef MARSHALLING_SEQUENCE_SER_LENGTH_FIELD_PREFIX_HPP
#define MARSHALLING_SEQUENCE_SER_LENGTH_FIELD_PREFIX_HPP

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<typename TLenField, status_type TStatus, typename TBase>
                class sequence_ser_length_field_prefix : public TBase {
                    using base_impl_type = TBase;
                    using len_field_type = TLenField;

                    static_assert(!len_field_type::is_version_dependent(),
                                  "Prefix fields must not be version dependent");

                public:
                    using value_type = typename base_impl_type::value_type;
                    using element_type = typename base_impl_type::element_type;

                    sequence_ser_length_field_prefix() = default;

                    explicit sequence_ser_length_field_prefix(const value_type &val) : base_impl_type(val) {
                    }

                    explicit sequence_ser_length_field_prefix(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    sequence_ser_length_field_prefix(const sequence_ser_length_field_prefix &) = default;

                    sequence_ser_length_field_prefix(sequence_ser_length_field_prefix &&) = default;

                    sequence_ser_length_field_prefix &operator=(const sequence_ser_length_field_prefix &) = default;

                    sequence_ser_length_field_prefix &operator=(sequence_ser_length_field_prefix &&) = default;

                    std::size_t length() const {
                        using LenValueType = typename len_field_type::value_type;
                        auto valLength = base_impl_type::length();
                        len_field_type lenField;
                        lenField.value() = static_cast<LenValueType>(valLength);
                        return lenField.length() + valLength;
                    }

                    static constexpr std::size_t min_length() {
                        return len_field_type::min_length() + base_impl_type::min_length();
                    }

                    static constexpr std::size_t max_length() {
                        return len_field_type::max_length() + base_impl_type::max_length();
                    }

                    bool valid() const {
                        len_field_type lenField;
                        lenField.value() = base_impl_type::length();
                        return lenField.valid() && base_impl_type::valid();
                    }

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t len) {
                        len_field_type lenField;
                        status_type es = lenField.read(iter, len);
                        if (es != status_type::success) {
                            return es;
                        }

                        es = base_impl_type::read(iter, static_cast<std::size_t>(lenField.value()));
                        if (es == status_type::not_enough_data) {
                            return TStatus;
                        }

                        return es;
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) = delete;

                    template<typename TIter>
                    status_type write(TIter &iter, std::size_t len) const {
                        using LenValueType = typename len_field_type::value_type;
                        auto lenVal = base_impl_type::length();
                        len_field_type lenField;
                        lenField.value() = static_cast<LenValueType>(lenVal);
                        status_type es = lenField.write(iter, len);
                        if (es != status_type::success) {
                            return es;
                        }

                        MARSHALLING_ASSERT(lenField.length() <= len);
                        return base_impl_type::write(iter, lenVal);
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        using LenValueType = typename len_field_type::value_type;
                        auto lenVal = base_impl_type::length();
                        len_field_type lenField;
                        lenField.value() = static_cast<LenValueType>(lenVal);
                        lenField.write_no_status(iter);
                        base_impl_type::write_no_status(iter);
                    }
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_SEQUENCE_SER_LENGTH_FIELD_PREFIX_HPP
