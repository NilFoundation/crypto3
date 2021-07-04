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

#ifndef MARSHALLING_SEQUENCE_ELEM_FIXED_SER_LENGTH_FIELD_PREFIX_HPP
#define MARSHALLING_SEQUENCE_ELEM_FIXED_SER_LENGTH_FIELD_PREFIX_HPP

#include <iterator>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/types/detail/common_funcs.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<typename TLenField, status_type TStatus, typename TBase>
                class sequence_elem_fixed_ser_length_field_prefix : public TBase {
                    using base_impl_type = TBase;
                    using len_field_type = TLenField;

                    static_assert(!len_field_type::is_version_dependent(),
                                  "Prefix fields must not be version dependent");

                public:
                    using value_type = typename base_impl_type::value_type;
                    using element_type = typename base_impl_type::element_type;

                    sequence_elem_fixed_ser_length_field_prefix() = default;

                    explicit sequence_elem_fixed_ser_length_field_prefix(const value_type &val) : base_impl_type(val) {
                    }

                    explicit sequence_elem_fixed_ser_length_field_prefix(value_type &&val) :
                        base_impl_type(std::move(val)) {
                    }

                    sequence_elem_fixed_ser_length_field_prefix(const sequence_elem_fixed_ser_length_field_prefix &)
                        = default;

                    sequence_elem_fixed_ser_length_field_prefix(sequence_elem_fixed_ser_length_field_prefix &&)
                        = default;

                    sequence_elem_fixed_ser_length_field_prefix &
                        operator=(const sequence_elem_fixed_ser_length_field_prefix &)
                        = default;

                    sequence_elem_fixed_ser_length_field_prefix &
                        operator=(sequence_elem_fixed_ser_length_field_prefix &&)
                        = default;

                    std::size_t length() const {
                        return length_internal(Len_field_length_tag());
                    }

                    static constexpr std::size_t min_length() {
                        return len_field_type::min_length() + base_impl_type::min_length();
                    }

                    static constexpr std::size_t max_length() {
                        return detail::common_funcs::max_supported_length();
                    }

                    template<typename TIter>
                    status_type read_element(element_type &elem, TIter &iter, std::size_t &len) const {
                        MARSHALLING_ASSERT(elemLen_ < max_length_limit);

                        if (len < elemLen_) {
                            return status_type::not_enough_data;
                        }

                        std::size_t elemLen = elemLen_;
                        status_type es = base_impl_type::read_element(elem, iter, elemLen);
                        if (es == status_type::not_enough_data) {
                            return TStatus;
                        }

                        if (es != status_type::success) {
                            return es;
                        }

                        MARSHALLING_ASSERT(elemLen <= elemLen_);
                        std::advance(iter, elemLen);
                        len -= elemLen_;
                        return status_type::success;
                    }

                    template<typename TIter>
                    void read_element_no_status(element_type &elem, TIter &iter) const = delete;

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t len) {
                        status_type es = read_len(iter, len);
                        if (es != status_type::success) {
                            return es;
                        }

                        return detail::common_funcs::read_sequence(*this, iter, len);
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) = delete;

                    template<typename TIter>
                    status_type read_n(std::size_t count, TIter &iter, std::size_t &len) {
                        if (0U < count) {
                            status_type es = read_len(iter, len);
                            if (es != status_type::success) {
                                return es;
                            }
                        } else {
                            elemLen_ = 0U;
                        }
                        return detail::common_funcs::read_sequence_n(*this, count, iter, len);
                    }

                    template<typename TIter>
                    void read_no_status_n(std::size_t count, TIter &iter) = delete;

                    template<typename TIter>
                    status_type write(TIter &iter, std::size_t len) const {
                        if (!base_impl_type::value().empty()) {
                            status_type es = write_len(iter, len);    // len is updated
                            if (es != status_type::success) {
                                return es;
                            }
                        }

                        return detail::common_funcs::write_sequence(*this, iter, len);
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        if (!base_impl_type::value().empty()) {
                            write_len_no_status(iter);
                        }
                        detail::common_funcs::write_sequence_no_status(*this, iter);
                    }

                    template<typename TIter>
                    status_type write_n(std::size_t count, TIter &iter, std::size_t &len) const {
                        if (0U < count) {
                            status_type es = write_len(iter, len);    // len is updated
                            if (es != status_type::success) {
                                return es;
                            }
                        }

                        return detail::common_funcs::write_sequence_n(*this, count, iter, len);
                    }

                    template<typename TIter>
                    void write_no_status_n(std::size_t count, TIter &iter) const {
                        if (0U < count) {
                            write_len_no_status(iter);
                        }
                        detail::common_funcs::write_sequence_no_status_n(*this, count, iter);
                    }

                private:
                    struct fixed_length_len_field_tag { };
                    struct var_length_len_field_tag { };

                    using Len_field_length_tag =
                        typename std::conditional<len_field_type::min_length() == len_field_type::max_length(),
                                                  fixed_length_len_field_tag,
                                                  var_length_len_field_tag>::type;

                    std::size_t length_internal(fixed_length_len_field_tag) const {
                        std::size_t prefixLen = 0U;
                        if (!base_impl_type::value().empty()) {
                            prefixLen = len_field_type::min_length();
                        }
                        return (prefixLen + base_impl_type::length());
                    }

                    std::size_t length_internal(var_length_len_field_tag) const {
                        std::size_t prefixLen = 0U;
                        if (!base_impl_type::value().empty()) {
                            len_field_type lenField;
                            lenField.value() = base_impl_type::min_element_length();
                            prefixLen = lenField.length();
                        }

                        return (prefixLen + base_impl_type::length());
                    }

                    template<typename TIter>
                    static void advance_write_iterator(TIter &iter, std::size_t len) {
                        detail::common_funcs::advance_write_iterator(iter, len);
                    }

                    template<typename TIter>
                    status_type read_len(TIter &iter, std::size_t &len) {
                        len_field_type lenField;
                        status_type es = lenField.read(iter, len);
                        if (es != status_type::success) {
                            return es;
                        }

                        len -= lenField.length();

                        elemLen_ = static_cast<std::size_t>(lenField.value());
                        if (elemLen_ == max_length_limit) {
                            return TStatus;
                        }

                        return status_type::success;
                    }

                    template<typename TIter>
                    status_type write_len(TIter &iter, std::size_t &len) const {
                        std::size_t elemLength = base_impl_type::min_element_length();
                        len_field_type lenField;
                        lenField.value() = elemLength;
                        status_type es = lenField.write(iter, len);
                        if (es != status_type::success) {
                            return es;
                        }

                        len -= lenField.length();
                        return es;
                    }

                    template<typename TIter>
                    void write_len_no_status(TIter &iter) const {
                        std::size_t elemLength = base_impl_type::min_element_length();
                        len_field_type lenField;
                        lenField.value() = elemLength;
                        lenField.write_no_status(iter);
                    }

                    static_assert(
                        base_impl_type::min_element_length() == base_impl_type::max_element_length(),
                        "Option sequence_elem_fixed_ser_length_field_prefix can be used only with fixed length "
                        "elements.");
                    static_assert(1U <= len_field_type::min_length(), "Invalid min length assumption");

                    static const std::size_t max_length_limit = std::numeric_limits<std::size_t>::max();
                    std::size_t elemLen_ = max_length_limit;
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_SEQUENCE_ELEM_FIXED_SER_LENGTH_FIELD_PREFIX_HPP
