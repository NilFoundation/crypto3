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

#ifndef MARSHALLING_SEQUENCE_ELEM_SER_LENGTH_FIELD_PREFIX_HPP
#define MARSHALLING_SEQUENCE_ELEM_SER_LENGTH_FIELD_PREFIX_HPP

#include <iterator>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/types/detail/common_funcs.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<typename TLenField, status_type TStatus, typename TBase>
                class sequence_elem_ser_length_field_prefix : public TBase {
                    using base_impl_type = TBase;
                    using LenField = TLenField;

                    static_assert(!LenField::is_version_dependent(), "Prefix fields must not be version dependent");

                public:
                    using value_type = typename base_impl_type::value_type;
                    using element_type = typename base_impl_type::element_type;

                    sequence_elem_ser_length_field_prefix() = default;

                    explicit sequence_elem_ser_length_field_prefix(const value_type &val) : base_impl_type(val) {
                    }

                    explicit sequence_elem_ser_length_field_prefix(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    sequence_elem_ser_length_field_prefix(const sequence_elem_ser_length_field_prefix &) = default;

                    sequence_elem_ser_length_field_prefix(sequence_elem_ser_length_field_prefix &&) = default;

                    sequence_elem_ser_length_field_prefix &operator=(const sequence_elem_ser_length_field_prefix &)
                        = default;

                    sequence_elem_ser_length_field_prefix &operator=(sequence_elem_ser_length_field_prefix &&)
                        = default;

                    std::size_t length() const {
                        return length_internal(Len_field_length_tag(), ElemLengthTag());
                    }

                    std::size_t element_length(const element_type &elem) const {
                        return element_length_internal(elem, Len_field_length_tag());
                    }

                    static constexpr std::size_t min_element_length() {
                        return LenField::min_length() + base_impl_type::min_element_length();
                    }

                    static constexpr std::size_t max_element_length() {
                        return LenField::max_length() + base_impl_type::max_element_length();
                    }

                    template<typename TIter>
                    status_type read_element(element_type &elem, TIter &iter, std::size_t &len) const {
                        LenField lenField;
                        status_type es = lenField.read(iter, len);
                        if (es != status_type::success) {
                            return es;
                        }

                        len -= lenField.length();
                        if (len < lenField.value()) {
                            return status_type::not_enough_data;
                        }

                        const auto reqLen = static_cast<std::size_t>(lenField.value());
                        std::size_t elemLen = reqLen;
                        es = base_impl_type::read_element(elem, iter, elemLen);
                        if (es == status_type::not_enough_data) {
                            return TStatus;
                        }

                        if (es != status_type::success) {
                            return es;
                        }

                        MARSHALLING_ASSERT(elemLen <= reqLen);
                        std::advance(iter, elemLen);
                        len -= reqLen;
                        return status_type::success;
                    }

                    template<typename TIter>
                    void read_element_no_status(element_type &elem, TIter &iter) const = delete;

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t len) {
                        return detail::common_funcs::read_sequence(*this, iter, len);
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) = delete;

                    template<typename TIter>
                    status_type read_n(std::size_t count, TIter &iter, std::size_t &len) {
                        return detail::common_funcs::read_sequence_n(*this, count, iter, len);
                    }

                    template<typename TIter>
                    void read_no_status_n(std::size_t count, TIter &iter) = delete;

                    template<typename TIter>
                    status_type write_element(const element_type &elem, TIter &iter, std::size_t &len) const {
                        auto elemLength = base_impl_type::element_length(elem);
                        LenField lenField;
                        lenField.value() = elemLength;
                        status_type es = lenField.write(iter, len);
                        if (es != status_type::success) {
                            return es;
                        }

                        len -= lenField.length();
                        return base_impl_type::write_element(elem, iter, len);
                    }

                    template<typename TIter>
                    static void write_element_no_status(const element_type &elem, TIter &iter) {
                        auto elemLength = base_impl_type::element_length(elem);
                        LenField lenField;
                        lenField.value() = elemLength;
                        lenField.write_no_status(iter);
                        base_impl_type::write_element_no_status(elem, iter);
                    }

                    template<typename TIter>
                    status_type write(TIter &iter, std::size_t len) const {
                        return detail::common_funcs::write_sequence(*this, iter, len);
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        detail::common_funcs::write_sequence_no_status(*this, iter);
                    }

                    template<typename TIter>
                    status_type write_n(std::size_t count, TIter &iter, std::size_t &len) const {
                        return detail::common_funcs::write_sequence_n(*this, count, iter, len);
                    }

                    template<typename TIter>
                    void write_no_status_n(std::size_t count, TIter &iter) const {
                        detail::common_funcs::write_sequence_no_status_n(*this, count, iter);
                    }

                private:
                    struct FixedLengthLenFieldTag { };
                    struct VarLengthLenFieldTag { };
                    struct FixedLengthElemTag { };
                    struct VarLengthElemTag { };

                    using Len_field_length_tag =
                        typename std::conditional<LenField::min_length() == LenField::max_length(),
                                                  FixedLengthLenFieldTag,
                                                  VarLengthLenFieldTag>::type;

                    using ElemLengthTag = typename std::conditional<base_impl_type::min_element_length()
                                                                        == base_impl_type::max_element_length(),
                                                                    FixedLengthElemTag,
                                                                    VarLengthElemTag>::type;

                    std::size_t length_internal(FixedLengthLenFieldTag, FixedLengthElemTag) const {
                        return (LenField::min_length() + base_impl_type::min_element_length())
                               * base_impl_type::value().size();
                    }

                    std::size_t length_internal(FixedLengthLenFieldTag, VarLengthElemTag) const {
                        std::size_t result = 0U;
                        for (auto &elem : base_impl_type::value()) {
                            result += (LenField::min_length() + base_impl_type::element_length(elem));
                        }
                        return result;
                    }

                    std::size_t length_internal(VarLengthLenFieldTag, FixedLengthElemTag) const {
                        LenField lenField;
                        lenField.value() = base_impl_type::min_element_length();
                        return (lenField.length() + base_impl_type::min_element_length())
                               * base_impl_type::value().size();
                    }

                    std::size_t length_internal(VarLengthLenFieldTag, VarLengthElemTag) const {
                        std::size_t result = 0U;
                        for (auto &elem : base_impl_type::value()) {
                            LenField lenField;
                            auto elemLength = base_impl_type::element_length(elem);
                            lenField.value() = elemLength;
                            result += (lenField.length() + elemLength);
                        }
                        return result;
                    }

                    std::size_t element_length_internal(const element_type &elem, FixedLengthLenFieldTag) const {
                        return LenField::min_length() + base_impl_type::element_length(elem);
                    }

                    std::size_t element_length_internal(const VarLengthLenFieldTag &elem,
                                                        FixedLengthLenFieldTag) const {
                        LenField lenField;
                        auto elemLength = base_impl_type::element_length(elem);
                        lenField.value() = elemLength;
                        return lenField.length() + elemLength;
                    }

                    template<typename TIter>
                    static void advance_write_iterator(TIter &iter, std::size_t len) {
                        using IterType = typename std::decay<decltype(iter)>::type;
                        using byte_type = typename std::iterator_traits<IterType>::value_type;
                        while (len > 0U) {
                            *iter = byte_type();
                            ++iter;
                            --len;
                        }
                    }
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_SEQUENCE_ELEM_SER_LENGTH_FIELD_PREFIX_HPP
