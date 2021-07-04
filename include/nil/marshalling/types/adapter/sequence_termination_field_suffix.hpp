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

#ifndef MARSHALLING_SEQUENCE_TERMINATION_FIELD_SUFFIX_HPP
#define MARSHALLING_SEQUENCE_TERMINATION_FIELD_SUFFIX_HPP

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<typename TTermFieldType, typename TBase>
                class sequence_termination_field_suffix : public TBase {
                    using base_impl_type = TBase;
                    using term_field_type = TTermFieldType;

                    static_assert(!term_field_type::is_version_dependent(),
                                  "Suffix fields must not be version dependent");

                public:
                    using value_type = typename base_impl_type::value_type;
                    using element_type = typename base_impl_type::element_type;

                    sequence_termination_field_suffix() = default;

                    explicit sequence_termination_field_suffix(const value_type &val) : base_impl_type(val) {
                    }

                    explicit sequence_termination_field_suffix(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    sequence_termination_field_suffix(const sequence_termination_field_suffix &) = default;

                    sequence_termination_field_suffix(sequence_termination_field_suffix &&) = default;

                    sequence_termination_field_suffix &operator=(const sequence_termination_field_suffix &) = default;

                    sequence_termination_field_suffix &operator=(sequence_termination_field_suffix &&) = default;

                    constexpr std::size_t length() const {
                        return term_field_type().length() + base_impl_type::length();
                    }

                    static constexpr std::size_t min_length() {
                        return term_field_type::min_length() + base_impl_type::min_length();
                    }

                    static constexpr std::size_t max_length() {
                        return term_field_type::max_length() + base_impl_type::max_length();
                    }

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t len) {
                        using IterType = typename std::decay<decltype(iter)>::type;
                        using IterTag = typename std::iterator_traits<IterType>::iterator_category;
                        static_assert(std::is_base_of<std::random_access_iterator_tag, IterTag>::value,
                                      "Only random access iterator for reading is supported with "
                                      "nil::marshalling::option::sequence_termination_field_suffix option");

                        using elem_tag =
                            typename std::conditional<std::is_integral<element_type>::value
                                                          && (sizeof(element_type) == sizeof(std::uint8_t)),
                                                      raw_data_tag,
                                                      field_tag>::type;

                        return read_internal(iter, len, elem_tag());
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) = delete;

                    template<typename TIter>
                    status_type write(TIter &iter, std::size_t len) const {
                        term_field_type termField;
                        auto trailLen = termField.length();
                        status_type es = base_impl_type::write(iter, len - trailLen);
                        if (es != status_type::success) {
                            return es;
                        }

                        return termField.write(iter, trailLen);
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        term_field_type termField;
                        base_impl_type::write_no_status(iter);
                        termField.write_no_status(iter);
                    }

                private:
                    struct raw_data_tag { };
                    struct field_tag { };

                    template<typename TIter>
                    status_type read_internal(TIter &iter, std::size_t len, field_tag) {
                        base_impl_type::clear();
                        term_field_type termField;
                        while (true) {
                            auto iterCpy = iter;
                            status_type es = termField.read(iterCpy, len);
                            if ((es == status_type::success) && (termField == term_field_type())) {
                                std::advance(iter, termField.length());
                                return es;
                            }

                            auto &elem = base_impl_type::create_back();
                            es = base_impl_type::read_element(elem, iter, len);
                            if (es != status_type::success) {
                                base_impl_type::value().pop_back();
                                return es;
                            }
                        }

                        return status_type::success;
                    }

                    template<typename TIter>
                    status_type read_internal(TIter &iter, std::size_t len, raw_data_tag) {
                        term_field_type termField;
                        std::size_t consumed = 0;
                        while (consumed < len) {
                            auto iterCpy = iter + consumed;
                            status_type es = termField.read(iterCpy, len);
                            if ((es == status_type::success) && (termField == term_field_type())) {
                                break;
                            }

                            ++consumed;
                        }

                        if (len <= consumed) {
                            return status_type::not_enough_data;
                        }

                        status_type es = base_impl_type::read(iter, consumed);
                        if (es != status_type::success) {
                            return es;
                        }

                        std::advance(iter, termField.length());
                        return status_type::success;
                    }
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_SEQUENCE_TERMINATION_FIELD_SUFFIX_HPP
