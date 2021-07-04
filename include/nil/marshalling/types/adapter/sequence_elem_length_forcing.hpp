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

#ifndef MARSHALLING_SEQUENCE_ELEM_LENGTH_FORCING_HPP
#define MARSHALLING_SEQUENCE_ELEM_LENGTH_FORCING_HPP

#include <iterator>
#include <limits>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/types/detail/common_funcs.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<typename TBase>
                class sequence_elem_length_forcing : public TBase {
                    using base_impl_type = TBase;

                public:
                    using value_type = typename base_impl_type::value_type;
                    using element_type = typename base_impl_type::element_type;

                    sequence_elem_length_forcing() = default;

                    explicit sequence_elem_length_forcing(const value_type &val) : base_impl_type(val) {
                    }

                    explicit sequence_elem_length_forcing(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    sequence_elem_length_forcing(const sequence_elem_length_forcing &) = default;

                    sequence_elem_length_forcing(sequence_elem_length_forcing &&) = default;

                    sequence_elem_length_forcing &operator=(const sequence_elem_length_forcing &) = default;

                    sequence_elem_length_forcing &operator=(sequence_elem_length_forcing &&) = default;

                    void force_read_elem_length(std::size_t val) {
                        MARSHALLING_ASSERT(val != cleared);
                        forced_ = val;
                    }

                    void clear_read_elem_length_forcing() {
                        forced_ = cleared;
                    }

                    std::size_t length() const {
                        if (forced_ != cleared) {
                            return base_impl_type::value().size() * forced_;
                        }

                        return base_impl_type::length();
                    }

                    std::size_t element_length(const element_type &elem) const {
                        if (forced_ != cleared) {
                            return forced_;
                        }
                        return base_impl_type::element_length(elem);
                    }

                    static constexpr std::size_t max_element_length() {
                        return detail::common_funcs::max_supported_length();
                    }

                    template<typename TIter>
                    status_type read_element(element_type &elem, TIter &iter, std::size_t &len) const {
                        using IterType = typename std::decay<decltype(iter)>::type;
                        using IterTag = typename std::iterator_traits<IterType>::iterator_category;
                        static_assert(std::is_base_of<std::random_access_iterator_tag, IterTag>::value,
                                      "Only random access iterator for reading is supported with "
                                      "nil::marshalling::option::SequenceElemLengthForcingEnabled option");

                        if (forced_ == cleared) {
                            return base_impl_type::read_element(elem, iter, len);
                        }

                        if (len < forced_) {
                            return status_type::not_enough_data;
                        }

                        auto iterTmp = iter;
                        auto remLen = forced_;
                        std::advance(iter, forced_);
                        len -= forced_;
                        return base_impl_type::read_element(elem, iterTmp, remLen);
                    }

                    // Why is this so? Function declared void, but in fact it returns status_type
                    template<typename TIter>
                    void read_element_no_status(element_type &elem, TIter &iter) const {
                        using IterType = typename std::decay<decltype(iter)>::type;
                        using IterTag = typename std::iterator_traits<IterType>::iterator_category;
                        static_assert(std::is_base_of<std::random_access_iterator_tag, IterTag>::value,
                                      "Only random access iterator for reading is supported with "
                                      "nil::marshalling::option::SequenceElemLengthForcingEnabled option");

                        if (forced_ == cleared) {
                            return base_impl_type::read_element_no_status(elem, iter);
                        }

                        auto fromIter = iter;
                        auto es = base_impl_type::read_element_no_status(elem, iter);
                        if (es != status_type::success) {
                            return es;
                        }

                        auto consumed = std::distance(fromIter, iter);
                        if (consumed < forced_) {
                            std::advance(iter, forced_ - consumed);
                        }
                    }

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
                    void read_no_status_n(std::size_t count, TIter &iter) {
                        detail::common_funcs::read_sequence_no_status_n(*this, count, iter);
                    }

                private:
                    static const std::size_t cleared = std::numeric_limits<std::size_t>::max();
                    std::size_t forced_ = cleared;
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_SEQUENCE_ELEM_LENGTH_FORCING_HPP
