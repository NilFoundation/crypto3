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

#ifndef MARSHALLING_SEQUENCE_FIXED_SIZE_HPP
#define MARSHALLING_SEQUENCE_FIXED_SIZE_HPP

#include <cstddef>

#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<typename TBase>
                class sequence_fixed_size_base : public TBase {
                    using base_impl_type = TBase;

                public:
                    using value_type = typename base_impl_type::value_type;
                    using element_type = typename base_impl_type::element_type;

                    explicit sequence_fixed_size_base(std::size_t maxSize) : fixedSize_(maxSize) {
                    }

                    sequence_fixed_size_base(std::size_t maxSize, const value_type &val) :
                        base_impl_type(val), fixedSize_(maxSize) {
                    }

                    sequence_fixed_size_base(std::size_t maxSize, value_type &&val) :
                        base_impl_type(std::move(val)), fixedSize_(maxSize) {
                    }

                    sequence_fixed_size_base(const sequence_fixed_size_base &) = default;

                    sequence_fixed_size_base(sequence_fixed_size_base &&) = default;

                    sequence_fixed_size_base &operator=(const sequence_fixed_size_base &) = default;

                    sequence_fixed_size_base &operator=(sequence_fixed_size_base &&) = default;

                    std::size_t length() const {
                        auto currSize = base_impl_type::value().size();
                        if (currSize == fixedSize_) {
                            return base_impl_type::length();
                        }

                        if (currSize < fixedSize_) {
                            auto remSize = fixedSize_ - currSize;
                            auto dummyElem = element_type();
                            return base_impl_type::length() + (remSize * base_impl_type::element_length(dummyElem));
                        }

                        using tag = typename std::conditional<std::is_integral<element_type>::value
                                                                  && (sizeof(element_type) == sizeof(std::uint8_t)),
                                                              has_raw_data_tag, has_fields_tag>::type;

                        return recalc_len(tag());
                    }

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t len) {
                        return base_impl_type::read_n(fixedSize_, iter, len);
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) {
                        return base_impl_type::read_no_status_n(fixedSize_, iter);
                    }

                    template<typename TIter>
                    status_type write(TIter &iter, std::size_t len) const {
                        auto writeCount = std::min(base_impl_type::value().size(), fixedSize_);
                        status_type es = base_impl_type::write_n(writeCount, iter, len);
                        if (es != status_type::success) {
                            return es;
                        }

                        auto remCount = fixedSize_ - writeCount;
                        if (remCount == 0) {
                            return es;
                        }

                        auto dummyElem = element_type();
                        while (0 < remCount) {
                            es = base_impl_type::write_element(dummyElem, iter, len);
                            if (es != status_type::success) {
                                break;
                            }

                            --remCount;
                        }

                        return es;
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        auto writeCount = std::min(base_impl_type::value().size(), fixedSize_);
                        base_impl_type::write_no_status_n(writeCount, iter);

                        auto remCount = fixedSize_ - writeCount;
                        if (remCount == 0) {
                            return;
                        }

                        auto dummyElem = element_type();
                        while (0 < remCount) {
                            base_impl_type::write_element_no_status(dummyElem, iter);
                            --remCount;
                        }
                    }

                    bool valid() const {
                        return base_impl_type::valid() && (base_impl_type::value().size() <= fixedSize_);
                    }

                    bool refresh() {
                        if (!base_impl_type::refresh()) {
                            return false;
                        }

                        using tag =
                            typename std::conditional<has_member_function_resize<element_type>::value,
                                                      has_resize_tag, no_resize_tag>::type;

                        return eval_refresh(tag());
                    }

                private:
                    struct has_raw_data_tag { };
                    struct has_fields_tag { };
                    struct has_fixed_length_elems_tag { };
                    struct has_var_length_elems_tag { };
                    struct has_resize_tag { };
                    struct no_resize_tag { };

                    std::size_t recalc_len(has_fields_tag) const {
                        using tag =
                            typename std::conditional<element_type::min_length() == element_type::max_length(),
                                                      has_fixed_length_elems_tag, has_var_length_elems_tag>::type;
                        return recalc_len(tag());
                    }

                    std::size_t recalc_len(has_raw_data_tag) const {
                        return fixedSize_;
                    }

                    std::size_t recalc_len(has_fixed_length_elems_tag) const {
                        return fixedSize_ * element_type::min_length();
                    }

                    std::size_t recalc_len(has_var_length_elems_tag) const {
                        std::size_t result = 0U;
                        auto count = fixedSize_;
                        for (auto &elem : base_impl_type::value()) {
                            if (count == 0U) {
                                break;
                            }

                            result += base_impl_type::element_length(elem);
                            --count;
                        }
                        return result;
                    }

                    bool eval_refresh(has_resize_tag) {
                        if (base_impl_type::value() == fixedSize_) {
                            return false;
                        }

                        base_impl_type::value().resize(fixedSize_);
                        return true;
                    }

                    static constexpr bool eval_refresh(no_resize_tag) {
                        return false;
                    }

                    std::size_t fixedSize_ = 0;
                };

                template<std::size_t TSize, typename TBase>
                class sequence_fixed_size : public sequence_fixed_size_base<TBase> {
                    using base_impl_type = sequence_fixed_size_base<TBase>;

                public:
                    using value_type = typename base_impl_type::value_type;
                    using element_type = typename base_impl_type::element_type;

                    explicit sequence_fixed_size() : base_impl_type(TSize) {
                    }

                    explicit sequence_fixed_size(const value_type &val) : base_impl_type(TSize, val) {
                    }

                    sequence_fixed_size(value_type &&val) : base_impl_type(TSize, std::move(val)) {
                    }

                    sequence_fixed_size(const sequence_fixed_size &) = default;

                    sequence_fixed_size(sequence_fixed_size &&) = default;

                    sequence_fixed_size &operator=(const sequence_fixed_size &) = default;

                    sequence_fixed_size &operator=(sequence_fixed_size &&) = default;

                    static constexpr std::size_t min_length() {
                        return base_impl_type::min_length() + base_impl_type::min_element_length() * TSize;
                    }

                    static constexpr std::size_t max_length() {
                        return base_impl_type::min_length() + base_impl_type::max_element_length() * TSize;
                    }
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_SEQUENCE_FIXED_SIZE_HPP
