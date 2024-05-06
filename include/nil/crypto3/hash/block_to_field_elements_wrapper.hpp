//---------------------------------------------------------------------------//
// Copyright (c) 2024 Iosif (x-mass) <x-mass@nil.foundation>
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

#ifndef CRYPTO3_HASH_BLOCK_TO_FIELD_ELEMENTS_WRAPPER_HPP
#define CRYPTO3_HASH_BLOCK_TO_FIELD_ELEMENTS_WRAPPER_HPP

#include <limits>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {

            template<typename Field, typename Container, bool OverflowOnPurpose = false>
            class block_to_field_elements_wrapper {
            public:
                static_assert(std::numeric_limits<typename Container::value_type>::is_specialized);

                block_to_field_elements_wrapper(const Container& container)
                    : block_to_field_elements_wrapper(container.begin(), container.end()) {}

                block_to_field_elements_wrapper(typename Container::const_iterator begin, typename Container::const_iterator end)
                    : input_container_begin_(begin), input_container_end_(end) {}

                class conversing_iterator {
                public:
                    using self_type = conversing_iterator;
                    using value_type = typename Field::value_type;
                    using reference = const value_type&;
                    using pointer = const value_type*;
                    using iterator_category = std::input_iterator_tag;
                    using difference_type = std::ptrdiff_t;

                    conversing_iterator(typename Container::const_iterator begin, typename Container::const_iterator end)
                        : input_container_l_(begin)
                        , input_container_r_(end) {}

                    self_type operator++() {
                        advance_container_iter();
                        return *this;
                    }

                    self_type operator++(int) {
                        self_type tmp = *this;
                        ++(*this);
                        return tmp;
                    }

                    bool operator==(const self_type& other) const {
                        return input_container_l_ == other.input_container_l_;
                    }

                    bool operator!=(const self_type& other) const {
                        return !(*this == other);
                    }

                    const value_type& operator*() const {
                        ensure_element_is_filled();
                        return field_element_;
                    }

                protected:
                    static constexpr std::size_t input_value_bits_ =
                        std::numeric_limits<typename Container::value_type>::digits
                        + std::numeric_limits<typename Container::value_type>::is_signed;
                    static constexpr std::size_t container_elements_per_field_element_ =
                        Field::modulus_bits / input_value_bits_ + ((Field::modulus_bits % input_value_bits_) ? OverflowOnPurpose : 0);

                private:
                    friend class block_to_field_elements_wrapper;

                    typename Container::const_iterator input_container_l_;
                    typename Container::const_iterator input_container_r_;
                    mutable value_type field_element_ = value_type::zero();
                    mutable bool element_filled_ = false;

                    void ensure_element_is_filled() const {
                        if (element_filled_) {
                            return;
                        }
                        value_type field_element = value_type::zero();
                        std::size_t field_bits_left_ = Field::modulus_bits;
                        auto tmp_iter = input_container_l_;
                        for (std::size_t i = 0; i < container_elements_per_field_element_ && tmp_iter != input_container_r_; ++i) {
                            field_element.data <<= input_value_bits_; // TODO: add shift operators to field values
                            field_element += *tmp_iter++;
                            field_bits_left_ -= input_value_bits_;
                        }
                        field_element_ = field_element;
                        element_filled_ = true;
                    }

                    void advance_container_iter() {
                        for (std::size_t i = 0; i < container_elements_per_field_element_ && input_container_l_ != input_container_r_; ++i) {
                            input_container_l_++;
                        }
                        element_filled_ = false;
                    }
                };

                // Required for BOOST_RANGE_CONCEPT_ASSERT
                using iterator = conversing_iterator;
                using const_iterator = conversing_iterator;

                conversing_iterator begin() const {
                    return conversing_iterator(input_container_begin_, input_container_end_);
                }

                conversing_iterator end() const {
                    return conversing_iterator(input_container_end_, input_container_end_);
                }

                std::size_t size() const {
                    const std::size_t size = std::distance(input_container_begin_, input_container_end_);
                    return (size + conversing_iterator::container_elements_per_field_element_ - 1)
                        / conversing_iterator::container_elements_per_field_element_;
                }

            private:
                typename Container::const_iterator input_container_begin_;
                typename Container::const_iterator input_container_end_;
            };

            template<typename Output, typename Container, bool OverflowOnPurpose, bool = algebra::is_field_element<Output>::value>
            struct conditional_block_to_field_elements_wrapper_helper {
                using type = Container;
            };

            template<typename Output, typename Container, bool OverflowOnPurpose>
            struct conditional_block_to_field_elements_wrapper_helper<Output, Container, OverflowOnPurpose, true> {
                using type = block_to_field_elements_wrapper<typename Output::field_type, Container, OverflowOnPurpose>;
            };

            template<typename Output, typename Container, bool OverflowOnPurpose = false>
            using conditional_block_to_field_elements_wrapper = typename conditional_block_to_field_elements_wrapper_helper<Output, Container, OverflowOnPurpose>::type;


        }    // namespace hashes
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_BLOCK_TO_FIELD_ELEMENTS_WRAPPER_HPP
