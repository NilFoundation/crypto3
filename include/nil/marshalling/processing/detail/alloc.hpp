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

/// @file nil/marshalling/processing/alloc.h
/// This file contains various generic allocator classes that may be used
/// to allocate objects using dynamic memory or "in-place" allocations.

#ifndef MARSHALLING_ALLOC_DETAIL_HPP
#define MARSHALLING_ALLOC_DETAIL_HPP

#include <memory>
#include <type_traits>
#include <array>
#include <algorithm>

#include <nil/detail/type_traits.hpp>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/processing/tuple.hpp>

namespace nil {
    namespace marshalling {
        namespace processing {
            namespace alloc {
                namespace detail {

                    template<typename T>
                    class in_place_deleter {
                        template<typename U>
                        friend class in_place_deleter;

                    public:
                        in_place_deleter(bool *allocated = nullptr) : allocated_(allocated) {
                        }

                        in_place_deleter(const in_place_deleter &other) = delete;

                        template<typename U>
                        in_place_deleter(in_place_deleter<U> &&other) : allocated_(other.allocated_) {
                            static_assert(std::is_base_of<T, U>::value || std::is_base_of<U, T>::value
                                              || std::is_convertible<U, T>::value || std::is_convertible<T, U>::value,
                                          "To make Deleter convertible, their template parameters "
                                          "must be convertible.");

                            other.allocated_ = nullptr;
                        }

                        ~in_place_deleter() noexcept {
                            MARSHALLING_ASSERT(allocated_ == nullptr);
                        }

                        in_place_deleter &operator=(const in_place_deleter &other) = delete;

                        template<typename U>
                        in_place_deleter &operator=(in_place_deleter<U> &&other) {
                            static_assert(std::is_base_of<T, U>::value || std::is_base_of<U, T>::value
                                              || std::is_convertible<U, T>::value || std::is_convertible<T, U>::value,
                                          "To make Deleter convertible, their template parameters "
                                          "must be convertible.");

                            if (reinterpret_cast<void *>(this) == reinterpret_cast<const void *>(&other)) {
                                return *this;
                            }

                            MARSHALLING_ASSERT(allocated_ == nullptr);
                            allocated_ = other.allocated_;
                            other.allocated_ = nullptr;
                            return *this;
                        }

                        void operator()(T *obj) {
                            MARSHALLING_ASSERT(allocated_ != nullptr);
                            MARSHALLING_ASSERT(*allocated_);
                            obj->~T();
                            *allocated_ = false;
                            allocated_ = nullptr;
                        }

                    private:
                        bool *allocated_;
                    };

                }    // namespace detail
            }    // namespace alloc
        }    // namespace processing
    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_ALLOC_DETAIL_HPP
