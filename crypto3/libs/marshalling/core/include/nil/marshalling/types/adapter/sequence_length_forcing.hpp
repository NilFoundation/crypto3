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

#ifndef MARSHALLING_SEQUENCE_LENGTH_FORCING_HPP
#define MARSHALLING_SEQUENCE_LENGTH_FORCING_HPP

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>

#include <limits>
#include <algorithm>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<typename TBase>
                class sequence_length_forcing : public TBase {
                    using base_impl_type = TBase;

                public:
                    using value_type = typename base_impl_type::value_type;
                    using element_type = typename base_impl_type::element_type;

                    sequence_length_forcing() = default;

                    explicit sequence_length_forcing(const value_type &val) : base_impl_type(val) {
                    }

                    explicit sequence_length_forcing(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    sequence_length_forcing(const sequence_length_forcing &) = default;

                    sequence_length_forcing(sequence_length_forcing &&) = default;

                    sequence_length_forcing &operator=(const sequence_length_forcing &) = default;

                    sequence_length_forcing &operator=(sequence_length_forcing &&) = default;

                    void force_read_length(std::size_t val) {
                        MARSHALLING_ASSERT(val != Cleared);
                        forced_ = val;
                    }

                    void clear_read_length_forcing() {
                        forced_ = Cleared;
                    }

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t len) {
                        if (forced_ == Cleared) {
                            return base_impl_type::read(iter, len);
                        }

                        if (len < forced_) {
                            return status_type::not_enough_data;
                        }

                        return base_impl_type::read(iter, forced_);
                    }

                    template<typename TIter>
                    status_type read_n(std::size_t count, TIter &iter, std::size_t &len) {
                        if (forced_ == Cleared) {
                            return base_impl_type::read(iter, len);
                        }

                        if (len < forced_) {
                            return status_type::not_enough_data;
                        }

                        return base_impl_type::read_n(count, iter, forced_);
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) = delete;

                    template<typename TIter>
                    void read_no_status_n(std::size_t count, TIter &iter) = delete;

                private:
                    static const std::size_t Cleared = std::numeric_limits<std::size_t>::max();
                    std::size_t forced_ = Cleared;
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_SEQUENCE_LENGTH_FORCING_HPP
