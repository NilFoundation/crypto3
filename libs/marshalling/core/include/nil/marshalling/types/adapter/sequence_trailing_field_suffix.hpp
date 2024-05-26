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

#ifndef MARSHALLING_SEQUENCE_TRAILING_FIELD_SUFFIX_HPP
#define MARSHALLING_SEQUENCE_TRAILING_FIELD_SUFFIX_HPP

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<typename TTrailField, typename TBase>
                class sequence_trailing_field_suffix : public TBase {
                    using base_impl_type = TBase;
                    using trail_field_type = TTrailField;

                    static_assert(!trail_field_type::is_version_dependent(),
                                  "Suffix fields must not be version dependent");

                public:
                    using value_type = typename base_impl_type::value_type;
                    using element_type = typename base_impl_type::element_type;

                    sequence_trailing_field_suffix() = default;

                    explicit sequence_trailing_field_suffix(const value_type &val) : base_impl_type(val) {
                    }

                    explicit sequence_trailing_field_suffix(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    sequence_trailing_field_suffix(const sequence_trailing_field_suffix &) = default;

                    sequence_trailing_field_suffix(sequence_trailing_field_suffix &&) = default;

                    sequence_trailing_field_suffix &operator=(const sequence_trailing_field_suffix &) = default;

                    sequence_trailing_field_suffix &operator=(sequence_trailing_field_suffix &&) = default;

                    constexpr std::size_t length() const {
                        return trailField_.length() + base_impl_type::length();
                    }

                    static constexpr std::size_t min_length() {
                        return trail_field_type::min_length() + base_impl_type::min_length();
                    }

                    static constexpr std::size_t max_length() {
                        return trail_field_type::max_length() + base_impl_type::max_length();
                    }

                    bool valid() const {
                        return trailField_.valid() && base_impl_type::valid();
                    }

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t len) {
                        status_type es = base_impl_type::read(iter, len - trail_field_type::min_length());
                        if (es != status_type::success) {
                            return es;
                        }

                        return trailField_.read(iter, len - base_impl_type::length());
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) = delete;

                    template<typename TIter>
                    status_type write(TIter &iter, std::size_t len) const {
                        auto trailLen = trailField_.length();
                        status_type es = base_impl_type::write(iter, len - trailLen);
                        if (es != status_type::success) {
                            return es;
                        }

                        return trailField_.write(iter, trailLen);
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        base_impl_type::write_no_status(iter);
                        trailField_.write_no_status(iter);
                    }

                private:
                    trail_field_type trailField_;
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_SEQUENCE_TRAILING_FIELD_SUFFIX_HPP
