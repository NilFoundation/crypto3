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

#ifndef MARSHALLING_BASIC_OPTIONAL_HPP
#define MARSHALLING_BASIC_OPTIONAL_HPP

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/types/optional_mode.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace detail {

                template<typename TField>
                class basic_optional : public nil::marshalling::field_type<
                                     nil::marshalling::option::endian<typename TField::endian_type>,
                                     nil::marshalling::option::version_type<typename TField::version_type>> {
                    using base_impl_type = nil::marshalling::field_type<
                        nil::marshalling::option::endian<typename TField::endian_type>,
                        nil::marshalling::option::version_type<typename TField::version_type>>;

                public:
                    using field_type = TField;
                    using value_type = TField;
                    using mode_type = types::optional_mode;
                    using version_type = typename base_impl_type::version_type;

                    basic_optional() = default;

                    explicit basic_optional(const field_type &fieldSrc, mode_type mode = mode_type::tentative) :
                        field_(fieldSrc), mode_(mode) {
                    }

                    explicit basic_optional(field_type &&fieldSrc, mode_type mode = mode_type::tentative) :
                        field_(std::move(fieldSrc)), mode_(mode) {
                    }

                    basic_optional(const basic_optional &) = default;

                    basic_optional(basic_optional &&) = default;

                    ~basic_optional() noexcept = default;

                    basic_optional &operator=(const basic_optional &) = default;

                    basic_optional &operator=(basic_optional &&) = default;

                    field_type &field() {
                        return field_;
                    }

                    const field_type &field() const {
                        return field_;
                    }

                    value_type &value() {
                        return field();
                    }

                    const value_type &value() const {
                        return field();
                    }

                    mode_type get_mode() const {
                        return mode_;
                    }

                    void set_mode(mode_type val) {
                        MARSHALLING_ASSERT(val < mode_type::modes_amount);
                        mode_ = val;
                    }

                    std::size_t length() const {
                        if (mode_ != mode_type::exists) {
                            return 0U;
                        }

                        return field_.length();
                    }

                    static constexpr std::size_t min_length() {
                        return 0U;
                    }

                    static constexpr std::size_t max_length() {
                        return field_type::max_length();
                    }

                    bool valid() const {
                        if (mode_ == mode_type::missing) {
                            return true;
                        }

                        return field_.valid();
                    }

                    bool refresh() {
                        if (mode_ != mode_type::exists) {
                            return false;
                        }
                        return field_.refresh();
                    }

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t len) {
                        if (mode_ == mode_type::missing) {
                            return status_type::success;
                        }

                        if ((mode_ == mode_type::tentative) && (0U == len)) {
                            mode_ = mode_type::missing;
                            return status_type::success;
                        }

                        status_type es = field_.read(iter, len);
                        if (es == status_type::success) {
                            mode_ = mode_type::exists;
                        }
                        return es;
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) {
                        if (mode_ != mode_type::exists) {
                            mode_ = mode_type::missing;
                            return;
                        }

                        mode_ = mode_type::exists;
                        field_.read_no_status(iter);
                    }

                    template<typename TIter>
                    status_type write(TIter &iter, std::size_t len) const {
                        if (mode_ == mode_type::missing) {
                            return status_type::success;
                        }

                        if ((mode_ == mode_type::tentative) && (0U == len)) {
                            return status_type::success;
                        }

                        return field_.write(iter, len);
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        if (mode_ != mode_type::exists) {
                            return;
                        }

                        field_.write_no_status(iter);
                    }

                    static constexpr bool is_version_dependent() {
                        return field_type::is_version_dependent();
                    }

                    bool set_version(version_type version) {
                        return field_.set_version(static_cast<typename field_type::version_type>(version));
                    }

                private:
                    field_type field_;
                    mode_type mode_ = mode_type::tentative;
                };

            }    // namespace detail
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_BASIC_OPTIONAL_HPP
