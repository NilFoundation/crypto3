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

#ifndef MARSHALLING_EXISTS_BETWEEN_VERSIONS_HPP
#define MARSHALLING_EXISTS_BETWEEN_VERSIONS_HPP

#include <cstdint>
#include <type_traits>
#include <limits>
#include <algorithm>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/types/optional_mode.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<std::uintmax_t TFrom, std::uintmax_t TUntil, typename TBase>
                class exists_between_versions : public TBase {
                    using base_impl_type = TBase;
                    static_assert(TFrom <= TUntil, "Invalid parameters");

                public:
                    using value_type = typename base_impl_type::value_type;
                    using version_type = typename base_impl_type::version_type;

                    exists_between_versions() = default;

                    explicit exists_between_versions(const value_type &val) : base_impl_type(val) {
                    }

                    explicit exists_between_versions(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    exists_between_versions(const exists_between_versions &) = default;

                    exists_between_versions(exists_between_versions &&) = default;

                    exists_between_versions &operator=(const exists_between_versions &) = default;

                    exists_between_versions &operator=(exists_between_versions &&) = default;

                    static constexpr bool is_version_dependent() {
                        return true;
                    }

                    bool set_version(version_type version) {
                        bool updated = base_impl_type::set_version(version);
                        typename types::optional_mode mode = 
                            types::optional_mode::missing;
                        if (above_from(version) && below_until(version)) {
                            mode = types::optional_mode::exists;
                        }

                        if (mode == base_impl_type::get_mode()) {
                            return updated;
                        }

                        base_impl_type::set_mode(mode);
                        return true;
                    }

                private:
                    struct always_true_tag { };
                    struct compare_tag { };

                    static bool above_from(version_type version) {
                        using tag = typename std::conditional<TFrom == 0, always_true_tag, compare_tag>::type;
                        return above_from(version, tag());
                    }

                    static constexpr bool above_from(version_type, always_true_tag) {
                        return true;
                    }

                    static bool above_from(version_type version, compare_tag) {
                        static const version_type min_version = static_cast<version_type>(
                            std::min(static_cast<decltype(TFrom)>(std::numeric_limits<version_type>::max()), TFrom));

                        return min_version <= version;
                    }

                    static bool below_until(version_type version) {
                        using tag = typename std::conditional<
                            static_cast<decltype(TUntil)>(std::numeric_limits<version_type>::max()) <= TUntil,
                            always_true_tag, compare_tag>::type;
                        return below_until(version, tag());
                    }

                    static constexpr bool below_until(version_type, always_true_tag) {
                        return true;
                    }

                    static bool below_until(version_type version, compare_tag) {
                        static const version_type max_version = static_cast<version_type>(
                            std::min(static_cast<decltype(TUntil)>(std::numeric_limits<version_type>::max()), TUntil));

                        return version <= max_version;
                    }
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_EXISTS_BETWEEN_VERSIONS_HPP
