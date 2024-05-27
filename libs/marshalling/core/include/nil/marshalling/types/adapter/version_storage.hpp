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

#ifndef MARSHALLING_VERSION_STORAGE_HPP
#define MARSHALLING_VERSION_STORAGE_HPP

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<typename TBase>
                class version_storage : public TBase {
                    using base_impl_type = TBase;

                public:
                    using value_type = typename base_impl_type::value_type;
                    using version_type = typename base_impl_type::version_type;

                    version_storage() = default;

                    explicit version_storage(const value_type &val) : base_impl_type(val) {
                    }

                    explicit version_storage(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    version_storage(const version_storage &) = default;

                    version_storage(version_storage &&) = default;

                    version_storage &operator=(const version_storage &) = default;

                    version_storage &operator=(version_storage &&) = default;

                    static constexpr bool is_version_dependent() {
                        return true;
                    }

                    version_type get_version() const {
                        return m_version;
                    }

                    bool set_version(version_type val) {
                        bool updated = base_impl_type::set_version(val);
                        if (m_version != val) {
                            m_version = val;
                            return true;
                        }
                        return updated;
                    }

                private:
                    version_type m_version = static_cast<version_type>(0);
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_VERSION_STORAGE_HPP
