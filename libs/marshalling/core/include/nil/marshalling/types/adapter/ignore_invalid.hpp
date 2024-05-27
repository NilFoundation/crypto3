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

#ifndef MARSHALLING_IGNORE_INVALID_HPP
#define MARSHALLING_IGNORE_INVALID_HPP

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/status_type.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<typename TBase>
                class ignore_invalid : public TBase {
                    using base_impl_type = TBase;

                public:
                    using value_type = typename base_impl_type::value_type;

                    ignore_invalid() = default;

                    explicit ignore_invalid(const value_type &val) : base_impl_type(val) {
                    }

                    explicit ignore_invalid(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    ignore_invalid(const ignore_invalid &) = default;

                    ignore_invalid(ignore_invalid &&) = default;

                    ignore_invalid &operator=(const ignore_invalid &) = default;

                    ignore_invalid &operator=(ignore_invalid &&) = default;

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t len) {
                        base_impl_type tmp;
                        status_type es = tmp.read(iter, len);
                        if (es != status_type::success) {
                            return es;
                        }

                        if (tmp.valid()) {
                            static_cast<base_impl_type &>(*this) = std::move(tmp);
                        }

                        return status_type::success;
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) {
                        base_impl_type tmp;
                        tmp.read_no_status(iter);

                        if (tmp.valid()) {
                            static_cast<base_impl_type &>(*this) = std::move(tmp);
                        }
                    }
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_IGNORE_INVALID_HPP
