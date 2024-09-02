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

#ifndef MARSHALLING_CUSTOM_VALUE_READER_HPP
#define MARSHALLING_CUSTOM_VALUE_READER_HPP

#include <nil/marshalling/status_type.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<typename T, typename TBase>
                class custom_value_reader : public TBase {
                    using base_impl_type = TBase;

                public:
                    using value_type = typename base_impl_type::value_type;

                    custom_value_reader() = default;

                    explicit custom_value_reader(const value_type &val) : base_impl_type(val) {
                    }

                    explicit custom_value_reader(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    custom_value_reader(const custom_value_reader &) = default;

                    custom_value_reader(custom_value_reader &&) = default;

                    custom_value_reader &operator=(const custom_value_reader &) = default;

                    custom_value_reader &operator=(custom_value_reader &&) = default;

                    template<typename TIter>
                    status_type read(TIter &iter, std::size_t size) {
                        return T()(static_cast<base_impl_type &>(*this), iter, size);
                    }

                    template<std::size_t TFromIdx, typename TIter>
                    status_type read_from(TIter &iter, std::size_t size) = delete;

                    template<std::size_t TUntilIdx, typename TIter>
                    status_type read_until(TIter &iter, std::size_t size) = delete;

                    template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
                    status_type read_from_until(TIter &iter, std::size_t size) = delete;

                    template<typename TIter>
                    void read_no_status(TIter &iter) = delete;

                    template<std::size_t TFromIdx, typename TIter>
                    void read_from_no_status(TIter &iter) = delete;

                    template<std::size_t TUntilIdx, typename TIter>
                    void read_until_no_status(TIter &iter) = delete;

                    template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TIter>
                    void read_from_until_no_status(TIter &iter) = delete;
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_CUSTOM_VALUE_READER_HPP
