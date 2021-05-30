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

#ifndef MARSHALLING_DEFAULT_VALUE_INITIALISER_HPP
#define MARSHALLING_DEFAULT_VALUE_INITIALISER_HPP

#include <nil/marshalling/status_type.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<typename TInitialiser, typename TBase>
                class default_value_initialiser : public TBase {
                    using base_impl_type = TBase;
                    using initialiser_type = TInitialiser;

                public:
                    using value_type = typename base_impl_type::value_type;

                    default_value_initialiser() {
                        initialiser_type()(*this);
                    }

                    explicit default_value_initialiser(const value_type &val) : base_impl_type(val) {
                    }

                    explicit default_value_initialiser(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    default_value_initialiser(const default_value_initialiser &) = default;

                    default_value_initialiser(default_value_initialiser &&) = default;

                    default_value_initialiser &operator=(const default_value_initialiser &) = default;

                    default_value_initialiser &operator=(default_value_initialiser &&) = default;
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_DEFAULT_VALUE_INITIALISER_HPP
