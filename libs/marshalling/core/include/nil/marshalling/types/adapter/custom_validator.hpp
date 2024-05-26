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

#ifndef MARSHALLING_CUSTOM_VALIDATOR_HPP
#define MARSHALLING_CUSTOM_VALIDATOR_HPP

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<typename TValidator, typename TBase>
                class custom_validator : public TBase {
                    using base_impl_type = TBase;
                    using validator_type = TValidator;

                public:
                    using value_type = typename base_impl_type::value_type;

                    custom_validator() = default;

                    explicit custom_validator(const value_type &val) : base_impl_type(val) {
                    }

                    explicit custom_validator(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    custom_validator(const custom_validator &) = default;

                    custom_validator(custom_validator &&) = default;

                    custom_validator &operator=(const custom_validator &) = default;

                    custom_validator &operator=(custom_validator &&) = default;

                    bool valid() const {
                        return base_impl_type::valid() && (validator_type()(*this));
                    }
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_CUSTOM_VALIDATOR_HPP
