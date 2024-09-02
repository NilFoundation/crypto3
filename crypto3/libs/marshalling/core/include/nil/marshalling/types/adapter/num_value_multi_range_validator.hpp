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

#ifndef MARSHALLING_NUM_VALUE_MULTI_RANGE_VALIDATOR_HPP
#define MARSHALLING_NUM_VALUE_MULTI_RANGE_VALIDATOR_HPP

#include <nil/detail/type_traits.hpp>

#include <nil/marshalling/processing/tuple.hpp>

namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<typename TRanges, typename TBase>
                class num_value_multi_range_validator : public TBase {
                    using base_impl_type = TBase;

                    static_assert(nil::detail::is_tuple<TRanges>::value, "TRanges must be a tuple");

                public:
                    using value_type = typename base_impl_type::value_type;

                    static_assert(std::is_integral<value_type>::value || std::is_enum<value_type>::value
                                      || std::is_floating_point<value_type>::value,
                                  "Only numeric fields are supported for multi range validation.");

                    num_value_multi_range_validator() = default;

                    explicit num_value_multi_range_validator(const value_type &val) : base_impl_type(val) {
                    }

                    explicit num_value_multi_range_validator(value_type &&val) : base_impl_type(std::move(val)) {
                    }

                    num_value_multi_range_validator(const num_value_multi_range_validator &) = default;

                    num_value_multi_range_validator(num_value_multi_range_validator &&) = default;

                    num_value_multi_range_validator &operator=(const num_value_multi_range_validator &) = default;

                    num_value_multi_range_validator &operator=(num_value_multi_range_validator &&) = default;

                    bool valid() const {
                        return base_impl_type::valid()
                               && processing::tuple_type_accumulate<TRanges>(
                                   false, Validator(base_impl_type::value()));
                    }

                private:
                    class Validator {
                    public:
                        Validator(value_type val) : m_val(val) {
                        }

                        template<typename TRange>
                        bool operator()(bool val) const {
                            static_cast<void>(val);
                            static_assert(nil::detail::is_tuple<TRange>::value,
                                          "TRange must be a tuple");
                            static_assert(std::tuple_size<TRange>::value == 2, "Tuple with 2 elements is expected");
                            using MinVal = typename std::tuple_element<0, TRange>::type;
                            using MaxVal = typename std::tuple_element<1, TRange>::type;
                            static_assert(MinVal::value <= MaxVal::value, "Invalid range");
                            return val
                                   || ((static_cast<value_type>(MinVal::value) <= m_val)
                                       && (m_val <= static_cast<value_type>(MaxVal::value)));
                        }

                    private:
                        value_type m_val;
                    };
                };

            }    // namespace adapter
        }        // namespace types
    }            // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_NUM_VALUE_MULTI_RANGE_VALIDATOR_HPP
