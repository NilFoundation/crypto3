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

#ifndef MARSHALLING_TRANSPORT_VALUE_LAYER_ADAPTER_HPP
#define MARSHALLING_TRANSPORT_VALUE_LAYER_ADAPTER_HPP

#include <nil/marshalling/protocol/detail/transport_value_layer_options_parser.hpp>

namespace nil {
    namespace marshalling {

        namespace protocol {

            namespace detail {

                template<typename TBase>
                class transport_value_layer_pseudo_base : public TBase {
                    using base_impl_type = TBase;
                    using field_impl_type = typename base_impl_type::field_type;

                public:
                    field_impl_type &pseudo_field() {
                        return pseudoField_;
                    }

                    const field_impl_type &pseudo_field() const {
                        return pseudoField_;
                    }

                private:
                    field_impl_type pseudoField_;
                };

                template<bool THasPseudoValue>
                struct transport_value_layer_process_pseudo_base;

                template<>
                struct transport_value_layer_process_pseudo_base<true> {
                    template<typename TBase>
                    using type = transport_value_layer_pseudo_base<TBase>;
                };

                template<>
                struct transport_value_layer_process_pseudo_base<false> {
                    template<typename TBase>
                    using type = TBase;
                };

                template<typename TBase, typename TOpt>
                using transport_value_layer_pseudo_base_type =
                    typename transport_value_layer_process_pseudo_base<TOpt::has_pseudo_value>::template type<TBase>;

                template<typename TBase, typename... TOptions>
                class transport_value_layer_adapter {
                    using options_type = transport_value_layer_options_parser<TOptions...>;
                    using pseudo_base_type = transport_value_layer_pseudo_base_type<TBase, options_type>;

                public:
                    using type = pseudo_base_type;
                };

                template<typename TBase, typename... TOptions>
                using transport_value_layer_adapter_type =
                    typename transport_value_layer_adapter<TBase, TOptions...>::type;

            }    // namespace detail

        }    // namespace protocol

    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_TRANSPORT_VALUE_LAYER_ADAPTER_HPP
