//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_MULTIPRECISION_INFERENCE_TYPE_TRAITS_HPP
#define CRYPTO3_MARSHALLING_MULTIPRECISION_INFERENCE_TYPE_TRAITS_HPP

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase, typename IntegralContainer, typename... TOptions>
                class integral;
            }        // namespace types
        }        // namespace marshalling
    }        // namespace crypto3
    namespace marshalling {

        template<typename T, typename Enabled>
        class is_compatible;

        template<typename Backend,
                 nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
        class is_compatible <nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>, void> {
            using default_endianness = option::big_endian;
        public:
            template <typename TEndian = default_endianness, typename... TOptions>
            using type = typename nil::crypto3::marshalling::types::integral<field_type<TEndian>, 
                nil::crypto3::multiprecision::number<Backend, ExpressionTemplates>, TOptions...>;
            static const bool value = true;
            static const bool fixed_size = true;
        };

    }        // namespace marshalling
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_MULTIPRECISION_INFERENCE_TYPE_TRAITS_HPP