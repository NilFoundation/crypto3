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

#ifndef MARSHALLING_PROCESSING_ALIGNED_UNION_HPP
#define MARSHALLING_PROCESSING_ALIGNED_UNION_HPP

#include <type_traits>

namespace nil {
    namespace marshalling {
        namespace processing {

            /// @cond SKIP_DOC
            template<typename TType, typename... TTypes>
            class aligned_union {
                using other_storage_type = typename aligned_union<TTypes...>::type;
                static const std::size_t other_size = sizeof(other_storage_type);
                static const std::size_t other_alignment = std::alignment_of<other_storage_type>::value;
                using first_storage_type = typename aligned_union<TType>::type;
                static const std::size_t first_size = sizeof(first_storage_type);
                static const std::size_t first_alignment = std::alignment_of<first_storage_type>::value;
                static const std::size_t max_size = first_size > other_size ? first_size : other_size;
                static const std::size_t max_alignment
                    = first_alignment > other_alignment ? first_alignment : other_alignment;

            public:
                /// Type that has proper size and proper alignment to keep any of the
                /// specified types
                using type = typename std::aligned_storage<max_size, max_alignment>::type;
            };

            template<typename TType>
            class aligned_union<TType> {
            public:
                using type = typename std::aligned_storage<sizeof(TType), std::alignment_of<TType>::value>::type;
            };

            /// @endcond

        }    // namespace processing
    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_PROCESSING_ALIGNED_UNION_HPP
