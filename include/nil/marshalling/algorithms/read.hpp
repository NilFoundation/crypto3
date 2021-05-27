//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef MARSHALLING_ALGORITHMS_READ_HPP
#define MARSHALLING_ALGORITHMS_READ_HPP

namespace nil {
    namespace marshalling {
        template<typename TypeToProcess, typename InputIterator>
        TypeToProcess read(InputIterator &first, InputIterator &last,
                                   status_type expectedStatus
                                   = status_type::success) {

            return read<TypeToProcess>(first, std::distance(first, last));
        }

        template<typename TypeToProcess, typename InputIterator>
        TypeToProcess read(InputIterator &first, std::size_t buf_len,
                                   status_type expectedStatus
                                   = status_type::success) {

            TypeToProcess field;

            BOOST_CHECK(field.read(iter, buf_len) == expectedStatus);

            return field;
        }
    }            // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_ALGORITHMS_READ_HPP
