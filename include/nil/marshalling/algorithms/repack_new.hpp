//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
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

#ifndef MARSHALLING_REPACK_NEW_HPP
#define MARSHALLING_REPACK_NEW_HPP

#include <nil/marshalling/algorithms/unpack_new.hpp>
#include <nil/marshalling/algorithms/pack_new.hpp>

namespace nil {
    namespace marshalling {
        template<typename TInputEndian, typename TOutputEndian, typename SinglePassRange>
            range_pack_impl<TOutputEndian, std::vector<std::uint8_t>::const_iterator> repack(const SinglePassRange &val, status_type &status) {

            status_type result_status;
            std::vector<std::uint8_t> buffer = unpack<TInputEndian>(val, result_status);

            return range_pack_impl<TOutputEndian, std::vector<std::uint8_t>::const_iterator>(buffer, status);
        }
    }    // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_REPACK_NEW_HPP
