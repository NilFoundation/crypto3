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

#ifndef MARSHALLING_REPACK_HPP
#define MARSHALLING_REPACK_HPP

#include <nil/marshalling/algorithms/unpack.hpp>
#include <nil/marshalling/algorithms/pack.hpp>

namespace nil {
    namespace marshalling {

        /*!
         * @defgroup marshalling Marshalling
         *
         * @brief Marshalling between one type, different endianness
         *
         * @defgroup marshalling_algorithms Algorithms
         * @ingroup marshalling
         * @brief Algorithms are meant to provide marshalling interface similar to STL algorithms' one.
         */

        /*!
         * @brief Repack converting between arbitrary types, arbitrary endiannesses. 
         * In case, if one type (inpur nor output) is byte container and there is no 
         * need to change the endianness, it's better to use pack or unpack algorithm 
         * respectively. The repack algorithm would work less effective in that case.
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TInputEndian
         * @tparam TOutputEndian
         * @tparam TInput
         * @tparam TOutput
         *
         * @param val
         * @param status
         *
         * @return TOutput
         */
        template<typename TInputEndian, typename TOutputEndian, typename TInput, 
                typename TOutput>
        TOutput repack(TInput val, status_type &status) {
            status_type result_status;

            std::vector<std::uint8_t> buffer = unpack<TInputEndian,
            std::vector<std::uint8_t>>(val, result_status);

            TOutput result = pack<TOutputEndian, TOutput>(buffer, status);

            status = status|result_status;
            return result;
        }

    }    // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_REPACK_HPP
