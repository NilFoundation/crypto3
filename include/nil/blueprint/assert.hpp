//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_ASSERT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_ASSERT_HPP

#include <stdexcept>
#include <boost/format.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {
            template<typename T1, typename T2, typename T3>
            static void blueprint_assert(T1 line, T2 file, T3 expr){
                std::stringstream errMsg;
                errMsg << "Assertion " << expr << " failed on line " << line << " in file " << file;
                throw std::runtime_error(errMsg.str().c_str());
            }
        }    // namespace detail
    }    // namespace blueprint
}    // namespace nil

#define BLUEPRINT_RELEASE_ASSERT( expr ) \
    ( (expr) ? (void)0 : nil::blueprint::detail::blueprint_assert( __LINE__, __FILE__, #expr))

#ifdef BLUEPRINT_DEBUG_ENABLED
#define BLUEPRINT_ASSERT( expr ) \
    BLUEPRINT_RELEASE_ASSERT( expr )
#else
#define BLUEPRINT_ASSERT( expr ) ((void)0)
#endif

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_ASSERT_HPP
