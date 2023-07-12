//---------------------------------------------------------------------------//
// Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
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

#ifndef CRYPTO3_PLACEHOLDER_SCOPED_PROFILER_HPP
#define CRYPTO3_PLACEHOLDER_SCOPED_PROFILER_HPP

#include <chrono>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    class placeholder_scoped_profiler
                    {
                        public:
                            inline placeholder_scoped_profiler(std::string name) 
                                : start(std::chrono::high_resolution_clock::now())
                                , name(name) {
                            }
                    
                            inline ~placeholder_scoped_profiler() {
                                auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                std::chrono::high_resolution_clock::now() - start);
                                std::cout << name << ": " << std::fixed << std::setprecision(3)
                                    << elapsed.count() * 1e-6 << "ms" << std::endl;
                            }
                    
                        private:
                            std::chrono::time_point<std::chrono::high_resolution_clock> start;
                            std::string name;
                    };
                }    // namespace detail
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
    #define PROFILE_PLACEHOLDER_SCOPE(name) \
        nil::crypto3::zk::snark::detail::placeholder_scoped_profiler profiler(name);
#else
    #define PROFILE_PLACEHOLDER_SCOPE(name) 
#endif

#endif    // CRYPTO3_PLACEHOLDER_SCOPED_PROFILER_HPP
