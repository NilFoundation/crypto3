//---------------------------------------------------------------------------//
// Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#ifndef CRYPTO3_SCOPED_PROFILER_HPP
#define CRYPTO3_SCOPED_PROFILER_HPP

#include <chrono>
#include <string>
#include <iostream>
#include <iomanip>
#include <unordered_map>

namespace nil {
    namespace crypto3 {
        namespace bench {
            namespace detail {

// Measures execution time of a given function just once. Prints 
// the time when leaving the function in which this class was created.
class scoped_profiler
{
    public:
        inline scoped_profiler(std::string name) 
            : start(std::chrono::high_resolution_clock::now())
            , name(name) {
        }

        inline ~scoped_profiler() {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::high_resolution_clock::now() - start);
            std::cout << name << ": " << std::fixed << std::setprecision(3)
                << elapsed.count() << " ms" << std::endl;
        }

    private:
        std::chrono::time_point<std::chrono::high_resolution_clock> start;
        std::string name;
};

class call_stats {
    public:
        // Make this class singleton.
        static call_stats& get_stats() {
            static call_stats instance;
            return instance;
        }

        void add_stat(const std::string& name, uint64_t time_ms) {
            call_counts[name]++;
            call_miliseconds[name] += time_ms;
        }

    private:
        call_stats() {}
        ~call_stats() {
            for (const auto& [name, count]: call_counts) {
                uint64_t miliseconds = call_miliseconds[name] / 1000000;
                std::cout << name << ": " << count << " calls "
                    << miliseconds / 1000 << " sec " 
                    << miliseconds % 1000 << " ms" << std::endl;
            }
        }

        std::unordered_map<std::string, uint64_t> call_counts;
        std::unordered_map<std::string, uint64_t> call_miliseconds;
};

// Measures the total execution time of the functions it's placed in, and the number of calls.
// Prints the time and number of calls on program exit.
class scoped_aggregate_profiler
{
    public:
        inline scoped_aggregate_profiler(std::string name) 
            : start(std::chrono::high_resolution_clock::now())
            , name(name) {
        }

        inline ~scoped_aggregate_profiler() {
            auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - start);
            call_stats::get_stats().add_stat(name, elapsed.count());
        }

    private:
        std::chrono::time_point<std::chrono::high_resolution_clock> start;
        std::string name;
};

            }    // namespace detail
        }        // namespace bench
    }            // namespace crypto3
}    // namespace nil

#ifdef PROFILING_ENABLED
    #define PROFILE_SCOPE(name) \
        nil::crypto3::bench::detail::scoped_profiler profiler(name);
#else
    #define PROFILE_SCOPE(name) 
#endif

#ifdef PROFILING_ENABLED
    #define PROFILE_FUNCTION_CALLS() \
        nil::crypto3::bench::detail::scoped_aggregate_profiler profiler(__PRETTY_FUNCTION__ );
#else
    #define PROFILE_FUNCTION_CALLS() 
#endif

#endif    // CRYPTO3_SCOPED_PROFILER_HPP
