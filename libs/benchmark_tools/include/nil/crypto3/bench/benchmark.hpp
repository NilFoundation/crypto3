//---------------------------------------------------------------------------//
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
//
// SPDX-License-Identifier: MIT
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


#ifndef CRYPTO3_BENCHMARK_HPP
#define CRYPTO3_BENCHMARK_HPP

#include <iomanip>
#include <vector>
#include <array>
#include <chrono>
#include <tuple>
#include <algorithm>
#include <iostream>
#include <cmath>

#include <unistd.h>

#include <nil/crypto3/algebra/random_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace bench {

/* Amount of elements that will not fit into L1D cache.
 * Goldilocks field is the smallest object to benchmark, 64 bits, 8 bytes,
 * so 8192 samples take 64kb, that is twice as large as L1D cache (32kb)
 * Largest object to benchmark is BLS12-381 Fp12, 2over3over2, 72 bytes each,
 * This will take 589kb
 * */
constexpr std::size_t SAMPLES_COUNT = 8192;

template<typename T>
std::vector<typename T::value_type> generate_samples()
{
    std::vector<typename T::value_type> samples;
    for(std::size_t i = 0; i < SAMPLES_COUNT; ++i) {
        samples.emplace_back(algebra::random_element<T>());
    }
    return samples;
}

template<typename... A>
std::tuple<std::vector<typename A::value_type>...> allocate_samples()
{
    return std::make_tuple(generate_samples<A>()...);
}


template<typename... A>
std::array<std::size_t, sizeof...(A)> calculate_strides()
{
    /* For each type of argument calculate stride used to traverse array of samples
     * Stride is twice larger than a cache line to ensure values for benchmarked
     * operation are not cached */
    return { (1 + sysconf(_SC_LEVEL1_DCACHE_LINESIZE)*2 / sizeof(typename A::value_type)) ... };
    // stride = 0 means the same element is used in all operations, maximum cache utilization
    // return {(0*sizeof(typename A::value_type)) ...};
}


template<typename... A, std::size_t... I>
auto make_slice_impl(
    std::tuple<std::vector<typename A::value_type>...>& samples,
    const std::array<std::size_t, sizeof...(A)>& strides,
    std::size_t i,
    std::index_sequence<I...>
) -> std::tuple<typename A::value_type&...>
{
    return std::tuple<typename A::value_type&...>(
        std::get<I>(samples)[i * strides[I] % SAMPLES_COUNT]...
    );
}


template<typename... A>
auto make_slice(
    std::tuple<std::vector<typename A::value_type>...>& samples,
    const std::array<std::size_t, sizeof...(A)>& strides,
    std::size_t i
) -> std::tuple<typename A::value_type&...>
{
    return make_slice_impl<A...>(
        samples, strides, i, std::index_sequence_for<A...>{}
    );
}


template<typename...A, typename F >
void run_benchmark(std::string const& name, F && func)
{
    using duration = std::chrono::duration<double, std::nano>;

    auto samples = allocate_samples<A...>();
    auto strides = calculate_strides<A...>();

    auto run_batch = [&] (std::size_t batch_size) {
        for(std::size_t i = 0; i < batch_size; ++i) {
            auto args = make_slice<A...>(samples, strides, i);
            /* volatile hints to compiler that it has important side effects
             * and call should not be optimized out */
            volatile auto r = std::apply(func, args);
            (void) r;
        }
    };

    auto run_at_least = [&] (duration const& dur) {
        std::size_t WARMUP_BATCH_SIZE = 1000, total_runs = 0;
        auto start = std::chrono::high_resolution_clock::now();
        while (std::chrono::high_resolution_clock::now() - start < dur) {
            run_batch(WARMUP_BATCH_SIZE);
            total_runs += WARMUP_BATCH_SIZE;
        }
        return total_runs;
    };

    std::size_t MEASUREMENTS = 100;
    duration WARMUP_DURATION = std::chrono::seconds(3);

    std::size_t BATCH_SIZE = 1 + run_at_least(WARMUP_DURATION)/MEASUREMENTS/10;

    std::vector<double> durations(MEASUREMENTS);
    for(std::size_t m = 0; m < MEASUREMENTS; ++m) {
        auto start = std::chrono::high_resolution_clock::now();
        run_batch(BATCH_SIZE);
        auto finish = std::chrono::high_resolution_clock::now();
        durations[m] = (finish - start).count()*1.0 / BATCH_SIZE;
    }

    std::sort(durations.begin(), durations.end());

    // discard top 20% outliers
    durations.resize(MEASUREMENTS * 0.8);

    double median = durations[durations.size()/2];
    double mean = 0, stddiv = 0;

    for(auto &dur : durations) {
        mean += dur;
        stddiv += dur*dur;
    }

    mean /= durations.size();
    // stddiv^2 = E x^2 -  (E x)^2
    stddiv = sqrt(stddiv / durations.size() - mean * mean);

    // https://support.numxl.com/hc/en-us/articles/115001223503-MdAPE-Median-Absolute-Percentage-Error
    for(auto &dur : durations) {
        dur = (dur - median) / dur;
        if ( dur < 0 ) {
            dur = -dur;
        }
    }
    std::sort(durations.begin(), durations.end());
    double MdAPE = durations[durations.size()/2];

    std::cout << std::fixed << std::setprecision(3);
    std::cout << name <<
        " mean: " << mean << "ns err: " << (MdAPE*100) <<
        "% median: " << median << "ns stddiv: " << stddiv <<
        std::endl;
}

        }
    }
}

#endif /* CRYPTO3_BENCHMARK_HPP */
