//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#define BOOST_TEST_MODULE basic_radix2_domain_test

#include <vector>
#include <cstdint>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>


#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/detail/basic_radix2_domain_aux.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::math;

typedef fields::bls12_fr<381> FieldType;

BOOST_AUTO_TEST_SUITE(basic_radix2_domain_test_suit)

BOOST_AUTO_TEST_CASE(basic_radix2_domain_benchmark, *boost::unit_test::disabled()) {
    using value_type = FieldType::value_type;
    const std::size_t fft_count = 5;
    const std::array<std::size_t, fft_count> fft_sizes = {1 << 16, 1 << 17, 1 << 18, 1 << 19, 1 << 20};
    std::array<std::vector<value_type>, fft_count> test_data;
    std::chrono::time_point<std::chrono::high_resolution_clock> gen_start(std::chrono::high_resolution_clock::now());
    for (std::size_t i = 0; i < fft_count; ++i) {
        test_data[i].resize(fft_sizes[i]);
        for (std::size_t j = 0; j < fft_sizes[i]; ++j) {
            test_data[i][j] = nil::crypto3::algebra::random_element<FieldType>();
        }
    }
    std::cout << "Generation: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - gen_start)
                 .count()
              << " ms" << std::endl;

    // manually calculate the power, saving all the intermediate powers
    std::chrono::time_point<std::chrono::high_resolution_clock> cache_start(std::chrono::high_resolution_clock::now());
    std::vector<std::shared_ptr<std::vector<value_type>>> omega_powers(fft_count);
    for (std::size_t i = 0; i < fft_count; i++) {
        omega_powers[i].reset(new std::vector<value_type>);
        omega_powers[i]->resize(fft_sizes[i]);
        (*omega_powers[i])[0] = unity_root<FieldType>(fft_sizes[i]);
        for (std::size_t j = 1; j < fft_sizes[i]; j++) {
            (*omega_powers[i])[j] = (*omega_powers[i])[j - 1] * (*omega_powers[i])[0];
        }
    }
    std::cout << "Cache: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::high_resolution_clock::now() - cache_start)
                 .count()
              << " ms" << std::endl;

    std::chrono::time_point<std::chrono::high_resolution_clock> start_fft(std::chrono::high_resolution_clock::now());
    for (std::size_t i = 0; i < fft_count; ++i) {
        nil::crypto3::math::detail::basic_radix2_fft<FieldType>(
            test_data[i],
            unity_root<FieldType>(fft_sizes[i])); //omega_powers[i]);
    }

    std::cout << "Uncached FFT: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::high_resolution_clock::now() - start_fft)
                 .count()
              << " ms" << std::endl;

    std::chrono::time_point<std::chrono::high_resolution_clock> start_cached(std::chrono::high_resolution_clock::now());
    for (std::size_t i = 0; i < fft_count; ++i) {
        nil::crypto3::math::detail::basic_radix2_fft<FieldType>(
            test_data[i],
            unity_root<FieldType>(fft_sizes[i]),
            omega_powers[i]);
    }
    std::cout << "Cached FFT: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::high_resolution_clock::now() - start_cached
                 ).count()
              << " ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(fft_vs_multiplication_benchmark) {
    using value_type = FieldType::value_type;
    const std::size_t fft_size = 1 << 16;
    std::vector<value_type> test_data(fft_size);
    std::chrono::time_point<std::chrono::high_resolution_clock> gen_start(std::chrono::high_resolution_clock::now());
    for (std::size_t i = 0; i < fft_size; ++i) {
        test_data[i] = nil::crypto3::algebra::random_element<FieldType>();
    }
    std::vector<value_type> duped_data(test_data);
    value_type random_mult = nil::crypto3::algebra::random_element<FieldType>();
    std::cout << "Generation: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::high_resolution_clock::now() - gen_start)
                 .count()
              << " ms" << std::endl;

    std::chrono::time_point<std::chrono::high_resolution_clock> start_fft(std::chrono::high_resolution_clock::now());
    nil::crypto3::math::detail::basic_radix2_fft<FieldType>(
        test_data,
        unity_root<FieldType>(fft_size));
    std::cout << "FFT: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::high_resolution_clock::now() - start_fft)
                 .count()
              << " ms" << std::endl;

    std::chrono::time_point<std::chrono::high_resolution_clock> start_mult(std::chrono::high_resolution_clock::now());

    for (std::size_t i = 0; i < fft_size; ++i) {
        duped_data[i] *= random_mult;
    }
    std::cout << "Multiplication: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::high_resolution_clock::now() - start_mult)
                 .count()
             << " ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
