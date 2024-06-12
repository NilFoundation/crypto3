//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#include <vector>
#include <sltbench/Bench.h>

#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>
#include <nil/crypto3/algebra/fields/pallas/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_k1/base_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_k1/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_r1/base_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_r1/scalar_field.hpp>
#include <nil/crypto3/algebra/random_element.hpp>


#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <boost/multiprecision/cpp_int.hpp>

using namespace nil::crypto3::algebra;
using field_type = typename curves::bls12_381::scalar_field_type;

std::vector<typename field_type::value_type> generate_samples(size_t const& samples_count)
{
    std::vector<typename field_type::value_type> result;
    for (int i = 0; i < samples_count; ++i) {
        result.push_back(random_element<field_type>());
    }
    return result;
}

void benchmark_field(std::vector<typename field_type::value_type>& samples, size_t const& samples_count)
{
    typename field_type::value_type result = samples[0];

    for(auto const& s: samples) {
        result += s;
    }
}

static const std::vector<size_t> SAMPLE_VARIANTS = {10, 100};

SLTBENCH_FUNCTION_WITH_FIXTURE_BUILDER_AND_ARGS(
        benchmark_field,
        generate_samples,
        SAMPLE_VARIANTS);

SLTBENCH_MAIN();
