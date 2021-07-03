//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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
// @file Functions to profile implementations of Benes and AS-Waksman routing networks.
//---------------------------------------------------------------------------//

#include <algorithm>

#include <nil/crypto3/algebra/common/default_types/ec_pp.hpp>
#include <nil/crypto3/algebra/common/profiling.hpp>

#include <nil/crypto3/zk/snark/components/routing/as_waksman_components.hpp>
#include <nil/crypto3/zk/snark/components/routing/benes_components.hpp>

using namespace nil::crypto3::zk::snark;

template<typename FieldType>
void get_as_waksman_size(const std::size_t n, const std::size_t l, std::size_t &num_constraints,
                         std::size_t &num_variables) {
    blueprint<FieldType> bp;

    std::vector<blueprint_variable_vector<FieldType>> randbits(n), outbits(n);
    for (std::size_t y = 0; y < n; ++y) {
        randbits[y].allocate(bp, l);
        outbits[y].allocate(bp, l);
    }

    as_waksman_routing_component<FieldType> r(bp, n, randbits, outbits);
    r.generate_r1cs_constraints();

    num_constraints = bp.num_constraints();
    num_variables = bp.num_variables();
}

template<typename FieldType>
void get_benes_size(const std::size_t n, const std::size_t l, std::size_t &num_constraints,
                    std::size_t &num_variables) {
    const std::size_t t = static_cast<std::size_t>(std::ceil(std::log2(n)));
    assert(n == 1ul << t);

    blueprint<FieldType> bp;

    std::vector<blueprint_variable_vector<FieldType>> randbits(1ul << t), outbits(1ul << t);
    for (std::size_t y = 0; y < 1ul << t; ++y) {
        randbits[y].allocate(bp, l);
        outbits[y].allocate(bp, l);
    }

    benes_routing_component<FieldType> r(bp, n, randbits, outbits, n);
    r.generate_r1cs_constraints();

    num_constraints = bp.num_constraints();
    num_variables = bp.num_variables();
}

template<typename FieldType>
void profile_routing_components(const std::size_t l) {
    for (std::size_t n = 2; n <= 65; ++n) {
        std::size_t as_waksman_constr, as_waksman_vars;
        get_as_waksman_size<FieldType>(n, l, as_waksman_constr, as_waksman_vars);

        const std::size_t rounded_n = 1ul << static_cast<std::size_t>(std::ceil(std::log2(n)));
        std::size_t benes_constr, benes_vars;
        get_benes_size<FieldType>(rounded_n, l, benes_constr, benes_vars);
    }
}

template<typename FieldType>
void profile_num_switches(const std::size_t l) {
    for (std::size_t n = 2; n <= 65; ++n) {
        std::size_t as_waksman_constr, as_waksman_vars;
        get_as_waksman_size<FieldType>(n, l, as_waksman_constr, as_waksman_vars);

        const std::size_t rounded_n = 1ul << static_cast<std::size_t>(std::ceil(std::log2(n)));
        std::size_t benes_constr, benes_vars;
        get_benes_size<FieldType>(rounded_n, l, benes_constr, benes_vars);

        const std::size_t as_waksman_switches = (as_waksman_constr - n * (2 + l)) / 2;
        const std::size_t benes_switches = (benes_constr - rounded_n * (2 + l)) / 2;
        // const std::size_t benes_expected = static_cast<std::size_t>(std::ceil(std::log2(rounded_n)))*rounded_n; //
        // switch-Benes has (-rounded_n/2) term
    }
}

int main() {

    profile_routing_components<typename algebra::default_ec_pp::scalar_field_type>(32 + 16 + 3 + 2);
    profile_num_switches<typename algebra::default_ec_pp::scalar_field_type>(1);
}
