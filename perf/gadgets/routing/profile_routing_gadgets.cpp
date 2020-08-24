//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Functions to profile implementations of Benes and AS-Waksman routing networks.
//---------------------------------------------------------------------------//

#include <algorithm>

#include <nil/algebra/common/default_types/ec_pp.hpp>
#include <nil/algebra/common/profiling.hpp>

#include <nil/crypto3/zk/snark/gadgets/routing/as_waksman_routing_gadget.hpp>
#include <nil/crypto3/zk/snark/gadgets/routing/benes_routing_gadget.hpp>

using namespace nil::crypto3::zk::snark;

template<typename FieldType>
void get_as_waksman_size(const std::size_t n, const std::size_t l, std::size_t &num_constraints, std::size_t &num_variables) {
    protoboard<FieldType> pb;

    std::vector<pb_variable_array<FieldType>> randbits(n), outbits(n);
    for (std::size_t y = 0; y < n; ++y) {
        randbits[y].allocate(pb, l);
        outbits[y].allocate(pb, l);
    }

    as_waksman_routing_gadget<FieldType> r(pb, n, randbits, outbits);
    r.generate_r1cs_constraints();

    num_constraints = pb.num_constraints();
    num_variables = pb.num_variables();
}

template<typename FieldType>
void get_benes_size(const std::size_t n, const std::size_t l, std::size_t &num_constraints, std::size_t &num_variables) {
    const std::size_t t = static_cast<std::size_t>(std::ceil(std::log2(n)));
    assert(n == 1ul << t);

    protoboard<FieldType> pb;

    std::vector<pb_variable_array<FieldType>> randbits(1ul << t), outbits(1ul << t);
    for (std::size_t y = 0; y < 1ul << t; ++y) {
        randbits[y].allocate(pb, l);
        outbits[y].allocate(pb, l);
    }

    benes_routing_gadget<FieldType> r(pb, n, randbits, outbits, n);
    r.generate_r1cs_constraints();

    num_constraints = pb.num_constraints();
    num_variables = pb.num_variables();
}

template<typename FieldType>
void profile_routing_gadgets(const std::size_t l) {
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
        // const std::size_t benes_expected = static_cast<std::size_t>(std::ceil(std::log2(rounded_n)))*rounded_n; // switch-Benes has (-rounded_n/2) term
    }
}

int main() {


    profile_routing_gadgets<typename algebra::default_ec_pp::scalar_field_type>(32 + 16 + 3 + 2);
    profile_num_switches<typename algebra::default_ec_pp::scalar_field_type>(1);
}
