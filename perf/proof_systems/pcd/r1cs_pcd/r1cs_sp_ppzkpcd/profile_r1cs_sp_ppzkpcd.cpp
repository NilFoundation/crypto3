//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <nil/crypto3/zk/snark/default_types/r1cs_ppzkpcd_pp.hpp>
#include <nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/examples/run_r1cs_sp_ppzkpcd.hpp>
#include <nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/r1cs_sp_ppzkpcd.hpp>

using namespace nil::crypto3::zk::snark;

template<typename PCD_ppT>
void profile_tally(const std::size_t arity, const std::size_t max_layer) {
    const std::size_t wordsize = 32;
    const bool test_serialization = true;
    const bool bit = run_r1cs_sp_ppzkpcd_tally_example<PCD_ppT>(wordsize, arity, max_layer, test_serialization);
    assert(bit);
}

int main(void) {
    typedef default_r1cs_ppzkpcd_pp PCD_pp;

    algebra::start_profiling();
    PCD_pp::init_public_params();

    const std::size_t arity = 2;
    const std::size_t max_layer = 2;

    profile_tally<PCD_pp>(arity, max_layer);
}
