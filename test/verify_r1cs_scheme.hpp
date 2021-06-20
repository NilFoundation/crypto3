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

#ifndef CRYPTO3_ZK_BLUEPRINT_VERIFY_R1CS_SCHEME_COMPONENT_TEST_HPP
#define CRYPTO3_ZK_BLUEPRINT_VERIFY_R1CS_SCHEME_COMPONENT_TEST_HPP

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/zk/snark/algorithms/generate.hpp>
#include <nil/crypto3/zk/snark/algorithms/verify.hpp>
#include <nil/crypto3/zk/snark/algorithms/prove.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <nil/crypto3/zk/components/blueprint.hpp>

#include <nil/crypto3/algebra/curves/edwards.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

template<typename CurveType, 
         typename SchemeType = snark::r1cs_gg_ppzksnark<CurveType>>
bool verify_component(components::blueprint<typename CurveType::scalar_field_type> bp){

    if (bp.num_variables() == 0x00){
        std::cout << "Empty blueprint!" << std::endl;
        return false;
    }

    using field_type = typename CurveType::scalar_field_type;
    using scheme_type = SchemeType;

    const snark::r1cs_constraint_system<field_type> constraint_system = bp.get_constraint_system();

    auto begin = std::chrono::high_resolution_clock::now();
    const typename scheme_type::keypair_type keypair = snark::generate<scheme_type>(constraint_system);
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "Key generation finished, time: " << elapsed.count() * 1e-9 << std::endl;

    begin = std::chrono::high_resolution_clock::now();
    const typename scheme_type::proof_type proof = snark::prove<scheme_type>(keypair.first, bp.primary_input(), bp.auxiliary_input());
    end = std::chrono::high_resolution_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "Proving finished, time: " << elapsed.count() * 1e-9 << std::endl;

    begin = std::chrono::high_resolution_clock::now();
    bool verified = snark::verify<scheme_type>(keypair.second, bp.primary_input(), proof);
    end = std::chrono::high_resolution_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

    std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << std::endl;
    std::cout << "Verification finished, time: " << elapsed.count() * 1e-9 << std::endl;
    std::cout << "Verification status: " << verified << std::endl;

    return verified;
}

template<>
bool verify_component<curves::edwards<183>,
                      snark::r1cs_gg_ppzksnark<curves::edwards<183>>>(components::blueprint<typename curves::edwards<183>::scalar_field_type> bp){
    std::cout << "Warning! r1cs_gg_ppzksnark for Edwards-183 is not implemented yet" << std::endl;

    return false;
}

#endif    // CRYPTO3_ZK_BLUEPRINT_VERIFY_R1CS_SCHEME_COMPONENT_TEST_HPP
