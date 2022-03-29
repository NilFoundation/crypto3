//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_basic_verifier_test

#include <assert.h>
#include <boost/test/unit_test.hpp>
#include <fstream>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/proof.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>

#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/unified_addition.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>
#include <nil/crypto3/marshalling/zk/types/redshift/proof.hpp>

#include "test_plonk_component.hpp"
#include "proof_data.hpp"

using namespace nil::crypto3;

template<typename TIter>
void print_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end) {
    os << std::hex;
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::setfill('0') << std::setw(2) << std::right << int(*it);
    }
    os << std::endl << std::dec;
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_demo_verifier_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_demo_verifier_test) {
    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    constexpr std::size_t WitnessColumns = 11;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;

    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

    nil::crypto3::zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof();

    using component_type = zk::components::curve_element_unified_addition<ArithmetizationType, curve_type, 0, 1, 2, 3,
                                                                          4, 5, 6, 7, 8, 9, 10>;

    typename component_type::private_params_type private_params = {kimchi_proof.commitments.w_comm[0].unshifted[0],
                                                                   kimchi_proof.commitments.w_comm[1].unshifted[0]};
    typename component_type::public_params_type public_params = {};

    auto expected_result = (private_params.P + private_params.Q).to_affine();
    std::cout << "exprected result: (" << expected_result.X.data << ", " << expected_result.Y.data << ")" << std::endl;

    zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> desc;

    zk::blueprint<ArithmetizationType> bp(desc);
    zk::blueprint_private_assignment_table<ArithmetizationType> private_assignment(desc);
    zk::blueprint_public_assignment_table<ArithmetizationType> public_assignment(desc);

    std::size_t start_row = component_type::allocate_rows(bp);
    component_type::generate_gates(bp, public_assignment, public_params, start_row);
    component_type::generate_copy_constraints(bp, public_assignment, public_params, start_row);
    component_type::generate_assignments(private_assignment, public_assignment, public_params, private_params,
                                         start_row);

    std::cout << "actual result: (" << private_assignment.witness(4)[0].data << ", "
              << private_assignment.witness(5)[0].data << ")" << std::endl;

    private_assignment.padding();
    public_assignment.padding();

    zk::snark::plonk_assignment_table<BlueprintFieldType, ArithmetizationParams> assignments(private_assignment,
                                                                                             public_assignment);

    using params = zk::snark::redshift_params<BlueprintFieldType, ArithmetizationParams, hash_type, hash_type, Lambda>;
    using types = zk::snark::detail::redshift_policy<BlueprintFieldType, params>;

    using fri_type = typename zk::commitments::fri<BlueprintFieldType, typename params::merkle_hash_type,
                                                   typename params::transcript_hash_type, 2>;

    std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

    typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log);

    std::size_t permutation_size = desc.witness_columns + desc.public_input_columns + desc.constant_columns;

    typename types::preprocessed_public_data_type public_preprocessed_data =
        zk::snark::redshift_public_preprocessor<BlueprintFieldType, params>::process(bp, public_assignment, desc,
                                                                                     fri_params, permutation_size);
    typename types::preprocessed_private_data_type private_preprocessed_data =
        zk::snark::redshift_private_preprocessor<BlueprintFieldType, params>::process(bp, private_assignment, desc);

    auto redshift_proof = zk::snark::redshift_prover<BlueprintFieldType, params>::process(
        public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using proof_marshalling_type =
        nil::crypto3::marshalling::types::redshift_proof<TTypeBase, decltype(redshift_proof)>;
    auto filled_redshift_proof =
        nil::crypto3::marshalling::types::fill_redshift_proof<decltype(redshift_proof), Endianness>(redshift_proof);
    std::vector<std::uint8_t> cv;
    cv.resize(filled_redshift_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_redshift_proof.write(write_iter, cv.size());
    std::cout << "proof (" << cv.size() << " bytes) = " << std::endl;
    std::ofstream proof_file;
    proof_file.open("redshift.txt");
    print_byteblob(proof_file, cv.cbegin(), cv.cend());

    std::cout << "modulus = " << BlueprintFieldType::modulus << std::endl;
    std::cout << "fri_params.r = " << fri_params.r << std::endl;
    std::cout << "fri_params.max_degree = " << fri_params.max_degree << std::endl;
    std::cout << "fri_params.q = ";
    for (const auto &coeff : fri_params.q) {
        std::cout << coeff.data << ", ";
    }
    std::cout << std::endl;
    std::cout << "fri_params.D_omegas = ";
    for (const auto &dom : fri_params.D) {
        std::cout << static_cast<nil::crypto3::math::basic_radix2_domain<BlueprintFieldType> &>(*dom).omega.data
                  << ", ";
    }
    std::cout << std::endl;
    std::cout << "lpc_params.lambda = " << params::commitment_params_type::lambda << std::endl;
    std::cout << "lpc_params.m = " << params::commitment_params_type::m << std::endl;
    std::cout << "lpc_params.r = " << params::commitment_params_type::r << std::endl;
    std::cout << "common_data.rows_amount = " << public_preprocessed_data.common_data.rows_amount << std::endl;
    std::cout << "common_data.omega = "
              << static_cast<nil::crypto3::math::basic_radix2_domain<BlueprintFieldType> &>(
                     *public_preprocessed_data.common_data.basic_domain)
                     .omega.data
              << std::endl;
    std::cout << "columns_rotations (" << public_preprocessed_data.common_data.columns_rotations.size()
              << " number) = {" << std::endl;
    for (const auto &column_rotations : public_preprocessed_data.common_data.columns_rotations) {
        std::cout << "[";
        for (auto rot : column_rotations) {
            std::cout << int(rot) << ", ";
        }
        std::cout << "]," << std::endl;
    }
    std::cout << "}" << std::endl;

    bool verifier_res = zk::snark::redshift_verifier<BlueprintFieldType, params>::process(
        public_preprocessed_data, redshift_proof, bp, fri_params);
    std::cout << "Proof check: " << verifier_res << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()