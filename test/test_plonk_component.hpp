//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_TEST_PLONK_COMPONENT_HPP
#define CRYPTO3_TEST_PLONK_COMPONENT_HPP

#include <fstream>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>

#include "profiling.hpp"
#include "profiling_component.hpp"

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>
#include <nil/crypto3/marshalling/zk/types/redshift/proof.hpp>

namespace nil {
    namespace crypto3 {
        template<typename fri_type, typename FieldType>
        typename fri_type::params_type create_fri_params(std::size_t degree_log) {
            typename fri_type::params_type params;
            math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

            constexpr std::size_t expand_factor = 0;
            std::size_t r = degree_log - 1;

            std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
                zk::commitments::detail::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

            params.r = r;
            params.D = domain_set;
            params.q = q;
            params.max_degree = (1 << degree_log) - 1;

            return params;
        }

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
                 std::size_t Lambda, typename PublicInput,
                 typename std::enable_if<
                     std::is_same<typename BlueprintFieldType::value_type,
                                  typename std::iterator_traits<typename PublicInput::iterator>::value_type>::value,
                     bool>::type = true>
        auto prepare_component(typename ComponentType::params_type params, const PublicInput &public_input) {

            using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
            using component_type = ComponentType;

            zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> desc;

            zk::blueprint<ArithmetizationType> bp(desc);
            zk::blueprint_private_assignment_table<ArithmetizationType> private_assignment(desc);
            zk::blueprint_public_assignment_table<ArithmetizationType> public_assignment(desc);
            zk::blueprint_assignment_table<ArithmetizationType> assignment_bp(private_assignment, public_assignment);

            std::size_t start_row = component_type::allocate_rows(bp);
            bp.allocate_rows(public_input.size());

            for (std::size_t i = 0; i < public_input.size(); i++) {
                auto allocated_pi = assignment_bp.allocate_public_input(public_input[i]);
            }

            typename component_type::allocated_data_type allocated_data;
            component_type::generate_circuit(bp, assignment_bp, params, allocated_data, start_row);
            component_type::generate_assignments(assignment_bp, params, start_row);

            assignment_bp.padding();
            std::cout << "Usable rows: " << desc.usable_rows_amount << std::endl;
            std::cout << "Padded rows: " << desc.rows_amount << std::endl;

            zk::snark::plonk_assignment_table<BlueprintFieldType, ArithmetizationParams> assignments(private_assignment,
                                                                                                     public_assignment);

            using redshift_params =
                zk::snark::redshift_params<BlueprintFieldType, ArithmetizationParams, Hash, Hash, Lambda>;
            using types = zk::snark::detail::redshift_policy<BlueprintFieldType, redshift_params>;

            using fri_type =
                typename zk::commitments::fri<BlueprintFieldType, typename redshift_params::merkle_hash_type,
                                              typename redshift_params::transcript_hash_type, 2>;

            std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

            typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log);

            std::size_t permutation_size = desc.witness_columns + desc.public_input_columns + desc.constant_columns;

            typename types::preprocessed_public_data_type public_preprocessed_data =
                zk::snark::redshift_public_preprocessor<BlueprintFieldType, redshift_params>::process(
                    bp, public_assignment, desc, fri_params, permutation_size);
            typename types::preprocessed_private_data_type private_preprocessed_data =
                zk::snark::redshift_private_preprocessor<BlueprintFieldType, redshift_params>::process(
                    bp, private_assignment, desc);

            return std::make_tuple(desc, bp, fri_params, assignments, public_preprocessed_data,
                                   private_preprocessed_data);
        }

        template<typename RedshiftParams, typename FieldType, typename Proof, typename FRIParams, typename CommonData>
        void print_test_data(const Proof &proof, const FRIParams &fri_params, const CommonData &common_data) {
            using Endianness = nil::marshalling::option::big_endian;
            using TTypeBase = nil::marshalling::field_type<Endianness>;
            using proof_marshalling_type = nil::crypto3::marshalling::types::redshift_proof<TTypeBase, Proof>;
            auto filled_redshift_proof =
                nil::crypto3::marshalling::types::fill_redshift_proof<Proof, Endianness>(proof);
            std::vector<std::uint8_t> cv;
            cv.resize(filled_redshift_proof.length(), 0x00);
            auto write_iter = cv.begin();
            nil::marshalling::status_type status = filled_redshift_proof.write(write_iter, cv.size());
            std::cout << "proof (" << cv.size() << " bytes) = " << std::endl;
            std::ofstream proof_file;
            proof_file.open("redshift_proof.txt");
            print_hex_byteblob(proof_file, cv.cbegin(), cv.cend(), false);

            std::cout << "modulus = " << FieldType::modulus << std::endl;
            std::cout << "fri_params.r = " << fri_params.r << std::endl;
            std::cout << "fri_params.max_degree = " << fri_params.max_degree << std::endl;
            std::cout << "fri_params.q = ";
            for (const auto &coeff : fri_params.q) {
                std::cout << coeff.data << ", ";
            }
            std::cout << std::endl;
            std::cout << "fri_params.D_omegas = ";
            for (const auto &dom : fri_params.D) {
                std::cout << static_cast<nil::crypto3::math::basic_radix2_domain<FieldType> &>(*dom).omega.data << ", ";
            }
            std::cout << std::endl;
            std::cout << "lpc_params.lambda = " << RedshiftParams::commitment_params_type::lambda << std::endl;
            std::cout << "lpc_params.m = " << RedshiftParams::commitment_params_type::m << std::endl;
            std::cout << "lpc_params.r = " << RedshiftParams::commitment_params_type::r << std::endl;
            std::cout << "common_data.rows_amount = " << common_data.rows_amount << std::endl;
            std::cout << "common_data.omega = "
                      << static_cast<nil::crypto3::math::basic_radix2_domain<FieldType> &>(*common_data.basic_domain)
                             .omega.data
                      << std::endl;
            std::cout << "columns_rotations (" << common_data.columns_rotations.size() << " number) = {" << std::endl;
            for (const auto &column_rotations : common_data.columns_rotations) {
                std::cout << "[";
                for (auto rot : column_rotations) {
                    std::cout << int(rot) << ", ";
                }
                std::cout << "]," << std::endl;
            }
            std::cout << "}" << std::endl;
        }

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
                 std::size_t Lambda, typename PublicInput>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInput::iterator>::value_type>::value>::type
            test_component(typename ComponentType::params_type params, const PublicInput &public_input) {

            using redshift_params =
                zk::snark::redshift_params<BlueprintFieldType, ArithmetizationParams, Hash, Hash, Lambda>;

            auto [desc, bp, fri_params, assignments, public_preprocessed_data, private_preprocessed_data] =
                prepare_component<ComponentType, BlueprintFieldType, ArithmetizationParams, Hash, Lambda>(params,
                                                                                                          public_input);

            auto proof = zk::snark::redshift_prover<BlueprintFieldType, redshift_params>::process(
                public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);

            print_test_data<redshift_params, BlueprintFieldType>(proof, fri_params,
                                                                 public_preprocessed_data.common_data);

            bool verifier_res = zk::snark::redshift_verifier<BlueprintFieldType, redshift_params>::process(
                public_preprocessed_data, proof, bp, fri_params);
            profiling(assignments);
            profiling_component<BlueprintFieldType, ArithmetizationParams, Hash, Lambda>::process(
                std::cout, bp, public_preprocessed_data);
            BOOST_CHECK(verifier_res);
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_TEST_PLONK_COMPONENT_HPP
