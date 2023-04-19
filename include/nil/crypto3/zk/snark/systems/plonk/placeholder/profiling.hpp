//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_PROFILING_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_PROFILING_HPP

#include <algorithm>

#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename PlaceholderParams>
                struct placeholder_profiling;


/*              template<typename FieldType, typename ArithmetizationParams, typename MerkleTreeHashType,
                         typename TranscriptHashType, std::size_t Lambda, std::size_t R, std::size_t M>
                struct placeholder_profiling<placeholder_params<FieldType, ArithmetizationParams, MerkleTreeHashType,
                                                                TranscriptHashType, Lambda, R, M>> {
                    typedef placeholder_params<FieldType, ArithmetizationParams, MerkleTreeHashType, TranscriptHashType,
                                               Lambda, R, M>
                        placeholder_params_type;

                    template<typename Proof, typename FRIParams, typename CommonData>
                    static void print_params(const Proof &proof, const FRIParams &fri_params,
                                             const CommonData &common_data) {
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
                            std::cout
                                << static_cast<nil::crypto3::math::basic_radix2_domain<FieldType> &>(*dom).omega.data
                                << ", ";
                        }
                        std::cout << std::endl;
                        std::cout << "lpc_params.lambda = "
                                  << placeholder_params_type::batched_commitment_params_type::lambda << std::endl;
                        std::cout << "lpc_params.m = " << placeholder_params_type::batched_commitment_params_type::m
                                  << std::endl;
                        std::cout << "common_data.rows_amount = " << common_data.rows_amount << std::endl;
                        std::cout << "common_data.omega = "
                                  << static_cast<nil::crypto3::math::basic_radix2_domain<FieldType> &>(
                                         *common_data.basic_domain)
                                         .omega.data
                                  << std::endl;
                        std::cout << "columns_rotations (" << common_data.columns_rotations.size() << " number) = {"
                                  << std::endl;
                        for (const auto &column_rotations : common_data.columns_rotations) {
                            std::cout << "[";
                            for (auto rot : column_rotations) {
                                std::cout << int(rot) << ", ";
                            }
                            std::cout << "]," << std::endl;
                        }
                        std::cout << "}" << std::endl;

                        auto max_leaf_size_fri_proof = [](const auto &fri_proof) {
                            std::size_t max_leaf_size = 0;
                            for (const auto &round_proofs_i : fri_proof.round_proofs) {
                                max_leaf_size = std::max(max_leaf_size, round_proofs_i.y.size());
                            }
                            return max_leaf_size;
                        };
                        auto max_leaf_size_lpc_proof = [&max_leaf_size_fri_proof](const auto &lpc_proof) {
                            std::size_t max_leaf_size = 0;
                            for (const auto &fri_proofs_i : lpc_proof.fri_proof) {
                                max_leaf_size = std::max(max_leaf_size, max_leaf_size_fri_proof(fri_proofs_i));
                            }
                            return max_leaf_size;
                        };
                        std::cout << "max_leaf_size = "
                                  << std::max({
                                         max_leaf_size_lpc_proof(proof.eval_proof.witness),
                                         max_leaf_size_lpc_proof(proof.eval_proof.quotient),
                                         max_leaf_size_lpc_proof(proof.eval_proof.id_permutation),
                                         max_leaf_size_lpc_proof(proof.eval_proof.sigma_permutation),
                                         max_leaf_size_lpc_proof(proof.eval_proof.public_input),
                                         max_leaf_size_lpc_proof(proof.eval_proof.constant),
                                         max_leaf_size_lpc_proof(proof.eval_proof.selector),
                                         max_leaf_size_lpc_proof(proof.eval_proof.special_selectors),
                                     })
                                  << std::endl;
                    }
*/

                    template<typename FRI, typename TableDescriptionType, typename ColumnsRotationsType,
                            typename ArithmetizationParams>
                    void print_placeholder_params(typename FRI::params_type &fri_params, TableDescriptionType table_description,
                                    ColumnsRotationsType &columns_rotations, std::string filename) {
                        using FRIParamsType = typename FRI::params_type;
                        std::ofstream out;

                        out.open(filename);
                        out << "{"
                            << "\t\"_test_name\":\"Test name\"," << std::endl;
                        out << "\t\"arithmetization_params\":[" << ArithmetizationParams::witness_columns << ","
                            << ArithmetizationParams::public_input_columns << "," << ArithmetizationParams::constant_columns << ","
                            << ArithmetizationParams::selector_columns << "]," << std::endl
                            << "\t\"columns_rotations\":[";
                        for (size_t i = 0; i < columns_rotations.size(); i++) {
                            if (i != 0)
                                out << ",";
                            out << "[";
                            bool print_coma = false;
                            for (int r: columns_rotations[i]) {
                                if (print_coma)
                                    out << ",";
                                out << r;
                                print_coma = true;
                            }
                            out << "]";
                        }
                        out << "]," << std::endl;
                        out << "\t\"modulus\":" << FRI::field_type::modulus << "," << std::endl;
                        out << "\t\"r\":" << fri_params.r << "," << std::endl;
                        out << "\t\"m\":" << FRI::m << "," << std::endl;
                        out << "\t\"lambda\":" << FRI::lambda << "," << std::endl;
                        out << "\t\"batches_num\":" << FRI::batches_num << "," << std::endl;
                        out << "\t\"step_list\":[";
                        for (size_t i = 0; i < fri_params.step_list.size(); i++) {
                            if (i != 0)
                                out << ",";
                            out << fri_params.step_list[i];
                        }
                        out << "]," << std::endl;
                        out << "\t\"D_omegas\":[" << std::endl;
                        for (size_t i = 0; i < fri_params.D.size(); i++) {
                            if (i != 0)
                                out << "," << std::endl;
                            out << "\t\t" << fri_params.D[i]->get_domain_element(1).data;
                        }
                        out << std::endl << "\t]," << std::endl;
                        out << "\t\"rows_amount\":" << table_description.rows_amount << "," << std::endl;
                        out << "\t\"max_degree\":" << fri_params.max_degree << "," << std::endl;
                        out << "\t\"omega\":" << fri_params.D[0]->get_domain_element(1).data << std::endl;
                        out << "}" << std::endl;
                        out.close();
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_PROFILING_HPP
