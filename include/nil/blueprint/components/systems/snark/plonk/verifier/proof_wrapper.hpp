//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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
// @file Object, that helps to transform placeholder proof to public input column for recursive circuit
//---------------------------------------------------------------------------//
#ifndef BLUEPRINT_COMPONENTS_FLEXIBLE_VERIFIER_PLACEHOLDER_PROOF_WRAPPER_HPP
#define BLUEPRINT_COMPONENTS_FLEXIBLE_VERIFIER_PLACEHOLDER_PROOF_WRAPPER_HPP

#include <map>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/proof.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail{
                template <typename PlaceholderParams>
                class placeholder_proof_wrapper{
                public:
                    using field_type = typename PlaceholderParams::field_type;
                    using proof_type = nil::crypto3::zk::snark::placeholder_proof<field_type, PlaceholderParams>;
                    using common_data_type = typename nil::crypto3::zk::snark::placeholder_public_preprocessor<field_type, PlaceholderParams>::preprocessed_data_type::common_data_type;
                    placeholder_proof_wrapper(const common_data_type& common_data, const proof_type& proof)
                        : common_data(common_data), proof(proof) {
                        fill_vector();
                    }
                public:
                    std::vector<typename field_type::value_type> vector(){
                        return _proof_field_vector;
                    }
                    std::vector<typename field_type::value_type> merkle_tree_positions(){
                        return _merkle_tree_positions;
                    }
                    std::vector<typename field_type::value_type> initial_proof_hashes(){
                        return _initial_proof_hashes;
                    }
                protected:
                    void fill_vector() {
                        _proof_field_vector.push_back(proof.commitments.at(1));
                        _proof_field_vector.push_back(proof.commitments.at(2));
                        _proof_field_vector.push_back(proof.commitments.at(3));

                        if( proof.commitments.find(4) != proof.commitments.end() ){ /*nil::crypto3::zk::snark::LOOKUP_BATCH*/
                            _proof_field_vector.push_back(proof.commitments.at(4));
                        }

                        _proof_field_vector.push_back(proof.eval_proof.challenge);

                        // TODO: Commitment scheme may be different
                        auto eval_proof = proof.eval_proof.eval_proof;
                        auto batch_info = eval_proof.z.get_batch_info();
                        for(const auto& [k, v]: batch_info){
                            for(std::size_t i = 0; i < v; i++){
                                BOOST_ASSERT(eval_proof.z.get_poly_points_number(k, i) != 0);
                                for(std::size_t j = 0; j < eval_proof.z.get_poly_points_number(k, i); j++){
                                    _proof_field_vector.push_back(eval_proof.z.get(k, i, j));
                                }
                            }
                        }

                        for( std::size_t i = 0; i < eval_proof.fri_proof.fri_roots.size(); i++){
                            _proof_field_vector.push_back(eval_proof.fri_proof.fri_roots[i]);
                        }

                        _merkle_tree_positions.resize(eval_proof.fri_proof.query_proofs.size());
                        _initial_proof_values.resize(eval_proof.fri_proof.query_proofs.size());
                        _initial_proof_hashes.resize(eval_proof.fri_proof.query_proofs.size());
                        for( std::size_t i = 0; i < eval_proof.fri_proof.query_proofs.size(); i++){
                            for( const auto &[j, initial_proof]: eval_proof.fri_proof.query_proofs[i].initial_proof){
                                for( std::size_t k = 0; k < initial_proof.values.size(); k++){
                                    _proof_field_vector.push_back(initial_proof.values[k][0][0]);
                                    _proof_field_vector.push_back(initial_proof.values[k][0][1]);
                                    _initial_proof_values[i].push_back(initial_proof.values[k][0][0]);
                                    _initial_proof_values[i].push_back(initial_proof.values[k][0][1]);
                                }
                            }

                            std::size_t x_index = 0;
                            for( const auto &[j, initial_proof]: eval_proof.fri_proof.query_proofs[i].initial_proof){
                                _merkle_tree_positions[i].resize(initial_proof.p.path().size());
                                std::cout << "Initial proof position ";
                                for( std::size_t k = 0; k < initial_proof.p.path().size(); k++){
                                    _proof_field_vector.push_back(initial_proof.p.path()[k][0].position());
                                    _merkle_tree_positions[i][k] = initial_proof.p.path()[k][0].position();
                                    std::cout << initial_proof.p.path()[k][0].position() << " ";
                                }
                                std::cout << " => " << x_index << std::endl;
                                break;
                            }

                            for( const auto &[j, initial_proof]: eval_proof.fri_proof.query_proofs[i].initial_proof){
                                //std::cout << "Initial proof hashes: " << std::endl;
                                for( std::size_t k = 0; k < initial_proof.p.path().size(); k++){
                                    _proof_field_vector.push_back(initial_proof.p.path()[k][0].hash());
                                    _initial_proof_hashes[i].push_back(initial_proof.p.path()[k][0].hash());
                                    //std::cout << "\t" << _proof_field_vector.size() << " ";
                                    //std::cout << "\t" << initial_proof.p.path()[k][0].hash() << std::endl;
                                }
                            }
                            for( std::size_t j = 0; j < eval_proof.fri_proof.query_proofs[i].round_proofs.size(); j++){
                                const auto &round_proof = eval_proof.fri_proof.query_proofs[i].round_proofs[j];
                                _proof_field_vector.push_back(round_proof.y[0][0]);
                                _proof_field_vector.push_back(round_proof.y[0][1]);
                            }
                            for( std::size_t j = 0; j < eval_proof.fri_proof.query_proofs[i].round_proofs.size(); j++){
                                const auto& p = eval_proof.fri_proof.query_proofs[i].round_proofs[j].p;
                                for( std::size_t k = 0; k < p.path().size(); k++){
                                    _proof_field_vector.push_back(p.path()[k][0].hash());
                                 }
                            }
                        }

                        for( std::size_t i = 0; i < eval_proof.fri_proof.final_polynomial.size(); i++){
                            _proof_field_vector.push_back(eval_proof.fri_proof.final_polynomial[i]);
                        }
                    }
                private:
                    const common_data_type common_data;
                    const proof_type proof;
                    std::vector<typename field_type::value_type> _proof_field_vector;
                    std::vector<std::vector<typename field_type::value_type>> _merkle_tree_positions;
                    // lambda * batches_num * 2 values. Convenient for merkle leaves calculation.
                    std::vector<std::vector<typename field_type::value_type>> _initial_proof_values;
                    std::vector<std::vector<typename field_type::value_type>> _initial_proof_hashes;
                };
            }
        }
    }
}

#endif