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

#ifndef CRYPTO3_ZK_PICKLES_PROOF_HPP
#define CRYPTO3_ZK_PICKLES_PROOF_HPP

#include <array>
#include <tuple>
#include <vector>

#include <nil/crypto3/zk/commitments/polynomial/kimchi_pedersen.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/constants.hpp>


namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename value_type>
                struct lookup_evaluation_type {
                    std::vector<value_type> sorted;
                    value_type aggreg;
                    value_type table;
                    value_type runtime;
                    bool runtime_is_used;

                    lookup_evaluation_type(std::vector<value_type>& sorted, value_type& aggreg, 
                        value_type& table, value_type& runtime) : sorted(sorted),
                        aggreg(aggreg), table(table), runtime(runtime) {};

                    lookup_evaluation_type() = default;
                };

                template<typename value_type>
                struct base_proof_evaluation_type {
                    constexpr static const std::size_t Permuts = kimchi_constant::PERMUTES;
                    constexpr static const std::size_t WiresAmount = kimchi_constant::COLUMNS;

                    std::array<value_type, WiresAmount> w;
                    value_type z;
                    std::array<value_type, Permuts - 1> s;
                    lookup_evaluation_type<value_type> lookup;
                    bool lookup_is_used;
                    value_type generic_selector;
                    value_type poseidon_selector;

                    base_proof_evaluation_type(std::array<value_type, WiresAmount>& w, 
                        value_type& z, std::array<value_type, Permuts - 1>& s,
                        lookup_evaluation_type<value_type> &lookup, 
                        value_type& generic_selector, value_type& poseidon_selector) : 
                        w(w), z(z), s(s), lookup(lookup), generic_selector(generic_selector), 
                        poseidon_selector(poseidon_selector) {}

                    base_proof_evaluation_type() = default;
                };

                template <typename value_type>
                struct proof_evaluation_type : base_proof_evaluation_type<value_type> {
                    using base_proof_evaluation_type<value_type>::base_proof_evaluation_type;
                };

                template <typename value_type>
                struct proof_evaluation_type<std::vector<value_type>> : base_proof_evaluation_type<std::vector<value_type>>{
                    using base_proof_evaluation_type<std::vector<value_type>>::base_proof_evaluation_type;
                    
                    proof_evaluation_type<value_type> combine(value_type& pt){
                        std::array<value_type, kimchi_constant::PERMUTES - 1> s_combined;
                        for(int i = 0; i < s_combined.size(); ++i){
                            math::polynomial<value_type> temp_polynomial(this->s[i].begin(), this->s[i].end());
                            s_combined[i] = temp_polynomial.evaluate(pt);
                        }

                        std::array<value_type, kimchi_constant::COLUMNS> w_combined;
                        for(int i = 0; i < w_combined.size(); ++i){
                            math::polynomial<value_type> temp_polynomial(this->w[i].begin(), this->w[i].end());
                            w_combined[i] = temp_polynomial.evaluate(pt);
                        }

                        math::polynomial<value_type> temp_polynomial_z(this->z.begin(), this->z.end());
                        value_type z_combined = temp_polynomial_z.evaluate(pt);

                        math::polynomial<value_type> temp_polynomial_gs(this->generic_selector.begin(), this->generic_selector.end());
                        value_type generic_selector_combined = temp_polynomial_gs.evaluate(pt);

                        math::polynomial<value_type> temp_polynomial_ps(this->poseidon_selector.begin(), this->poseidon_selector.end());
                        value_type poseidon_selector_combined = temp_polynomial_ps.evaluate(pt);

                        lookup_evaluation_type<value_type> lookup_combined;
                        if(this->lookup_is_used){
                            lookup_combined = lookup_evaluation_type<value_type>();

                            math::polynomial<value_type> temp_polynomial_table(this->lookup.table.begin(), this->lookup.table.end());
                            lookup_combined.table = temp_polynomial_table.evaluate(pt);

                            math::polynomial<value_type> temp_polynomial_aggreg(this->lookup.aggreg.begin(), this->lookup.aggreg.end());
                            lookup_combined.aggreg = temp_polynomial_aggreg.evaluate(pt);

                            for(int i = 0; i < this->lookup.sorted.size(); ++i){
                                math::polynomial<value_type> temp_polynomial_sorted(this->lookup.sorted[i].begin(), this->lookup.sorted[i].end());
                                lookup_combined.sorted[i] = temp_polynomial_sorted.evaluate(pt);
                            }
                            
                            if(this->lookup.runtime_is_used){
                                math::polynomial<value_type> temp_polynomial_runtime(this->lookup.runtime.begin(),
                                                                                            this->lookup.runtime.end());
                                lookup_combined.runtime = temp_polynomial_runtime.evaluate(pt);
                            }
                        }

                        return proof_evaluation_type<value_type>(w_combined, z_combined, s_combined, lookup_combined, 
                                generic_selector_combined, poseidon_selector_combined);
                    }
                };
                
                template<typename CurveType>
                struct lookup_commitment_type {
                    typedef commitments::kimchi_pedersen<CurveType> commitment_scheme;
                    typedef typename commitments::kimchi_pedersen<CurveType>::commitment_type commitment_type;

                    std::vector<commitment_type> sorted;
                    commitment_type aggreg;
                    commitment_type runtime;
                    bool runtime_is_used;
                };
                
                template<typename CurveType>
                struct proof_commitment_type {
                    typedef commitments::kimchi_pedersen<CurveType> commitment_scheme;
                    typedef typename commitments::kimchi_pedersen<CurveType>::commitment_type commitment_type;

                    // constexpr static const std::size_t Permuts = kimchi_constant::PERMUTES;
                    constexpr static const std::size_t WiresAmount = kimchi_constant::COLUMNS;

                    std::array<commitment_type, WiresAmount> w_comm;
                    commitment_type z_comm;
                    commitment_type t_comm;
                    lookup_commitment_type<CurveType> lookup;
                    bool lookup_is_used;
                };

                template<typename CurveType, std::size_t WiresAmount = kimchi_constant::COLUMNS, std::size_t Permuts = kimchi_constant::PERMUTES>
                class proof_type {
                    typedef commitments::kimchi_pedersen<CurveType> commitment_scheme;
                    typedef typename commitments::kimchi_pedersen<CurveType>::commitment_type commitment_type;
                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::base_field_type base_field_type;

                public:
                    // Commitments:

                    proof_commitment_type<CurveType> commitments;
                    typename commitments::kimchi_pedersen<CurveType>::proof_type proof;
                    std::array<proof_evaluation_type<std::vector<typename scalar_field_type::value_type>>, 2> evals;

                    // ft_eval1
                    typename scalar_field_type::value_type ft_eval1;
                    // public
                    std::vector<typename scalar_field_type::value_type> public_input;
                    // Previous challenges
                    std::vector<
                        std::pair<
                            std::vector<typename CurveType::scalar_field_type::value_type>, 
                            commitment_type
                        >
                    >   prev_challenges;
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PROOF_HPP