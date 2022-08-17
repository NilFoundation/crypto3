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
#include <optional>

#include <nil/crypto3/zk/commitments/polynomial/kimchi_pedersen.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/constants.hpp>


namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename value_type>
                struct lookup_evaluation_type {
                    std::vector<typename value_type> sorted;
                    typename value_type aggreg;
                    typename value_type table;
                    typename value_type runtime;

                    lookup_evaluation_type(std::vector<typename value_type>& sorted, typename value_type& aggreg, 
                        typename value_type& table, std::optional<typename value_type>& runtime) : sorted(sorted),
                        aggreg(aggreg), table(table), runtime(runtime) {};
                };

                template<typename value_type>
                struct proof_evaluation_type {
                    std::array<typename value_type, WiresAmount> w;
                    typename value_type z;
                    std::array<typename value_type, Permuts - 1> s;
                    std::optional<typename lookup_evaluation_type<typename value_type>> lookup;
                    typename value_type generic_selector;
                    typename value_type poseidon_selector;

                    proof_evaluation_type(std::array<value_type, WiresAmount>& w, 
                        typename value_type& z, std::array<typename value_type, Permuts - 1>& s,
                        std::optional<typename lookup_evaluation_type<value_type>> &lookup, 
                        typename value_type& generic_selector, typename value_type& poseidon_selector) : 
                        w(w), z(z), s(s), lookup(lookup), generic_selector(generic_selector), 
                        poseidon_selector(poseidon_selector) {}
                };

                template <typename value_type>
                struct proof_evaluation_type<std::vector<typename value_type>> : proof_evaluation_type<value_type>{
                    proof_evaluation_type<typename value_type> combine(typename value_type& pt){
                        std::array<typename value_type, Permuts - 1> s_combined;
                        for(int i = 0; i < s_combined.size(); ++i){
                            math::polynomial<typename value_type> temp_polynomial(this->s[i].begin(), this->s[i].end());
                            s_combined[i] = temp_polynomial.evaluate(pt);
                        }

                        std::array<value_type, WiresAmount> w_combined;
                        for(int i = 0; i < s_combined.size(); ++i){
                            math::polynomial<typename value_type> temp_polynomial(this->w[i].begin(), this->w[i].end());
                            w_combined[i] = temp_polynomial.evaluate(pt);
                        }

                        math::polynomial<typename value_type> temp_polynomial_z(this->z[i].begin(), this->z[i].end());
                        typename value_type z_combined = temp_polynomial.evaluate(pt);

                        math::polynomial<typename value_type> temp_polynomial_gs(this->generic_selector[i].begin(), this->generic_selector[i].end());
                        typename value_type generic_selector_combined = temp_polynomial.evaluate(pt);

                        math::polynomial<typename value_type> temp_polynomial_ps(this->poseidon_selector[i].begin(), this->poseidon_selector[i].end());
                        typename value_type poseidon_selector_combined = temp_polynomial.evaluate(pt);

                        std::optional<typename lookup_evaluation_type<value_type>> lookup_combined;
                        if(this->lookup){
                            lookup_combined = lookup_evaluation_type<value_type>();

                            math::polynomial<typename value_type> temp_polynomial_table(this->lookup.table.begin(), this->lookup.table.end());
                            lookup_combined.value().table = temp_polynomial_table.evaluate(pt);

                            math::polynomial<typename value_type> temp_polynomial_aggreg(this->lookup.aggreg.begin(), this->lookup.aggreg.end());
                            lookup_combined.value().aggreg = temp_polynomial_aggreg.evaluate(pt);

                            for(int i = 0; i < this->lookup.sorted.size(); ++i){
                                math::polynomial<typename value_type> temp_polynomial_sorted(this->lookup.sorted[i].begin(), this->lookup.sorted[i].end());
                                lookup_combined.value().sorted[i] = temp_polynomial_sorted.evaluate(pt);
                            }
                            
                            if(this->lookup.value().runtime){
                                math::polynomial<typename value_type> temp_polynomial_runtime(this->lookup.value().runtime.value().begin(),
                                                                                            this->lookup.value().runtime.value().end());
                                lookup_combined.value().runtime.value() = temp_polynomial_runtime.evaluate(pt);
                            }
                        }

                        return proof_evaluation_type<typename value_type>(w_combined, z_combined, s_combined, lookup_combined, 
                                generic_selector_combined, poseidon_selector_combined);
                    }
                };

                struct lookup_commitment_type {
                    std::vector<commitment_type> sorted;
                    commitment_type aggreg;
                    std::optional<commitment_type> runtime;
                };

                struct proof_commitment_type {
                    std::array<commitment_type, WiresAmount> w_comm;
                    commitment_type z_comm;
                    commitment_type t_comm;
                    std::optional<lookup_commitment_type> lookup;
                };

                template<typename CurveType, std::size_t WiresAmount = kimchi_constant::COLUMNS, std::size_t Permuts = kimchi_constant::PERMUTES>
                class proof_type {
                    typedef commitments::kimchi_pedersen<CurveType> commitment_scheme;
                    typedef typename commitments::kimchi_pedersen<CurveType>::commitment_type commitment_type;
                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::base_field_type base_field_type;

                public:
                    // Commitments:

                    proof_commitment_type commitments;
                    typename commitments::kimchi_pedersen<CurveType>::proof_type proof;
                    std::array<proof_evaluation_type<std::vector<scalar_field_type::value_type>>, 2> evals;

                    // ft_eval1
                    typename scalar_field_type::value_type ft_eval1;
                    // public
                    std::vector<typename scalar_field_type::value_type> public_input;
                    // Previous challenges
                    std::vector<
                        std::pair<std::vector<typename CurveType::scalar_field_type::value_type>, commitment_type>>
                        prev_challenges;
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PROOF_HPP
