//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_BATCHED_PICKLES_VERIFIER_INDEXER_HPP
#define CRYPTO3_ZK_PLONK_BATCHED_PICKLES_VERIFIER_INDEXER_HPP

#include <nil/crypto3/hash/detail/poseidon/poseidon_constants.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kimchi_pedersen.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/pickles/alphas.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/constants.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/expr.hpp>

#include <nil/crypto3/math/domains/basic_radix2_domain.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <array>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                // arithmetic_sponge_params<scalar_field_value_type> fr_sponge_params;
                // arithmetic_sponge_params<base_field_value_type> fq_sponge_params;  
                // hashes::detail::poseidon_constants_kimchi<scalar_field_type> fr_sponge_params;
                // hashes::detail::poseidon_constants_kimchi<base_field_type> fq_sponge_params;
                template<
                    typename CurveType, 
                    typename PoseidonKimchiScalarConstants = hashes::detail::poseidon_constants<nil::crypto3::hashes::detail::mina_poseidon_policy<typename CurveType::scalar_field_type>>,
                    typename PoseidonKimchiBaseConstants = hashes::detail::poseidon_constants<nil::crypto3::hashes::detail::mina_poseidon_policy<typename CurveType::base_field_type>>,
                    std::size_t WiresAmount = kimchi_constant::COLUMNS, 
                    std::size_t Permuts = kimchi_constant::PERMUTES
                >
                struct verifier_index {
                    typedef commitments::kimchi_pedersen<CurveType> commitment_scheme;
                    typedef typename commitment_scheme::commitment_type commitment_type;
                    using curve_type = CurveType;
                    using scalar_field_type = typename CurveType::scalar_field_type;
                    using base_field_type = typename CurveType::base_field_type;

                    math::basic_radix2_domain<scalar_field_type> domain;
                    size_t max_poly_size;
                    size_t max_quot_size;
                    typename commitment_scheme::params_type srs;

                    std::array<commitment_type, Permuts> sigma_comm;
                    std::array<commitment_type, WiresAmount> coefficients_comm;
                    commitment_type generic_comm;

                    commitment_type psm_comm;
                    
                    commitment_type complete_add_comm;
                    commitment_type mul_comm;
                    commitment_type emul_comm;
                    commitment_type endomul_scalar_comm;

                    std::array<commitment_type, 4> chacha_comm;
                    bool chacha_comm_is_used;
                    std::vector<commitment_type> range_check_comm;

                    std::array<typename scalar_field_type::value_type, Permuts> shift;
                    // Polynomial in coefficients form
                    math::polynomial<typename scalar_field_type::value_type> zkpm;
                    typename scalar_field_type::value_type w;
                    typename scalar_field_type::value_type endo;

                    lookup_verifier_index<CurveType> lookup_index;
                    bool lookup_index_is_used;
                    Linearization<std::vector<PolishToken<scalar_field_type>>> linearization;
                    //                    linearization;    // TODO:
                    //                    Linearization<Vec<PolishToken<scalar_field_value_type<G>>>>
                    Alphas<scalar_field_type> powers_of_alpha;
                    PoseidonKimchiScalarConstants   fr_sponge_params;
                    PoseidonKimchiBaseConstants   fq_sponge_params;

                    verifier_index() : domain(2) {}
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
};               // namespace nil

#endif    // CRYPTO3_ZK_PLONK_BATCHED_PICKLES_VERIFIER_INDEXER_HPP
