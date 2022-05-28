//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_VERIFIER_INDEX_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_VERIFIER_INDEX_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                typedef std::array<uint64_t, 2> kimchi_scalar_limbs;

                template<std::size_t AlphaPowersN, std::size_t PublicInputSize>
                struct kimchi_params_type {
                    constexpr static std::size_t alpha_powers_n = AlphaPowersN;
                    constexpr static std::size_t public_input_size = PublicInputSize;
                };

                template <std::size_t EvalRounds,
                    std::size_t MaxPolySize>
                struct kimchi_commitment_params_type {
                    constexpr static std::size_t max_poly_size = MaxPolySize;
                    constexpr static std::size_t eval_rounds = EvalRounds;
                    constexpr static std::size_t res_size = max_poly_size == (1 << eval_rounds) ? 1 : 2;
                };

                template<typename CurveType, std::size_t Permuts = 7>
                struct kimchi_verifier_index_scalar {
                    using Fr = typename CurveType::scalar_field_type::value_type;
                    using FieldType = typename CurveType::scalar_field_type;
                    using var = snark::plonk_variable<FieldType>;

                    // nil::crypto3::math::evaluation_domain<Fr> domain;
                    var max_poly_size;
                    std::size_t max_quot_size;
                    std::size_t alpha_powers;
                    std::size_t public_input_size;
                    std::array<Fr, Permuts> shift;

                    // Polynomial in coefficients form
                    nil::crypto3::math::polynomial<Fr> zkpm;
                    Fr w;
                    Fr endo;
                    var domain_size;
                    var omega;
                    Fr domain_size_inv;
                    // linearization_t linearization;    // TODO: Linearization<Vec<PolishToken<Fr<G>>>>
                    // Alphas<Fr> powers_of_alpha;
                    // ArithmeticSpongeParams<Fr> fr_sponge_params;
                };

                /*struct kimchi_verifier_index_base {
                    typedef commitments::kimchi_pedersen<CurveType> commitment_scheme;
                    typedef typename commitments::kimchi_pedersen<CurveType>::commitment_type commitment_type;
                    using curve_t = CurveType;
                    using Fr = typename CurveType::scalar_field_type;
                    using Fq = typename CurveType::base_field_type;

                    nil::crypto3::math::evaluation_domain<Fr> domain;
                    size_t max_poly_size;
                    size_t max_quot_size;
                    srs_t<CurveType> srs;
                    std::array<commitment_type, Permuts> sigma_comm;
                    std::array<commitment_type, WiresAmount> coefficients_comm;
                    commitment_type generic_comm;
                    commitment_type psm_comm;
                    commitment_type complete_add_comm;
                    commitment_type mul_comm;
                    commitment_type emul_comm;
                    commitment_type endomul_scalar_comm;
                    std::array<commitment_type, 4> chacha_comm;
                    std::array<Fr, Permuts> shift;

                    // Polynomial in coefficients form
                    nil::crypto3::math::polynomial<Fr> zkpm;
                    Fr w;
                    Fr endo;
                    lookup_verifier_index<CurveType> lookup_index;
                    linearization_t linearization;    // TODO: Linearization<Vec<PolishToken<Fr<G>>>>
                    Alphas<Fr> powers_of_alpha;
                    ArithmeticSpongeParams<Fr> fr_sponge_params;
                    ArithmeticSpongeParams<Fq> fq_sponge_params;
                };*/
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_VERIFIER_INDEX_HPP