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

#include <nil/crypto3/zk/snark/commitments/polynmomial/pedersen.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <map>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType, std::size_t WiresAmount = 15, std::size_t Permuts = 7>
                class verifier_index {
                    typedef pedersen_commitment_scheme<CurveType> commitment_scheme;
                    using curve_t = CurveType;
                    using Fr = typename CurveType::scalar_field_type;
                    using Fq = typename CurveType::base_field_type;

                    nil::crypto3::math::evaluation_domain<Fr> domain;
                    size_t max_poly_size;
                    size_t max_quot_size;
                    srs_t<CurveType> srs;
                    std::array<commitment_scheme, Permuts> sigma_comm;
                    std::array<commitment_scheme, WiresAmount> coefficients_comm;
                    commitment_scheme generic_comm;
                    commitment_scheme psm_comm;
                    commitment_scheme complete_add_comm;
                    commitment_scheme mul_comm;
                    commitment_scheme emul_comm;
                    commitment_scheme endomul_scalar_comm;
                    std::array<commitment_scheme, 4> chacha_comm;
                    std::array<Fr, Permuts> shift;

                    // Polynomial in coefficients form
                    nil::crypto3::math::polynomial<Fr> zkpm;
                    Fr w;
                    Fr endo;
                    lookup_verifier_index<CurveType, WiresAmount> lookup_index;
                    linearization_t linearization;    // TODO: Linearization<Vec<PolishToken<Fr<G>>>>
                    Alphas<Fr> powers_of_alpha;
                    ArithmeticSpongeParams<Fr> fr_sponge_params;
                    ArithmeticSpongeParams<Fq> fq_sponge_params;
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
};               // namespace nil

#endif    // CRYPTO3_ZK_PLONK_BATCHED_PICKLES_VERIFIER_INDEXER_HPP
