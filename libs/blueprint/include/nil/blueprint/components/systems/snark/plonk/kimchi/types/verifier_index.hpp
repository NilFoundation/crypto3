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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_VERIFIER_INDEX_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_VERIFIER_INDEX_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/commitment.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {
                typedef std::array<uint64_t, 2> kimchi_scalar_limbs;

                template<typename BlueprintFieldType, std::size_t Permuts = 7>
                struct kimchi_verifier_index_scalar {
                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    // nil::crypto3::math::evaluation_domain<Fr> domain;
                    std::size_t max_quot_size;
                    std::size_t domain_size;
                    std::array<var, Permuts> shift;

                    var omega;
                };

                template<typename CurveType, typename KimchiParamsType>
                struct kimchi_verifier_index_base {
                    using FieldType = typename CurveType::base_field_type;
                    using commitment_params_type = typename KimchiParamsType::commitment_params_type;

                    using commitment_type = typename zk::components::kimchi_commitment_type<
                        FieldType, commitment_params_type::shifted_commitment_split>;

                    using var = snark::plonk_variable<FieldType>;
                    using var_ec_point = typename zk::components::var_ec_point<FieldType>;

                    static constexpr const std::size_t chacha_size = 4;
                    static constexpr const std::size_t range_check_size = 2;

                    struct commitments_type {
                        std::array<commitment_type, KimchiParamsType::permut_size> sigma;
                        std::array<commitment_type, KimchiParamsType::witness_columns> coefficient;
                        commitment_type generic;
                        commitment_type psm;
                        std::vector<commitment_type> selectors;
                        std::vector<commitment_type> lookup_selectors;
                        commitment_type runtime_tables_selector;
                        std::vector<commitment_type> lookup_table;
                        commitment_type complete_add;
                        commitment_type var_base_mul;
                        commitment_type endo_mul;
                        commitment_type endo_mul_scalar;
                        std::array<commitment_type, chacha_size> chacha;
                        std::array<commitment_type, range_check_size> range_check;
                    };

                    var_ec_point H;
                    std::array<var_ec_point, commitment_params_type::srs_len> G;
                    std::array<var_ec_point, KimchiParamsType::public_input_size> lagrange_bases;
                    commitments_type comm;
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_VERIFIER_INDEX_HPP