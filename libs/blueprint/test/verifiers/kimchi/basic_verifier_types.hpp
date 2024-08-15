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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PICKLES_VERIFIER_PROOF_TYPES_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PICKLES_VERIFIER_PROOF_TYPES_HPP

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/verifier_base_field.hpp>

using namespace nil::crypto3;

using curve_type = algebra::curves::vesta;
using FpType = typename curve_type::base_field_type;
using FrType = typename curve_type::scalar_field_type;

template <typename BlueprintFieldType, typename ProofType>
struct proof_generator_result_type {
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
        ArithmetizationParams>;
    using params = zk::snark::placeholder_params<BlueprintFieldType>;
    using types = zk::snark::detail::placeholder_policy<BlueprintFieldType, params>;

    using fri_type = typename zk::commitments::fri<BlueprintFieldType,
        typename params::merkle_hash_type,
        typename params::transcript_hash_type,
        2>;

    ProofType placeholder_proof;
    typename fri_type::params_type fri_params;
    zk::blueprint<ArithmetizationType> bp;
    typename types::preprocessed_public_data_type public_preprocessed_data;
    typename curve_type::scalar_field_type::integral_type out;
};

//////////// BASE /////////////////////////////
constexpr std::size_t WitnessColumnsBase = 15;
constexpr std::size_t PublicInputColumnsBase = 1;
constexpr std::size_t ConstantColumnsBase = 0;
constexpr std::size_t SelectorColumnsBase = 1;

using ArithmetizationParamsBase = zk::snark::plonk_arithmetization_params<WitnessColumnsBase,
    PublicInputColumnsBase, ConstantColumnsBase, SelectorColumnsBase>;
using ArithmetizationTypeBase = zk::snark::plonk_constraint_system<FpType,
            ArithmetizationParamsBase>;

using params_base = zk::snark::placeholder_params<FpTypeBase>;
using types_base = zk::snark::detail::placeholder_policy<FpType, params_base>;

typedef zk::commitments::list_polynomial_commitment<FpType,
                                                typename params_base::commitment_params_type>
    commitment_scheme_witness_type_base;
typedef zk::commitments::list_polynomial_commitment<FpType,
                                                typename params_base::commitment_params_type>
    commitment_scheme_permutation_type_base;
typedef zk::commitments::list_polynomial_commitment<FpType,
                                                typename params_base::commitment_params_type>
    commitment_scheme_quotient_type_base;
typedef zk::commitments::list_polynomial_commitment<FpType,
                                                typename params_base::commitment_params_type>
    commitment_scheme_public_input_type_base;

using proof_type_base = zk::snark::placeholder_proof<FpType, commitment_scheme_witness_type_base,
        commitment_scheme_permutation_type_base, commitment_scheme_quotient_type_base,
        commitment_scheme_public_input_type_base>;

using proof_generator_result_type_base = proof_generator_result_type<FpType,
        ArithmetizationParamsBase, proof_type_base>;

//////////// SCALAR ///////////////////////////
constexpr std::size_t WitnessColumnsScalar = 15;
constexpr std::size_t PublicInputColumnsScalar = 1;
constexpr std::size_t ConstantColumnsScalar = 3;
constexpr std::size_t SelectorColumnsScalar = 11;

using ArithmetizationParamsScalar = zk::snark::plonk_arithmetization_params<WitnessColumnsScalar,
    PublicInputColumnsScalar, ConstantColumnsScalar, SelectorColumnsScalar>;
using ArithmetizationTypeScalar = zk::snark::plonk_constraint_system<FrType,
            ArithmetizationParamsScalar>;

using params_scalar = zk::snark::placeholder_params<FrTypeScalar>;
using types_scalar = zk::snark::detail::placeholder_policy<FrType, params_scalar>;

typedef zk::commitments::list_polynomial_commitment<FrType,
                                                typename params_scalar::commitment_params_type>
    commitment_scheme_witness_type_scalar;
typedef zk::commitments::list_polynomial_commitment<FrType,
                                                typename params_scalar::commitment_params_type>
    commitment_scheme_permutation_type_scalar;
typedef zk::commitments::list_polynomial_commitment<FrType,
                                                typename params_scalar::commitment_params_type>
    commitment_scheme_quotient_type_scalar;
typedef zk::commitments::list_polynomial_commitment<FrType,
                                                typename params_scalar::commitment_params_type>
    commitment_scheme_public_input_type_scalar;

using proof_type_scalar = zk::snark::placeholder_proof<FrType, commitment_scheme_witness_type_scalar,
        commitment_scheme_permutation_type_scalar, commitment_scheme_quotient_type_scalar,
        commitment_scheme_public_input_type_scalar>;

using proof_generator_result_type_scalar = proof_generator_result_type<FrType,
        ArithmetizationParamsScalar, proof_type_scalar>;

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PICKLES_VERIFIER_PROOF_TYPES_HPP