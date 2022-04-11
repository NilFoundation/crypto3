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

#define BOOST_TEST_MODULE blueprint_plonk_endo_scalar_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/oracles.hpp>

#include "test_plonk_component.hpp"
#include "proof_data.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_endo_scalar_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_unified_addition_addition) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 2;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using component_type = zk::components::oracles_scalar<ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    nil::crypto3::zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof();

    zk::components::kimchi_scalar_limbs alpha_limbs = {7388568927873460733U, 2067855711556196027U}; // 000000000000000000000000000000001CB27FD04E11D6BB6689784B2862E9FD
    zk::components::kimchi_scalar_limbs zeta_limbs = {13556945131955241727U, 14838652236930703881U}; // 00000000000000000000000000000000CDED7B9747CF6209BC23F1C50DA742FF
    //zk::components::kimchi_scalar_limbs fq_digest_limbs = {16614720608214505662U, 1222931729118221428U};
    typename BlueprintFieldType::value_type fq_digest = 0x01D4E77CCD66755BDDFDBB6E4E8D8D17A6708B9CB56654D12070BD7BF4A5B33B_cppui256;
    typename BlueprintFieldType::value_type expected_result = 0x0000000000000000000000000000000010F8B9EDA2A55474E693585D56FCD8BE_cppui256;
    std::cout<<"Expected: "<<expected_result.data<<std::endl;

    typename component_type::private_params_type private_params = {};
    typename component_type::public_params_type public_params = {alpha_limbs, zeta_limbs, fq_digest};

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (public_params, private_params);
}

BOOST_AUTO_TEST_SUITE_END()