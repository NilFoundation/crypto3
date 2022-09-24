//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_CONSTRAINTS_INDEX_TERMS_INSTANCES_RECURSION_TEST_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_CONSTRAINTS_INDEX_TERMS_INSTANCES_RECURSION_TEST_HPP

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/rpn_expression.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/index_term_type.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/rpn_string_literal.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/alpha_argument_type.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // index terms for ec test
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/tests/recursion.rs#L15
                template<typename ArithmetizationType>
                class index_terms_scalars_list_chacha_test;

                template<typename BlueprintFieldType, 
                         typename ArithmetizationParams>
                class index_terms_scalars_list_chacha_test<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    constexpr static const std::array<std::size_t, 4> argument_types = {
                        argument_type::Generic,
                        argument_type::Permutation,
                        argument_type::Generic,
                        argument_type::Permutation,
                    };

                    constexpr static const std::array<std::pair<std::size_t, std::size_t>, 4> arguments_values = {
                        std::make_pair(0, 21),
                        std::make_pair(21, 3),
                        std::make_pair(0, 21),
                        std::make_pair(21, 3),
                    };

                    public: 

                    static std::pair<std::size_t, std::size_t> alpha_map(argument_type arg) {
                        for (std::size_t i = 0; i < argument_types.size(); ++i) {
                            if (arg == argument_types[i]) {
                                return arguments_values[i];
                            }
                        }
                        assert(false);
                        return std::make_pair(0, 0);
                    }

                    constexpr static const std::size_t lookup_columns = 5;
                    constexpr static const bool lookup_runtime = false;
                    constexpr static const bool lookup_table_ids = false;
                    constexpr static const bool joint_lookup = false;

                    constexpr static const bool poseidon_gate = false;
                    constexpr static const bool ec_arithmetic_gates = true;
                    constexpr static const bool generic_gate = false;
                    constexpr static const bool chacha_gate = false;

                    constexpr static const std::size_t poseidon_gates_count = 15;
                    constexpr static const std::size_t ec_arithmetic_gates_count = 4;

                    constexpr static const std::size_t alpha_powers_n = 24;

                    constexpr static const std::array<char*, poseidon_gates_count> coefficient_str = {
                        "Cell(Variable { col: Index(Poseidon), row: Curr });Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Mul;\0",
                        "Cell(Variable { col: Index(Poseidon), row: Curr });Alpha;Pow(1);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Mul;Mul;\0",
                        "Cell(Variable { col: Index(Poseidon), row: Curr });Alpha;Pow(2);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Mul;Mul;\0",
                        "Cell(Variable { col: Index(Poseidon), row: Curr });Alpha;Pow(3);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Mul;Mul;\0",
                        "Cell(Variable { col: Index(Poseidon), row: Curr });Alpha;Pow(4);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Mul;Mul;\0",
                        "Cell(Variable { col: Index(Poseidon), row: Curr });Alpha;Pow(5);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Mul;Mul;\0",
                        "Cell(Variable { col: Index(Poseidon), row: Curr });Alpha;Pow(6);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Mul;Mul;\0",
                        "Cell(Variable { col: Index(Poseidon), row: Curr });Alpha;Pow(7);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Mul;Mul;\0",
                        "Cell(Variable { col: Index(Poseidon), row: Curr });Alpha;Pow(8);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Mul;Mul;\0",
                        "Cell(Variable { col: Index(Poseidon), row: Curr });Alpha;Pow(9);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Mul;Mul;\0",
                        "Cell(Variable { col: Index(Poseidon), row: Curr });Alpha;Pow(10);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Mul;Mul;\0",                       
                        "Cell(Variable { col: Index(Poseidon), row: Curr });Alpha;Pow(11);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Mul;Mul;\0",
                        "Cell(Variable { col: Index(Poseidon), row: Curr });Alpha;Pow(12);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Mul;Mul;\0",
                        "Cell(Variable { col: Index(Poseidon), row: Curr });Alpha;Pow(13);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Mul;Mul;\0",
                        "Cell(Variable { col: Index(Poseidon), row: Curr });Alpha;Pow(14);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Mul;Mul;\0",
                    };

                    constexpr static const char *var_base_mul_str = "Cell(Variable { col: Witness(5), row: Curr });Cell(Variable { col: Witness(6), row: Next });Cell(Variable { col: Witness(5), row: Next });Cell(Variable { col: Witness(4), row: Next });Cell(Variable { col: Witness(3), row: Next });Cell(Variable { col: Witness(2), row: Next });Cell(Variable { col: Witness(4), row: Curr });Dup;Add;Add;Dup;Add;Add;Dup;Add;Add;Dup;Add;Add;Dup;Add;Add;Sub;Alpha;Pow(1);Cell(Variable { col: Witness(2), row: Next });Cell(Variable { col: Witness(2), row: Next });Mul;Cell(Variable { col: Witness(2), row: Next });Sub;Mul;Add;Alpha;Pow(2);Cell(Variable { col: Witness(2), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Sub;Cell(Variable { col: Witness(7), row: Next });Mul;Cell(Variable { col: Witness(3), row: Curr });Cell(Variable { col: Witness(2), row: Next });Cell(Variable { col: Witness(2), row: Next });Add;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Cell(Variable { col: Witness(1), row: Curr });Mul;Sub;Sub;Mul;Add;Alpha;Pow(3);Cell(Variable { col: Witness(3), row: Curr });Cell(Variable { col: Witness(3), row: Curr });Add;Cell(Variable { col: Witness(2), row: Curr });Cell(Variable { col: Witness(7), row: Next });Cell(Variable { col: Witness(7), row: Next });Mul;Store;Cell(Variable { col: Witness(2), row: Curr });Sub;Cell(Variable { col: Witness(0), row: Curr });Sub;Sub;Store;Cell(Variable { col: Witness(7), row: Next });Mul;Sub;Store;Load(2);Mul;Load(1);Load(1);Mul;Cell(Variable { col: Witness(7), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Sub;Load(0);Add;Mul;Sub;Mul;Add;Alpha;Pow(4);Cell(Variable { col: Witness(8), row: Curr });Cell(Variable { col: Witness(3), row: Curr });Add;Load(1);Mul;Cell(Variable { col: Witness(2), row: Curr });Cell(Variable { col: Witness(7), row: Curr });Sub;Load(2);Mul;Sub;Mul;Add;Alpha;Pow(5);Cell(Variable { col: Witness(3), row: Next });Cell(Variable { col: Witness(3), row: Next });Mul;Cell(Variable { col: Witness(3), row: Next });Sub;Mul;Add;Alpha;Pow(6);Cell(Variable { col: Witness(7), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Sub;Cell(Variable { col: Witness(8), row: Next });Mul;Cell(Variable { col: Witness(8), row: Curr });Cell(Variable { col: Witness(3), row: Next });Cell(Variable { col: Witness(3), row: Next });Add;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Cell(Variable { col: Witness(1), row: Curr });Mul;Sub;Sub;Mul;Add;Alpha;Pow(7);Cell(Variable { col: Witness(8), row: Curr });Cell(Variable { col: Witness(8), row: Curr });Add;Cell(Variable { col: Witness(7), row: Curr });Cell(Variable { col: Witness(8), row: Next });Cell(Variable { col: Witness(8), row: Next });Mul;Store;Cell(Variable { col: Witness(7), row: Curr });Sub;Cell(Variable { col: Witness(0), row: Curr });Sub;Sub;Store;Cell(Variable { col: Witness(8), row: Next });Mul;Sub;Store;Load(5);Mul;Load(4);Load(4);Mul;Cell(Variable { col: Witness(9), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Sub;Load(3);Add;Mul;Sub;Mul;Add;Alpha;Pow(8);Cell(Variable { col: Witness(10), row: Curr });Cell(Variable { col: Witness(8), row: Curr });Add;Load(4);Mul;Cell(Variable { col: Witness(7), row: Curr });Cell(Variable { col: Witness(9), row: Curr });Sub;Load(5);Mul;Sub;Mul;Add;Alpha;Pow(9);Cell(Variable { col: Witness(4), row: Next });Cell(Variable { col: Witness(4), row: Next });Mul;Cell(Variable { col: Witness(4), row: Next });Sub;Mul;Add;Alpha;Pow(10);Cell(Variable { col: Witness(9), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Sub;Cell(Variable { col: Witness(9), row: Next });Mul;Cell(Variable { col: Witness(10), row: Curr });Cell(Variable { col: Witness(4), row: Next });Cell(Variable { col: Witness(4), row: Next });Add;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Cell(Variable { col: Witness(1), row: Curr });Mul;Sub;Sub;Mul;Add;Alpha;Pow(11);Cell(Variable { col: Witness(10), row: Curr });Cell(Variable { col: Witness(10), row: Curr });Add;Cell(Variable { col: Witness(9), row: Curr });Cell(Variable { col: Witness(9), row: Next });Cell(Variable { col: Witness(9), row: Next });Mul;Store;Cell(Variable { col: Witness(9), row: Curr });Sub;Cell(Variable { col: Witness(0), row: Curr });Sub;Sub;Store;Cell(Variable { col: Witness(9), row: Next });Mul;Sub;Store;Load(8);Mul;Load(7);Load(7);Mul;Cell(Variable { col: Witness(11), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Sub;Load(6);Add;Mul;Sub;Mul;Add;Alpha;Pow(12);Cell(Variable { col: Witness(12), row: Curr });Cell(Variable { col: Witness(10), row: Curr });Add;Load(7);Mul;Cell(Variable { col: Witness(9), row: Curr });Cell(Variable { col: Witness(11), row: Curr });Sub;Load(8);Mul;Sub;Mul;Add;Alpha;Pow(13);Cell(Variable { col: Witness(5), row: Next });Cell(Variable { col: Witness(5), row: Next });Mul;Cell(Variable { col: Witness(5), row: Next });Sub;Mul;Add;Alpha;Pow(14);Cell(Variable { col: Witness(11), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Sub;Cell(Variable { col: Witness(10), row: Next });Mul;Cell(Variable { col: Witness(12), row: Curr });Cell(Variable { col: Witness(5), row: Next });Cell(Variable { col: Witness(5), row: Next });Add;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Cell(Variable { col: Witness(1), row: Curr });Mul;Sub;Sub;Mul;Add;Alpha;Pow(15);Cell(Variable { col: Witness(12), row: Curr });Cell(Variable { col: Witness(12), row: Curr });Add;Cell(Variable { col: Witness(11), row: Curr });Cell(Variable { col: Witness(10), row: Next });Cell(Variable { col: Witness(10), row: Next });Mul;Store;Cell(Variable { col: Witness(11), row: Curr });Sub;Cell(Variable { col: Witness(0), row: Curr });Sub;Sub;Store;Cell(Variable { col: Witness(10), row: Next });Mul;Sub;Store;Load(11);Mul;Load(10);Load(10);Mul;Cell(Variable { col: Witness(13), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Sub;Load(9);Add;Mul;Sub;Mul;Add;Alpha;Pow(16);Cell(Variable { col: Witness(14), row: Curr });Cell(Variable { col: Witness(12), row: Curr });Add;Load(10);Mul;Cell(Variable { col: Witness(11), row: Curr });Cell(Variable { col: Witness(13), row: Curr });Sub;Load(11);Mul;Sub;Mul;Add;Alpha;Pow(17);Cell(Variable { col: Witness(6), row: Next });Cell(Variable { col: Witness(6), row: Next });Mul;Cell(Variable { col: Witness(6), row: Next });Sub;Mul;Add;Alpha;Pow(18);Cell(Variable { col: Witness(13), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Sub;Cell(Variable { col: Witness(11), row: Next });Mul;Cell(Variable { col: Witness(14), row: Curr });Cell(Variable { col: Witness(6), row: Next });Cell(Variable { col: Witness(6), row: Next });Add;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Cell(Variable { col: Witness(1), row: Curr });Mul;Sub;Sub;Mul;Add;Alpha;Pow(19);Cell(Variable { col: Witness(14), row: Curr });Cell(Variable { col: Witness(14), row: Curr });Add;Cell(Variable { col: Witness(13), row: Curr });Cell(Variable { col: Witness(11), row: Next });Cell(Variable { col: Witness(11), row: Next });Mul;Store;Cell(Variable { col: Witness(13), row: Curr });Sub;Cell(Variable { col: Witness(0), row: Curr });Sub;Sub;Store;Cell(Variable { col: Witness(11), row: Next });Mul;Sub;Store;Load(14);Mul;Load(13);Load(13);Mul;Cell(Variable { col: Witness(0), row: Next });Cell(Variable { col: Witness(0), row: Curr });Sub;Load(12);Add;Mul;Sub;Mul;Add;Alpha;Pow(20);Cell(Variable { col: Witness(1), row: Next });Cell(Variable { col: Witness(14), row: Curr });Add;Load(13);Mul;Cell(Variable { col: Witness(13), row: Curr });Cell(Variable { col: Witness(0), row: Next });Sub;Load(14);Mul;Sub;Mul;Add;\0";

                    constexpr static const char *endo_mul_str = "Cell(Variable { col: Witness(11), row: Curr });Dup;Mul;Cell(Variable { col: Witness(11), row: Curr });Sub;Alpha;Pow(1);Cell(Variable { col: Witness(12), row: Curr });Dup;Mul;Cell(Variable { col: Witness(12), row: Curr });Sub;Mul;Add;Alpha;Pow(2);Cell(Variable { col: Witness(13), row: Curr });Dup;Mul;Cell(Variable { col: Witness(13), row: Curr });Sub;Mul;Add;Alpha;Pow(3);Cell(Variable { col: Witness(14), row: Curr });Dup;Mul;Cell(Variable { col: Witness(14), row: Curr });Sub;Mul;Add;Alpha;Pow(4);Literal 0000000000000000000000000000000000000000000000000000000000000001;Cell(Variable { col: Witness(11), row: Curr });EndoCoefficient;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Mul;Add;Cell(Variable { col: Witness(0), row: Curr });Mul;Store;Cell(Variable { col: Witness(4), row: Curr });Sub;Cell(Variable { col: Witness(9), row: Curr });Mul;Cell(Variable { col: Witness(12), row: Curr });Dup;Add;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Cell(Variable { col: Witness(1), row: Curr });Mul;Cell(Variable { col: Witness(5), row: Curr });Sub;Sub;Mul;Add;Alpha;Pow(5);Cell(Variable { col: Witness(4), row: Curr });Dup;Add;Cell(Variable { col: Witness(9), row: Curr });Dup;Mul;Store;Sub;Load(0);Add;Cell(Variable { col: Witness(4), row: Curr });Cell(Variable { col: Witness(7), row: Curr });Sub;Store;Cell(Variable { col: Witness(9), row: Curr });Mul;Cell(Variable { col: Witness(8), row: Curr });Cell(Variable { col: Witness(5), row: Curr });Add;Store;Add;Mul;Cell(Variable { col: Witness(5), row: Curr });Dup;Add;Load(2);Mul;Sub;Mul;Add;Alpha;Pow(6);Load(3);Dup;Mul;Load(2);Dup;Mul;Load(1);Load(0);Sub;Cell(Variable { col: Witness(7), row: Curr });Add;Mul;Sub;Mul;Add;Alpha;Pow(7);Literal 0000000000000000000000000000000000000000000000000000000000000001;Cell(Variable { col: Witness(13), row: Curr });EndoCoefficient;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Mul;Add;Cell(Variable { col: Witness(0), row: Curr });Mul;Store;Cell(Variable { col: Witness(7), row: Curr });Sub;Cell(Variable { col: Witness(10), row: Curr });Mul;Cell(Variable { col: Witness(14), row: Curr });Dup;Add;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Cell(Variable { col: Witness(1), row: Curr });Mul;Cell(Variable { col: Witness(8), row: Curr });Sub;Sub;Mul;Add;Alpha;Pow(8);Cell(Variable { col: Witness(7), row: Curr });Dup;Add;Cell(Variable { col: Witness(10), row: Curr });Dup;Mul;Store;Sub;Load(4);Add;Cell(Variable { col: Witness(7), row: Curr });Cell(Variable { col: Witness(4), row: Next });Sub;Store;Cell(Variable { col: Witness(10), row: Curr });Mul;Cell(Variable { col: Witness(5), row: Next });Cell(Variable { col: Witness(8), row: Curr });Add;Store;Add;Mul;Cell(Variable { col: Witness(8), row: Curr });Dup;Add;Load(6);Mul;Sub;Mul;Add;Alpha;Pow(9);Load(7);Dup;Mul;Load(6);Dup;Mul;Load(5);Load(4);Sub;Cell(Variable { col: Witness(4), row: Next });Add;Mul;Sub;Mul;Add;Alpha;Pow(10);Cell(Variable { col: Witness(6), row: Curr });Dup;Add;Cell(Variable { col: Witness(11), row: Curr });Add;Dup;Add;Cell(Variable { col: Witness(12), row: Curr });Add;Dup;Add;Cell(Variable { col: Witness(13), row: Curr });Add;Dup;Add;Cell(Variable { col: Witness(14), row: Curr });Add;Cell(Variable { col: Witness(6), row: Next });Sub;Mul;Add;\0";

                    constexpr static const char *complete_add_str = "Cell(Variable { col: Witness(10), row: Curr });Cell(Variable { col: Witness(2), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Sub;Store;Mul;Literal 0000000000000000000000000000000000000000000000000000000000000001;Cell(Variable { col: Witness(7), row: Curr });Sub;Sub;Alpha;Pow(1);Cell(Variable { col: Witness(7), row: Curr });Load(0);Mul;Mul;Add;Alpha;Pow(2);Cell(Variable { col: Witness(7), row: Curr });Cell(Variable { col: Witness(8), row: Curr });Dup;Add;Cell(Variable { col: Witness(1), row: Curr });Mul;Cell(Variable { col: Witness(0), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Mul;Store;Dup;Add;Sub;Load(1);Sub;Mul;Literal 0000000000000000000000000000000000000000000000000000000000000001;Cell(Variable { col: Witness(7), row: Curr });Sub;Load(0);Cell(Variable { col: Witness(8), row: Curr });Mul;Cell(Variable { col: Witness(3), row: Curr });Cell(Variable { col: Witness(1), row: Curr });Sub;Store;Sub;Mul;Add;Mul;Add;Alpha;Pow(3);Cell(Variable { col: Witness(0), row: Curr });Cell(Variable { col: Witness(2), row: Curr });Add;Cell(Variable { col: Witness(4), row: Curr });Add;Cell(Variable { col: Witness(8), row: Curr });Cell(Variable { col: Witness(8), row: Curr });Mul;Sub;Mul;Add;Alpha;Pow(4);Cell(Variable { col: Witness(8), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Cell(Variable { col: Witness(4), row: Curr });Sub;Mul;Cell(Variable { col: Witness(1), row: Curr });Sub;Cell(Variable { col: Witness(5), row: Curr });Sub;Mul;Add;Alpha;Pow(5);Load(2);Cell(Variable { col: Witness(7), row: Curr });Cell(Variable { col: Witness(6), row: Curr });Sub;Mul;Mul;Add;Alpha;Pow(6);Load(2);Cell(Variable { col: Witness(9), row: Curr });Mul;Cell(Variable { col: Witness(6), row: Curr });Sub;Mul;Add;\0";

                    constexpr static const char *endo_mul_scalar_str = "Cell(Variable { col: Witness(0), row: Curr });Dup;Add;Dup;Add;Cell(Variable { col: Witness(6), row: Curr });Add;Dup;Add;Dup;Add;Cell(Variable { col: Witness(7), row: Curr });Add;Dup;Add;Dup;Add;Cell(Variable { col: Witness(8), row: Curr });Add;Dup;Add;Dup;Add;Cell(Variable { col: Witness(9), row: Curr });Add;Dup;Add;Dup;Add;Cell(Variable { col: Witness(10), row: Curr });Add;Dup;Add;Dup;Add;Cell(Variable { col: Witness(11), row: Curr });Add;Dup;Add;Dup;Add;Cell(Variable { col: Witness(12), row: Curr });Add;Dup;Add;Dup;Add;Cell(Variable { col: Witness(13), row: Curr });Add;Cell(Variable { col: Witness(1), row: Curr });Sub;Alpha;Pow(1);Cell(Variable { col: Witness(2), row: Curr });Dup;Add;Literal 1555555555555555555555555555555560C232FEADC45309330F104F00000001;Cell(Variable { col: Witness(6), row: Curr });Mul;Literal 2000000000000000000000000000000011234C7E04A67C8DCC9698767FFFFFFE;Add;Cell(Variable { col: Witness(6), row: Curr });Mul;Literal 0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB061197F56E229849987882780000002;Add;Cell(Variable { col: Witness(6), row: Curr });Mul;Store;Add;Dup;Add;Literal 1555555555555555555555555555555560C232FEADC45309330F104F00000001;Cell(Variable { col: Witness(7), row: Curr });Mul;Literal 2000000000000000000000000000000011234C7E04A67C8DCC9698767FFFFFFE;Add;Cell(Variable { col: Witness(7), row: Curr });Mul;Literal 0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB061197F56E229849987882780000002;Add;Cell(Variable { col: Witness(7), row: Curr });Mul;Store;Add;Dup;Add;Literal 1555555555555555555555555555555560C232FEADC45309330F104F00000001;Cell(Variable { col: Witness(8), row: Curr });Mul;Literal 2000000000000000000000000000000011234C7E04A67C8DCC9698767FFFFFFE;Add;Cell(Variable { col: Witness(8), row: Curr });Mul;Literal 0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB061197F56E229849987882780000002;Add;Cell(Variable { col: Witness(8), row: Curr });Mul;Store;Add;Dup;Add;Literal 1555555555555555555555555555555560C232FEADC45309330F104F00000001;Cell(Variable { col: Witness(9), row: Curr });Mul;Literal 2000000000000000000000000000000011234C7E04A67C8DCC9698767FFFFFFE;Add;Cell(Variable { col: Witness(9), row: Curr });Mul;Literal 0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB061197F56E229849987882780000002;Add;Cell(Variable { col: Witness(9), row: Curr });Mul;Store;Add;Dup;Add;Literal 1555555555555555555555555555555560C232FEADC45309330F104F00000001;Cell(Variable { col: Witness(10), row: Curr });Mul;Literal 2000000000000000000000000000000011234C7E04A67C8DCC9698767FFFFFFE;Add;Cell(Variable { col: Witness(10), row: Curr });Mul;Literal 0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB061197F56E229849987882780000002;Add;Cell(Variable { col: Witness(10), row: Curr });Mul;Store;Add;Dup;Add;Literal 1555555555555555555555555555555560C232FEADC45309330F104F00000001;Cell(Variable { col: Witness(11), row: Curr });Mul;Literal 2000000000000000000000000000000011234C7E04A67C8DCC9698767FFFFFFE;Add;Cell(Variable { col: Witness(11), row: Curr });Mul;Literal 0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB061197F56E229849987882780000002;Add;Cell(Variable { col: Witness(11), row: Curr });Mul;Store;Add;Dup;Add;Literal 1555555555555555555555555555555560C232FEADC45309330F104F00000001;Cell(Variable { col: Witness(12), row: Curr });Mul;Literal 2000000000000000000000000000000011234C7E04A67C8DCC9698767FFFFFFE;Add;Cell(Variable { col: Witness(12), row: Curr });Mul;Literal 0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB061197F56E229849987882780000002;Add;Cell(Variable { col: Witness(12), row: Curr });Mul;Store;Add;Dup;Add;Literal 1555555555555555555555555555555560C232FEADC45309330F104F00000001;Cell(Variable { col: Witness(13), row: Curr });Mul;Literal 2000000000000000000000000000000011234C7E04A67C8DCC9698767FFFFFFE;Add;Cell(Variable { col: Witness(13), row: Curr });Mul;Literal 0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB061197F56E229849987882780000002;Add;Cell(Variable { col: Witness(13), row: Curr });Mul;Store;Add;Cell(Variable { col: Witness(4), row: Curr });Sub;Mul;Add;Alpha;Pow(2);Cell(Variable { col: Witness(3), row: Curr });Dup;Add;Load(0);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Cell(Variable { col: Witness(6), row: Curr });Mul;Literal 0000000000000000000000000000000000000000000000000000000000000003;Add;Cell(Variable { col: Witness(6), row: Curr });Mul;Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Add;Add;Add;Dup;Add;Load(1);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Cell(Variable { col: Witness(7), row: Curr });Mul;Literal 0000000000000000000000000000000000000000000000000000000000000003;Add;Cell(Variable { col: Witness(7), row: Curr });Mul;Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Add;Add;Add;Dup;Add;Load(2);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Cell(Variable { col: Witness(8), row: Curr });Mul;Literal 0000000000000000000000000000000000000000000000000000000000000003;Add;Cell(Variable { col: Witness(8), row: Curr });Mul;Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Add;Add;Add;Dup;Add;Load(3);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Cell(Variable { col: Witness(9), row: Curr });Mul;Literal 0000000000000000000000000000000000000000000000000000000000000003;Add;Cell(Variable { col: Witness(9), row: Curr });Mul;Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Add;Add;Add;Dup;Add;Load(4);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Cell(Variable { col: Witness(10), row: Curr });Mul;Literal 0000000000000000000000000000000000000000000000000000000000000003;Add;Cell(Variable { col: Witness(10), row: Curr });Mul;Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Add;Add;Add;Dup;Add;Load(5);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Cell(Variable { col: Witness(11), row: Curr });Mul;Literal 0000000000000000000000000000000000000000000000000000000000000003;Add;Cell(Variable { col: Witness(11), row: Curr });Mul;Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Add;Add;Add;Dup;Add;Load(6);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Cell(Variable { col: Witness(12), row: Curr });Mul;Literal 0000000000000000000000000000000000000000000000000000000000000003;Add;Cell(Variable { col: Witness(12), row: Curr });Mul;Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Add;Add;Add;Dup;Add;Load(7);Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Cell(Variable { col: Witness(13), row: Curr });Mul;Literal 0000000000000000000000000000000000000000000000000000000000000003;Add;Cell(Variable { col: Witness(13), row: Curr });Mul;Literal 40000000000000000000000000000000224698FC094CF91B992D30ED00000000;Add;Add;Add;Cell(Variable { col: Witness(5), row: Curr });Sub;Mul;Add;Alpha;Pow(3);Cell(Variable { col: Witness(6), row: Curr });Literal 40000000000000000000000000000000224698FC094CF91B992D30ECFFFFFFFB;Add;Cell(Variable { col: Witness(6), row: Curr });Mul;Literal 000000000000000000000000000000000000000000000000000000000000000B;Add;Cell(Variable { col: Witness(6), row: Curr });Mul;Literal 40000000000000000000000000000000224698FC094CF91B992D30ECFFFFFFFB;Add;Cell(Variable { col: Witness(6), row: Curr });Mul;Mul;Add;Alpha;Pow(4);Cell(Variable { col: Witness(7), row: Curr });Literal 40000000000000000000000000000000224698FC094CF91B992D30ECFFFFFFFB;Add;Cell(Variable { col: Witness(7), row: Curr });Mul;Literal 000000000000000000000000000000000000000000000000000000000000000B;Add;Cell(Variable { col: Witness(7), row: Curr });Mul;Literal 40000000000000000000000000000000224698FC094CF91B992D30ECFFFFFFFB;Add;Cell(Variable { col: Witness(7), row: Curr });Mul;Mul;Add;Alpha;Pow(5);Cell(Variable { col: Witness(8), row: Curr });Literal 40000000000000000000000000000000224698FC094CF91B992D30ECFFFFFFFB;Add;Cell(Variable { col: Witness(8), row: Curr });Mul;Literal 000000000000000000000000000000000000000000000000000000000000000B;Add;Cell(Variable { col: Witness(8), row: Curr });Mul;Literal 40000000000000000000000000000000224698FC094CF91B992D30ECFFFFFFFB;Add;Cell(Variable { col: Witness(8), row: Curr });Mul;Mul;Add;Alpha;Pow(6);Cell(Variable { col: Witness(9), row: Curr });Literal 40000000000000000000000000000000224698FC094CF91B992D30ECFFFFFFFB;Add;Cell(Variable { col: Witness(9), row: Curr });Mul;Literal 000000000000000000000000000000000000000000000000000000000000000B;Add;Cell(Variable { col: Witness(9), row: Curr });Mul;Literal 40000000000000000000000000000000224698FC094CF91B992D30ECFFFFFFFB;Add;Cell(Variable { col: Witness(9), row: Curr });Mul;Mul;Add;Alpha;Pow(7);Cell(Variable { col: Witness(10), row: Curr });Literal 40000000000000000000000000000000224698FC094CF91B992D30ECFFFFFFFB;Add;Cell(Variable { col: Witness(10), row: Curr });Mul;Literal 000000000000000000000000000000000000000000000000000000000000000B;Add;Cell(Variable { col: Witness(10), row: Curr });Mul;Literal 40000000000000000000000000000000224698FC094CF91B992D30ECFFFFFFFB;Add;Cell(Variable { col: Witness(10), row: Curr });Mul;Mul;Add;Alpha;Pow(8);Cell(Variable { col: Witness(11), row: Curr });Literal 40000000000000000000000000000000224698FC094CF91B992D30ECFFFFFFFB;Add;Cell(Variable { col: Witness(11), row: Curr });Mul;Literal 000000000000000000000000000000000000000000000000000000000000000B;Add;Cell(Variable { col: Witness(11), row: Curr });Mul;Literal 40000000000000000000000000000000224698FC094CF91B992D30ECFFFFFFFB;Add;Cell(Variable { col: Witness(11), row: Curr });Mul;Mul;Add;Alpha;Pow(9);Cell(Variable { col: Witness(12), row: Curr });Literal 40000000000000000000000000000000224698FC094CF91B992D30ECFFFFFFFB;Add;Cell(Variable { col: Witness(12), row: Curr });Mul;Literal 000000000000000000000000000000000000000000000000000000000000000B;Add;Cell(Variable { col: Witness(12), row: Curr });Mul;Literal 40000000000000000000000000000000224698FC094CF91B992D30ECFFFFFFFB;Add;Cell(Variable { col: Witness(12), row: Curr });Mul;Mul;Add;Alpha;Pow(10);Cell(Variable { col: Witness(13), row: Curr });Literal 40000000000000000000000000000000224698FC094CF91B992D30ECFFFFFFFB;Add;Cell(Variable { col: Witness(13), row: Curr });Mul;Literal 000000000000000000000000000000000000000000000000000000000000000B;Add;Cell(Variable { col: Witness(13), row: Curr });Mul;Literal 40000000000000000000000000000000224698FC094CF91B992D30ECFFFFFFFB;Add;Cell(Variable { col: Witness(13), row: Curr });Mul;Mul;Add;\0";

                    constexpr static const char *constant_term_str = "Cell(Variable { col: Index(Poseidon), row: Curr });Cell(Variable { col: Witness(6), row: Curr });Mds { row: 0, col: 0 };Cell(Variable { col: Witness(0), row: Curr });Pow(7);Store;Mul;Mds { row: 0, col: 1 };Cell(Variable { col: Witness(1), row: Curr });Pow(7);Store;Mul;Add;Mds { row: 0, col: 2 };Cell(Variable { col: Witness(2), row: Curr });Pow(7);Store;Mul;Add;Sub;Alpha;Pow(1);Cell(Variable { col: Witness(7), row: Curr });Mds { row: 1, col: 0 };Load(0);Mul;Mds { row: 1, col: 1 };Load(1);Mul;Add;Mds { row: 1, col: 2 };Load(2);Mul;Add;Sub;Mul;Add;Alpha;Pow(2);Cell(Variable { col: Witness(8), row: Curr });Mds { row: 2, col: 0 };Load(0);Mul;Mds { row: 2, col: 1 };Load(1);Mul;Add;Mds { row: 2, col: 2 };Load(2);Mul;Add;Sub;Mul;Add;Alpha;Pow(3);Cell(Variable { col: Witness(9), row: Curr });Mds { row: 0, col: 0 };Cell(Variable { col: Witness(6), row: Curr });Pow(7);Store;Mul;Mds { row: 0, col: 1 };Cell(Variable { col: Witness(7), row: Curr });Pow(7);Store;Mul;Add;Mds { row: 0, col: 2 };Cell(Variable { col: Witness(8), row: Curr });Pow(7);Store;Mul;Add;Sub;Mul;Add;Alpha;Pow(4);Cell(Variable { col: Witness(10), row: Curr });Mds { row: 1, col: 0 };Load(3);Mul;Mds { row: 1, col: 1 };Load(4);Mul;Add;Mds { row: 1, col: 2 };Load(5);Mul;Add;Sub;Mul;Add;Alpha;Pow(5);Cell(Variable { col: Witness(11), row: Curr });Mds { row: 2, col: 0 };Load(3);Mul;Mds { row: 2, col: 1 };Load(4);Mul;Add;Mds { row: 2, col: 2 };Load(5);Mul;Add;Sub;Mul;Add;Alpha;Pow(6);Cell(Variable { col: Witness(12), row: Curr });Mds { row: 0, col: 0 };Cell(Variable { col: Witness(9), row: Curr });Pow(7);Store;Mul;Mds { row: 0, col: 1 };Cell(Variable { col: Witness(10), row: Curr });Pow(7);Store;Mul;Add;Mds { row: 0, col: 2 };Cell(Variable { col: Witness(11), row: Curr });Pow(7);Store;Mul;Add;Sub;Mul;Add;Alpha;Pow(7);Cell(Variable { col: Witness(13), row: Curr });Mds { row: 1, col: 0 };Load(6);Mul;Mds { row: 1, col: 1 };Load(7);Mul;Add;Mds { row: 1, col: 2 };Load(8);Mul;Add;Sub;Mul;Add;Alpha;Pow(8);Cell(Variable { col: Witness(14), row: Curr });Mds { row: 2, col: 0 };Load(6);Mul;Mds { row: 2, col: 1 };Load(7);Mul;Add;Mds { row: 2, col: 2 };Load(8);Mul;Add;Sub;Mul;Add;Alpha;Pow(9);Cell(Variable { col: Witness(3), row: Curr });Mds { row: 0, col: 0 };Cell(Variable { col: Witness(12), row: Curr });Pow(7);Store;Mul;Mds { row: 0, col: 1 };Cell(Variable { col: Witness(13), row: Curr });Pow(7);Store;Mul;Add;Mds { row: 0, col: 2 };Cell(Variable { col: Witness(14), row: Curr });Pow(7);Store;Mul;Add;Sub;Mul;Add;Alpha;Pow(10);Cell(Variable { col: Witness(4), row: Curr });Mds { row: 1, col: 0 };Load(9);Mul;Mds { row: 1, col: 1 };Load(10);Mul;Add;Mds { row: 1, col: 2 };Load(11);Mul;Add;Sub;Mul;Add;Alpha;Pow(11);Cell(Variable { col: Witness(5), row: Curr });Mds { row: 2, col: 0 };Load(9);Mul;Mds { row: 2, col: 1 };Load(10);Mul;Add;Mds { row: 2, col: 2 };Load(11);Mul;Add;Sub;Mul;Add;Alpha;Pow(12);Cell(Variable { col: Witness(0), row: Next });Mds { row: 0, col: 0 };Cell(Variable { col: Witness(3), row: Curr });Pow(7);Store;Mul;Mds { row: 0, col: 1 };Cell(Variable { col: Witness(4), row: Curr });Pow(7);Store;Mul;Add;Mds { row: 0, col: 2 };Cell(Variable { col: Witness(5), row: Curr });Pow(7);Store;Mul;Add;Sub;Mul;Add;Alpha;Pow(13);Cell(Variable { col: Witness(1), row: Next });Mds { row: 1, col: 0 };Load(12);Mul;Mds { row: 1, col: 1 };Load(13);Mul;Add;Mds { row: 1, col: 2 };Load(14);Mul;Add;Sub;Mul;Add;Alpha;Pow(14);Cell(Variable { col: Witness(2), row: Next });Mds { row: 2, col: 0 };Load(12);Mul;Mds { row: 2, col: 1 };Load(13);Mul;Add;Mds { row: 2, col: 2 };Load(14);Mul;Add;Sub;Mul;Add;Mul;\0";

                private:

                    constexpr static const std::array<std::size_t, poseidon_gates_count> 
                        coefficient_array_size = {
                            count_delimiters(coefficient_str[0]), count_delimiters(coefficient_str[1]),
                            count_delimiters(coefficient_str[2]), count_delimiters(coefficient_str[3]),
                            count_delimiters(coefficient_str[4]), count_delimiters(coefficient_str[5]),
                            count_delimiters(coefficient_str[6]), count_delimiters(coefficient_str[7]),
                            count_delimiters(coefficient_str[8]), count_delimiters(coefficient_str[9]),
                            count_delimiters(coefficient_str[10]), count_delimiters(coefficient_str[11]),
                            count_delimiters(coefficient_str[12]), count_delimiters(coefficient_str[13]),
                            count_delimiters(coefficient_str[14])
                    };

                    constexpr static const std::size_t var_base_mul_array_size = count_delimiters(var_base_mul_str);

                    constexpr static const std::size_t endo_mul_array_size = count_delimiters(endo_mul_str);

                    constexpr static const std::size_t complete_add_array_size = count_delimiters(complete_add_str);

                    constexpr static const std::size_t endo_mul_scalar_array_size = count_delimiters(endo_mul_scalar_str);

                    constexpr static const std::size_t constatnt_term_array_size = count_delimiters(constant_term_str);

                    constexpr static const std::array<std::size_t, poseidon_gates_count> 
                        coefficient_rows = {
                            rpn_component_rows<coefficient_array_size[0], ArithmetizationType>(coefficient_str[0]),
                            rpn_component_rows<coefficient_array_size[1], ArithmetizationType>(coefficient_str[1]),
                            rpn_component_rows<coefficient_array_size[2], ArithmetizationType>(coefficient_str[2]),
                            rpn_component_rows<coefficient_array_size[3], ArithmetizationType>(coefficient_str[3]),
                            rpn_component_rows<coefficient_array_size[4], ArithmetizationType>(coefficient_str[4]),
                            rpn_component_rows<coefficient_array_size[5], ArithmetizationType>(coefficient_str[5]),
                            rpn_component_rows<coefficient_array_size[6], ArithmetizationType>(coefficient_str[6]),
                            rpn_component_rows<coefficient_array_size[7], ArithmetizationType>(coefficient_str[7]),
                            rpn_component_rows<coefficient_array_size[8], ArithmetizationType>(coefficient_str[8]),
                            rpn_component_rows<coefficient_array_size[9], ArithmetizationType>(coefficient_str[9]),
                            rpn_component_rows<coefficient_array_size[10], ArithmetizationType>(coefficient_str[10]),
                            rpn_component_rows<coefficient_array_size[11], ArithmetizationType>(coefficient_str[11]),
                            rpn_component_rows<coefficient_array_size[12], ArithmetizationType>(coefficient_str[12]),
                            rpn_component_rows<coefficient_array_size[13], ArithmetizationType>(coefficient_str[13]),
                            rpn_component_rows<coefficient_array_size[14], ArithmetizationType>(coefficient_str[14])
                        };

                    constexpr static const std::size_t var_base_mul_rows = 
                        rpn_component_rows<var_base_mul_array_size, ArithmetizationType>(var_base_mul_str);

                    constexpr static const std::size_t endo_mul_rows = 
                        rpn_component_rows<endo_mul_array_size, ArithmetizationType>(endo_mul_str);

                    constexpr static const std::size_t complete_add_rows = 
                        rpn_component_rows<complete_add_array_size, ArithmetizationType>(complete_add_str);

                    constexpr static const std::size_t endo_mul_scalar_rows = 
                        rpn_component_rows<endo_mul_scalar_array_size, ArithmetizationType>(endo_mul_scalar_str);

                    constexpr static const std::size_t constant_term_rows = 
                        rpn_component_rows<constatnt_term_array_size, ArithmetizationType>(constant_term_str);

                    constexpr static const std::size_t lookup_gate_rows = 
                        rpn_component_rows<lookup_gate_array_size, ArithmetizationType>(lookup_gate_str);

                    public: 
                    
                    constexpr static const std::size_t size = 19;
                    constexpr static const std::array<index_term_type, size> terms = {{
                        {column_type::Coefficient, 0, coefficient_str[0], coefficient_rows[0]},
                        {column_type::Coefficient, 1, coefficient_str[1], coefficient_rows[1]},
                        {column_type::Coefficient, 2, coefficient_str[2], coefficient_rows[2]},
                        {column_type::Coefficient, 3, coefficient_str[3], coefficient_rows[3]},
                        {column_type::Coefficient, 4, coefficient_str[4], coefficient_rows[4]},
                        {column_type::Coefficient, 5, coefficient_str[5], coefficient_rows[5]},
                        {column_type::Coefficient, 6, coefficient_str[6], coefficient_rows[6]},
                        {column_type::Coefficient, 7, coefficient_str[7], coefficient_rows[7]},
                        {column_type::Coefficient, 8, coefficient_str[8], coefficient_rows[8]},
                        {column_type::Coefficient, 9, coefficient_str[9], coefficient_rows[9]},
                        {column_type::Coefficient, 10, coefficient_str[10], coefficient_rows[10]},
                        {column_type::Coefficient, 11, coefficient_str[11], coefficient_rows[11]},
                        {column_type::Coefficient, 12, coefficient_str[12], coefficient_rows[12]},
                        {column_type::Coefficient, 13, coefficient_str[13], coefficient_rows[13]},
                        {column_type::Coefficient, 14, coefficient_str[14], coefficient_rows[14]},
                        {column_type::VarBaseMul, 0, var_base_mul_str, var_base_mul_rows},
                        {column_type::EndoMul, 0, endo_mul_str, endo_mul_rows},
                        {column_type::EndoMulScalar, 0, endo_mul_scalar_str, endo_mul_scalar_rows},
                        {column_type::CompleteAdd, 0, complete_add_str, complete_add_rows},
                    }};
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_CONSTRAINTS_INDEX_TERMS_INSTANCES_LOOKUP_TEST_HPP