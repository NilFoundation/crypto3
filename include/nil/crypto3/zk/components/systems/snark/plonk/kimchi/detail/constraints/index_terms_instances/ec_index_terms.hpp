//---------------------------------------------------------------------------//
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_EC_INDEX_TERMS_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_EC_INDEX_TERMS_HPP

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/rpn_expression.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/rpn_string_literal.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // index terms for ec test
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/tests/ec.rs#L15
                template<typename ArithmetizationType, typename KimchiParamsType,
                    std::size_t... WireIndexes>
                class index_terms_scalars_list;

                template<typename BlueprintFieldType, 
                         typename ArithmetizationParams,
                         typename KimchiParamsType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8,
                         std::size_t W9,
                         std::size_t W10,
                         std::size_t W11,
                         std::size_t W12,
                         std::size_t W13,
                         std::size_t W14>
                class index_terms_scalars_list<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    KimchiParamsType,
                    W0,
                    W1,
                    W2,
                    W3,
                    W4,
                    W5,
                    W6,
                    W7,
                    W8,
                    W9,
                    W10,
                    W11,
                    W12,
                    W13,
                    W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    static const std::size_t coefficients_amount = 15;

                    public: 

                    constexpr static const std::array<char*, coefficients_amount> coefficient_str = {
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
                    
                    constexpr static const char *constatnt_term_str = "Cell(Variable { col: Index(Poseidon), row: Curr });Cell(Variable { col: Witness(6), row: Curr });Mds { row: 0, col: 0 };Cell(Variable { col: Witness(0), row: Curr });Pow(7);Store;Mul;Mds { row: 0, col: 1 };Cell(Variable { col: Witness(1), row: Curr });Pow(7);Store;Mul;Add;Mds { row: 0, col: 2 };Cell(Variable { col: Witness(2), row: Curr });Pow(7);Store;Mul;Add;Sub;Alpha;Pow(1);Cell(Variable { col: Witness(7), row: Curr });Mds { row: 1, col: 0 };Load(0);Mul;Mds { row: 1, col: 1 };Load(1);Mul;Add;Mds { row: 1, col: 2 };Load(2);Mul;Add;Sub;Mul;Add;Alpha;Pow(2);Cell(Variable { col: Witness(8), row: Curr });Mds { row: 2, col: 0 };Load(0);Mul;Mds { row: 2, col: 1 };Load(1);Mul;Add;Mds { row: 2, col: 2 };Load(2);Mul;Add;Sub;Mul;Add;Alpha;Pow(3);Cell(Variable { col: Witness(9), row: Curr });Mds { row: 0, col: 0 };Cell(Variable { col: Witness(6), row: Curr });Pow(7);Store;Mul;Mds { row: 0, col: 1 };Cell(Variable { col: Witness(7), row: Curr });Pow(7);Store;Mul;Add;Mds { row: 0, col: 2 };Cell(Variable { col: Witness(8), row: Curr });Pow(7);Store;Mul;Add;Sub;Mul;Add;Alpha;Pow(4);Cell(Variable { col: Witness(10), row: Curr });Mds { row: 1, col: 0 };Load(3);Mul;Mds { row: 1, col: 1 };Load(4);Mul;Add;Mds { row: 1, col: 2 };Load(5);Mul;Add;Sub;Mul;Add;Alpha;Pow(5);Cell(Variable { col: Witness(11), row: Curr });Mds { row: 2, col: 0 };Load(3);Mul;Mds { row: 2, col: 1 };Load(4);Mul;Add;Mds { row: 2, col: 2 };Load(5);Mul;Add;Sub;Mul;Add;Alpha;Pow(6);Cell(Variable { col: Witness(12), row: Curr });Mds { row: 0, col: 0 };Cell(Variable { col: Witness(9), row: Curr });Pow(7);Store;Mul;Mds { row: 0, col: 1 };Cell(Variable { col: Witness(10), row: Curr });Pow(7);Store;Mul;Add;Mds { row: 0, col: 2 };Cell(Variable { col: Witness(11), row: Curr });Pow(7);Store;Mul;Add;Sub;Mul;Add;Alpha;Pow(7);Cell(Variable { col: Witness(13), row: Curr });Mds { row: 1, col: 0 };Load(6);Mul;Mds { row: 1, col: 1 };Load(7);Mul;Add;Mds { row: 1, col: 2 };Load(8);Mul;Add;Sub;Mul;Add;Alpha;Pow(8);Cell(Variable { col: Witness(14), row: Curr });Mds { row: 2, col: 0 };Load(6);Mul;Mds { row: 2, col: 1 };Load(7);Mul;Add;Mds { row: 2, col: 2 };Load(8);Mul;Add;Sub;Mul;Add;Alpha;Pow(9);Cell(Variable { col: Witness(3), row: Curr });Mds { row: 0, col: 0 };Cell(Variable { col: Witness(12), row: Curr });Pow(7);Store;Mul;Mds { row: 0, col: 1 };Cell(Variable { col: Witness(13), row: Curr });Pow(7);Store;Mul;Add;Mds { row: 0, col: 2 };Cell(Variable { col: Witness(14), row: Curr });Pow(7);Store;Mul;Add;Sub;Mul;Add;Alpha;Pow(10);Cell(Variable { col: Witness(4), row: Curr });Mds { row: 1, col: 0 };Load(9);Mul;Mds { row: 1, col: 1 };Load(10);Mul;Add;Mds { row: 1, col: 2 };Load(11);Mul;Add;Sub;Mul;Add;Alpha;Pow(11);Cell(Variable { col: Witness(5), row: Curr });Mds { row: 2, col: 0 };Load(9);Mul;Mds { row: 2, col: 1 };Load(10);Mul;Add;Mds { row: 2, col: 2 };Load(11);Mul;Add;Sub;Mul;Add;Alpha;Pow(12);Cell(Variable { col: Witness(0), row: Next });Mds { row: 0, col: 0 };Cell(Variable { col: Witness(3), row: Curr });Pow(7);Store;Mul;Mds { row: 0, col: 1 };Cell(Variable { col: Witness(4), row: Curr });Pow(7);Store;Mul;Add;Mds { row: 0, col: 2 };Cell(Variable { col: Witness(5), row: Curr });Pow(7);Store;Mul;Add;Sub;Mul;Add;Alpha;Pow(13);Cell(Variable { col: Witness(1), row: Next });Mds { row: 1, col: 0 };Load(12);Mul;Mds { row: 1, col: 1 };Load(13);Mul;Add;Mds { row: 1, col: 2 };Load(14);Mul;Add;Sub;Mul;Add;Alpha;Pow(14);Cell(Variable { col: Witness(2), row: Next });Mds { row: 2, col: 0 };Load(12);Mul;Mds { row: 2, col: 1 };Load(13);Mul;Add;Mds { row: 2, col: 2 };Load(14);Mul;Add;Sub;Mul;Add;Mul;\0";
                
                private:

                    constexpr static const std::array<std::size_t, coefficients_amount> 
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

                    constexpr static const std::array<std::size_t, coefficients_amount> 
                        coefficient_rows = {
                            rpn_component_rows<coefficient_array_size[0], ArithmetizationType, KimchiParamsType>(coefficient_str[0]),
                            rpn_component_rows<coefficient_array_size[1], ArithmetizationType, KimchiParamsType>(coefficient_str[1]),
                            rpn_component_rows<coefficient_array_size[2], ArithmetizationType, KimchiParamsType>(coefficient_str[2]),
                            rpn_component_rows<coefficient_array_size[3], ArithmetizationType, KimchiParamsType>(coefficient_str[3]),
                            rpn_component_rows<coefficient_array_size[4], ArithmetizationType, KimchiParamsType>(coefficient_str[4]),
                            rpn_component_rows<coefficient_array_size[5], ArithmetizationType, KimchiParamsType>(coefficient_str[5]),
                            rpn_component_rows<coefficient_array_size[6], ArithmetizationType, KimchiParamsType>(coefficient_str[6]),
                            rpn_component_rows<coefficient_array_size[7], ArithmetizationType, KimchiParamsType>(coefficient_str[7]),
                            rpn_component_rows<coefficient_array_size[8], ArithmetizationType, KimchiParamsType>(coefficient_str[8]),
                            rpn_component_rows<coefficient_array_size[9], ArithmetizationType, KimchiParamsType>(coefficient_str[9]),
                            rpn_component_rows<coefficient_array_size[10], ArithmetizationType, KimchiParamsType>(coefficient_str[10]),
                            rpn_component_rows<coefficient_array_size[11], ArithmetizationType, KimchiParamsType>(coefficient_str[11]),
                            rpn_component_rows<coefficient_array_size[12], ArithmetizationType, KimchiParamsType>(coefficient_str[12]),
                            rpn_component_rows<coefficient_array_size[13], ArithmetizationType, KimchiParamsType>(coefficient_str[13]),
                            rpn_component_rows<coefficient_array_size[14], ArithmetizationType, KimchiParamsType>(coefficient_str[14])
                        };

                    constexpr static const std::size_t var_base_mul_array_size = count_delimiters(var_base_mul_str);
                    constexpr static const std::size_t var_base_mul_rows = 
                        rpn_component_rows<var_base_mul_array_size, ArithmetizationType, KimchiParamsType>(var_base_mul_str);

                    constexpr static const std::size_t endo_mul_array_size = count_delimiters(endo_mul_str);
                    constexpr static const std::size_t endo_mul_rows = 
                        rpn_component_rows<endo_mul_array_size, ArithmetizationType, KimchiParamsType>(endo_mul_str);

                    constexpr static const std::size_t complete_add_array_size = count_delimiters(complete_add_str);
                    constexpr static const std::size_t complete_add_rows = 
                        rpn_component_rows<complete_add_array_size, ArithmetizationType, KimchiParamsType>(complete_add_str);

                    constexpr static const std::size_t endo_mul_scalar_array_size = count_delimiters(endo_mul_scalar_str);
                    constexpr static const std::size_t endo_mul_scalar_rows = 
                        rpn_component_rows<endo_mul_scalar_array_size, ArithmetizationType, KimchiParamsType>(endo_mul_scalar_str);

                    constexpr static const std::size_t constatnt_term_array_size = count_delimiters(constatnt_term_str);
                    constexpr static const std::size_t constatnt_term_rows = 
                        rpn_component_rows<constatnt_term_array_size, ArithmetizationType, KimchiParamsType>(constatnt_term_str);

                public:
                    using coefficient_0 = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        coefficient_rows[0], W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using coefficient_1 = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType,
                        coefficient_rows[1], W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    
                    using coefficient_2 = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        coefficient_rows[2], W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using coefficient_3 = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType,
                        coefficient_rows[3], W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using coefficient_4 = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType,
                        coefficient_rows[4], W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using coefficient_5 = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        coefficient_rows[5], W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    
                    using coefficient_6 = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        coefficient_rows[6], W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    
                    using coefficient_7 = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        coefficient_rows[7], W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using coefficient_8 = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        coefficient_rows[8], W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using coefficient_9 = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        coefficient_rows[9], W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using coefficient_10 = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        coefficient_rows[10], W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using coefficient_11 = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        coefficient_rows[11], W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using coefficient_12 = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        coefficient_rows[12], W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using coefficient_13 = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        coefficient_rows[13], W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using coefficient_14 = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        coefficient_rows[14], W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using var_base_mul = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        var_base_mul_rows, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                        
                    using complete_add = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        complete_add_rows, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using endo_mul = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        endo_mul_rows, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using endo_mul_scalar = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        endo_mul_scalar_rows, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using constant_term = zk::components::rpn_expression<ArithmetizationType, KimchiParamsType, 
                        constatnt_term_rows, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_EC_INDEX_TERMS_HPP