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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_SHA256_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_SHA256_HPP

#include <nil/crypto3/zk/components/packing.hpp>
#include <nil/crypto3/zk/components/blueprint_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename TArithmetization,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class sha256;

                template<typename TBlueprintField,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8>
                class sha256<snark::plonk_constraint_system<TBlueprintField, 9>,
                                                       CurveType,
                                                       W0,
                                                       W1,
                                                       W2,
                                                       W3,
                                                       W4,
                                                       W5,
                                                       W6,
                                                       W7,
                                                       W8>
                    : public detail::
                          n_wires_helper<snark::plonk_constraint_system<TBlueprintField, 9>, 
                          W0, W1, W2, W3, W4, W5, W6, W7, W8> {

                    typedef snark::plonk_constraint_system<TBlueprintField, 9> TArithmetization;
                    typedef blueprint<TArithmetization> blueprint_type;

                    std::size_t j;

                    using n_wires_helper =
                        detail::n_wires_helper<snark::plonk_constraint_system<TBlueprintField, 9>, 
                        W0, W1, W2, W3, W4, W5, W6, W7, W8>;

                    using n_wires_helper::w;
                    enum indices { m2 = 0, m1, cur, p1, p2 };
                public:

                    sha256(blueprint_type &bp) :
                        n_wires_helper(bp){

                        j = this->bp.allocate_rows(85);
                    }

                private:

                    void generate_sigma0_gates() {

                        this->bp.add_gate(j + 0, w[0][cur] - (w[1][cur] + w[2][cur] * 2**3 + w[3][cur] * 2**7 + w[4][cur] * 2**18));
                        this->bp.add_gate(j + 0, (w[1][cur] - 7) * (w[1][cur] - 6) * (w[1][cur] - 5) * (w[1][cur] - 4) * (w[1][cur] - 3) * (w[1][cur] - 2) * (w[1][cur] - 1) * w[1][cur]);
                        this->bp.add_gate(j + 1, w[5][cur] + w[6][cur] * 4**14 + w[7][cur] * 4**28 + w[8][cur] * 2**30 - 
                            (w[2][cur] + w[3][cur] * 4**4 + w[4][cur] * 4**15 + w[3][cur] + w[4][cur] * 4**11 + 
                            w[7][m1] * 4**25 + w[2][cur] * 4**28 + w[4][cur] + w[7][m1] * 4**14+ w[2][cur] * 4**17 + 
                            w[3][cur] * 4**21));
                        this->bp.add_gate(j + 1, (w[7][cur] - 3) * (w[7][cur] - 2) * (w[7][cur] - 1) * w[7][cur]);
                        this->bp.add_gate(j + 1, (w[8][cur] - 3) * (w[8][cur] - 2) * (w[8][cur] - 1) * w[8][cur]);
                    }

                    void generate_sigma1_gates() {

                        this->bp.add_gate(j+3, w[0][cur] - (w[1][cur] + w[2][cur] * 2*10 + w[3][cur] * 2*17 + w[4][cur] * 2*19));
                        this->bp.add_gate(j+3, (w[3][cur] - 3) * (w[3][cur] - 2) * (w[3][cur] - 1) * w[3][cur]);
                        this->bp.add_gate(j+3, w[5][cur] + w[6][cur] * 4*14 + w[7][cur] * 4*28 + w[8][cur] * 2*30 -
                            (w[2][cur] + w[3][cur] * 4*7 + w[4][cur] * 4*9 + w[3][cur] + w[4][cur] * 4*2 + 
                             w[1][cur] * 4*15 + w[2][cur] * 4*25 + w[4][cur] + w[1][cur] * 4*13+ w[2][cur] * 4*23 + 
                             w[3][cur] * 4*30));
                        this->bp.add_gate(j+3, (w[7][cur] - 3) * (w[7][cur] - 2) * (w[7][cur] - 1) * w[7][cur]);
                        this->bp.add_gate(j+3, (w[8][cur] - 3) * (w[8][cur] - 2) * (w[8][cur] - 1) * w[8][cur]);
                    }

                    void generate_Sigma0_gates() {

                        this->bp.add_gate(j + 7, w[0][cur] - (w[2][cur] + w[3][cur] * 2**2 + w[4][cur] * 2**13 + w[5][cur] * 2**22));
                        this->bp.add_gate(j + 5, w[0][cur] - (w[2][p1] + w[3][p1] * 4**2 + w[4][p1] * 4**13 + w[5][p1] * 4**22));
                        this->bp.add_gate(j + 6, (w[2][cur] - 3) * (w[2][cur] - 2) * (w[2][cur] - 1) * w[2][cur]);
                        this->bp.add_gate(j + 6, w[0][cur] + w[1][cur] * 4**14 + w[6][cur] * 4**28 + w[7][cur] * 2**30 -
                            (w[3][cur] + w[4][cur] * 4**11 + w[5][cur] * 4**20 + w[1][cur] * 2**30 + w[4][cur] + 
                            w[5][cur] * 4**[9] + w[2][cur] * 4**19 + w[3][cur] * 4**21 + w[5][cur] + w[2][cur] * 4**10 + 
                            w[3][cur] * 4**12 + w[4][cur] * 4**23));
                        this->bp.add_gate(j + 6, (w[6][cur] - 3) * (w[6][cur] - 2) * (w[6][cur] - 1) * w[6][cur]);
                        this->bp.add_gate(j + 6, (w[7][cur] - 3) * (w[7][cur] - 2) * (w[7][cur] - 1) * w[7][cur]);
                    }

                    void generate_Sigma1_gates() {
                        this->bp.add_gate(j + 0, w[0][cur] - (w[2][cur] + w[3][cur] * 2**[6] + w[4][cur] * 2**[11] + w[5][cur] * 2**[25]));
                        this->bp.add_gate(j + 1, w[0][cur] - (w[1][m1] + w[2][cur] * 7**[6] + w[3][cur] * 7**[11] + w[4][cur] * 7**[25]));
                        this->bp.add_gate(j + 1, w[5][cur] + w[6][cur] * 4**[14] + w[7][cur] * 4**[28] + w[8][cur] * 2**[30] - 
                            (w[2][cur] + w[3][cur] * 4**[5] + w[4][cur] * 4**[19] + w[1][m1] * 2**[26] + w[3][cur] + 
                            w[4][cur] * 4**[14] + w[1][m1] * 4**[21] + w[2][cur] * 4**[27] + w[4][cur] + w[1][m1] * 4**[7] + 
                            w[2][cur] * 4**[13] + w[3][cur] * 4**[27]));
                        this->bp.add_gate(j + 1, (w[3][cur] - 3) * (w[3][cur] - 2) * (w[3][cur] - 1) * w[3][cur]);
                        this->bp.add_gate(j + 1, (w[4][cur] - 3) * (w[4][cur] - 2) * (w[4][cur] - 1) * w[4][cur]);
                    }

                    void generate_Maj_gates() {
                        this->bp.add_gate(j + 4, w[0][cur] + w[1][cur] * 4**8 + w[2][cur] * 4*(8 * 2) + w[3][cur] * 4*(8 * 3) - 
                            (w[0][p1] + w[1][p1] + w[4][p1]));
                    }

                    void generate_Ch_gates(){
                        this->bp.add_gate(j + 2, w[0][cur] + w[1][cur] * 7**8 + w[2][cur] * 7**(8 * 2) + w[3][cur] * 7**(8 * 3) - 
                            (w[0][m1] + 2 * w[1][m1] + 3 * w[0][p1]));
                    }

                public:

                    void generate_gates() {

                        generate_sigma0_gates();
                        generate_sigma1_gates();
                        generate_Sigma0_gates();
                        generate_Sigma1_gates();
                        generate_Maj_gates();
                        generate_Ch_gates();
                    }

                    void generate_assignments() {

                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_SHA256_HPP
