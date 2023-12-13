//---------------------------------------------------------------------------//
// Copyright (c) 2023 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
// @file Declaration of interfaces for FRI verification coset generating component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FRI_COSETS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FRI_COSETS_HPP

#include <cmath>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                // compute the number of lines if we need to place o object with pl object per line
                template<typename T1, typename T2>
                T1 lfit(T1 o, T2 pl) {
                    return o/pl + (o % pl > 0);
                }
            } // namespace detail

            // Uses parameters n, omega
            // Input: x (challenge)
            // Output: vector of length n with triplets < (s,-s,b) >, where s_0 = omega^{x % 2^n}, s_{i+1} = s_i^2,
            // b = 0 or 1, showing whether the pair (s,-s) needs reordering
            // For details see https://www.notion.so/nilfoundation/FRI-cosets-generator-910475aa46e54bdc986407d178428a8a
            //

            using detail::lfit;

            template<typename ArithmetizationType, typename FieldType>
            class fri_cosets;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            class fri_cosets<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType>:
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

                static std::size_t gates_amount_internal(std::size_t witness_amount, std::size_t n, std::size_t total_bits) {
                    const std::size_t l = witness_amount / 9; // number of 9-blocks per row
                    const std::size_t last_l = n % l; // 9-blocks in transition row. If 0, no transition row exists
                    const std::size_t nineb_rows = lfit(n,l); // number of rows with 9-blocks
                    const std::size_t bits = total_bits-n;
                    const std::size_t remaining_bits = bits - ((last_l > 0)? 3*(l - last_l)-1 : 0);

                    return (nineb_rows > 1) + (nineb_rows > 2) + 1 + (remaining_bits > 0);
                }


                static std::size_t rows_amount_internal(std::size_t witness_amount,
                                                        std::size_t n,
                                                        std::size_t total_bits) {

                    std::size_t trans_9_bl_space = 9*n % witness_amount; // space occupied by 9-blocks in transition line
                    // space for 3-bit_blocks in transition line
                    std::size_t trans_line_bits = (trans_9_bl_space > 0) ? (witness_amount - trans_9_bl_space)/3 - 1 : 0;

                    return lfit(9*n, witness_amount)
                           + lfit(total_bits-n - trans_line_bits, witness_amount/3 - 1 ) // 3-bit_blocks in all cols but the 1st three
                           + 1; // the row for storing 0
                }

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                class gate_manifest_type : public component_gate_manifest {

                    std::array<std::size_t,5> gates_footprint(std::size_t WA, std::size_t N, std::size_t TB) const {
                        std::size_t l = WA / 9;
                        std::size_t last_l = N % l;
                        std::size_t nineb_rows = lfit(N,l);
                        std::size_t bits = TB-N;

                        std::size_t remaining_bits = bits - ((last_l > 0)? 3*(l - last_l)-1 : 0);

                        return { WA, last_l, (nineb_rows > 1), (nineb_rows > 2), (remaining_bits > 0) };
                    }

                public:
                    std::size_t witness_amount;
                    std::size_t n;
                    const std::size_t total_bits = BlueprintFieldType::modulus_bits;

                    gate_manifest_type(std::size_t witness_amount_, std::size_t n_)
                        : witness_amount(witness_amount_), n(n_) {}

                    std::uint32_t gates_amount() const override {
                        return fri_cosets::gates_amount_internal(witness_amount,n,total_bits);
                    }

                    bool operator<(const component_gate_manifest *other) const override {
                        std::size_t o_witness_amount = dynamic_cast<const gate_manifest_type*>(other)->witness_amount;
                        std::size_t o_n = dynamic_cast<const gate_manifest_type*>(other)->n;

                        std::array<std::size_t,5> gates = gates_footprint(witness_amount,n,total_bits);
                        std::array<std::size_t,5> o_gates = gates_footprint(o_witness_amount,o_n,total_bits);
                        return (gates < o_gates);
                    }
                };

                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                using manifest_type = plonk_component_manifest;

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       std::size_t n, value_type omega) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount,n));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(
                            new manifest_range_param(9,2295,9) // 2295 = 9*255, because we expect n <= 255
                        ),
                        true // constant column required
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount,
                                                             std::size_t n, value_type omega) {
                    return rows_amount_internal(witness_amount,n,BlueprintFieldType::modulus_bits);
                }
                // Initialized by constructor
                std::size_t n;
                value_type omega;
                // aliases and derivatives
                const std::size_t total_bits = BlueprintFieldType::modulus_bits; // the total amount of bits for storing a field element

                const std::size_t WA = this->witness_amount();
                const std::size_t nine_bl_per_line = WA / 9; // 9-blocks per line
                const std::size_t bits_blocks_count = total_bits-n; // number of bit blocks

                const std::size_t rows_amount = rows_amount_internal(this->witness_amount(), n, total_bits);

                struct input_type {
                    var x = var(0, 0, false);

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x};
                    }
                };

                struct result_type {
                    std::vector<std::array<var,3>> output = {};

                    result_type(const fri_cosets &component, std::size_t start_row_index) {
                        const std::size_t n = component.n;
                        const std::size_t l = component.nine_bl_per_line;

                        output.clear();
                        for(std::size_t b = n; b > 0; b--) {
                            std::size_t i = (b-1) / l; // blocks are numbered 0..(n-1). i = row of block b
                            std::size_t j = (b-1) % l; // j = number of block b in i-th row
                            output.push_back({ var(component.W(9*j + 5), start_row_index + i, false, var::column_type::witness),
                                               var(component.W(9*j + 6), start_row_index + i, false, var::column_type::witness),
                                               var(component.W(9*j + 7), start_row_index + i, false, var::column_type::witness) });
                        }
                    }

                    std::vector<var> all_vars() const {
                        std::vector<var> res = {};

                        for(auto & e : output) {
                            res.push_back(e[0]); res.push_back(e[1]); res.push_back(e[2]);
                        }
                        return res;
                    }
                };

                template <typename WitnessContainerType, typename ConstantContainerType,
                    typename PublicInputContainerType>
                fri_cosets(WitnessContainerType witness,
                           ConstantContainerType constant,
                           PublicInputContainerType public_input,
                           std::size_t n_,
                           value_type omega_):
                    component_type(witness, constant, public_input, get_manifest()),
                    n(n_),
                    omega(omega_) {
                };

                fri_cosets(std::initializer_list<
                        typename component_type::witness_container_type::value_type> witnesses,
                               std::initializer_list<
                        typename component_type::constant_container_type::value_type> constants,
                               std::initializer_list<
                        typename component_type::public_input_container_type::value_type> public_inputs,
                        std::size_t n_,
                        value_type omega_):
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    n(n_),
                    omega(omega_) {
                };
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fri_cosets =
                fri_cosets<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType>;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;

                const std::size_t WA = component.WA;
                const std::size_t n = component.n;
                const std::size_t l = component.nine_bl_per_line;

                typename BlueprintFieldType::integral_type
                    x_decomp = typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.x).data),
                    pm1_decomp = typename BlueprintFieldType::integral_type(BlueprintFieldType::value_type::modulus - 1);

                value_type w_power = component.omega;
                value_type coset_element = 1;

                // fill the 9-blocks
                // top-down part
                for(std::size_t b = 0; b < n; b++) {
                    std::size_t i = start_row_index + b / l;
                    std::size_t j = b % l;
                    assignment.witness(component.W(9*j),i) = value_type(x_decomp);
                    assignment.witness(component.W(9*j+1),i) = value_type(pm1_decomp);
                    // W(9j + 2) = sgn(pm1_decomp - x_decomp)
                    assignment.witness(component.W(9*j+2),i) = value_type((x_decomp < pm1_decomp) - (pm1_decomp < x_decomp));
                    assignment.witness(component.W(9*j+3),i) = w_power;
                    coset_element *= (x_decomp % 2 == 1 ? w_power : 1);
                    assignment.witness(component.W(9*j+4),i) = coset_element;
                    assignment.witness(component.W(9*j+7),i) = value_type(x_decomp % 2);
                    assignment.witness(component.W(9*j+8),i) = value_type(pm1_decomp % 2);
                    x_decomp /= 2;
                    pm1_decomp /= 2;
                    w_power *= w_power;
                }
                // down-top part
                for(std::size_t b = n; b > 0; b--) {
                    std::size_t i = start_row_index + (b-1) / l;
                    std::size_t j = (b-1) % l;
                    assignment.witness(component.W(9*j+5),i) = coset_element;
                    assignment.witness(component.W(9*j+6),i) = (-1)*coset_element;
                    coset_element = coset_element * coset_element;
                }

                std::size_t i = (9*n) / WA;
                std::size_t j = (9*n) % WA;
                assignment.witness(component.W(j),start_row_index + i) = value_type(x_decomp);
                assignment.witness(component.W(j+1),start_row_index + i) = value_type(pm1_decomp);
                // W(j + 2) = sgn(pm1_decomp - x_decomp)
                assignment.witness(component.W(j+2),start_row_index + i) =
                                   value_type((x_decomp < pm1_decomp) - (pm1_decomp < x_decomp));
                j += 3;
                while(i < component.rows_amount-1) {
                    assignment.witness(component.W(j),start_row_index + i) = value_type(x_decomp % 2);
                    assignment.witness(component.W(j+1),start_row_index + i) = value_type(pm1_decomp % 2);
                    assignment.witness(component.W(j+2),start_row_index + i) =
                                       value_type((x_decomp < pm1_decomp) - (pm1_decomp < x_decomp));
                    x_decomp = x_decomp / 2;
                    pm1_decomp = pm1_decomp / 2;
                    // W(j + 2) = sgn(pm1_decomp - x_decomp)
                    j += 3;
                    if (j == WA) {
                        i++;
                        assignment.witness(component.W(0),start_row_index + i) = value_type(x_decomp);
                        assignment.witness(component.W(1),start_row_index + i) = value_type(pm1_decomp);
                        // W(2) = sgn(pm1_decomp - x_decomp)
                        assignment.witness(component.W(j+2),start_row_index + i) =
                                           value_type((x_decomp < pm1_decomp) - (pm1_decomp < x_decomp));
                        j = 3;
                    }
                }

                return typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::var;

                // input
                bp.add_copy_constraint({instance_input.x, var(component.W(0), start_row_index, false)});

                // omega
                bp.add_copy_constraint({var(0, start_row_index, false, var::column_type::constant),
                                        var(component.W(3), start_row_index, false)});

                // everything that's over total_bits should be zero
                std::size_t WA = component.WA; // witness_amount
                std::size_t l = component.nine_bl_per_line; // number of 9-blocks per row
                std::size_t last_l = component.n % l; // 9-blocks in transition row. If 0, no transition row exists
                std::size_t remaining_bits = component.bits_blocks_count - ((last_l > 0)? 3*(l - last_l)-1 : 0);

                if (remaining_bits % (WA/3 - 1) > 0) { // Are there extra bits in the last row?
                    for(std::size_t j = 3*(remaining_bits % (WA/3 - 1) + 1); j < WA; j++) {
                        bp.add_copy_constraint({var(0, start_row_index + 1, false, var::column_type::constant),
                                                var(component.W(j), start_row_index + component.rows_amount - 2, false)});
                    }
                }

                // final row first 3-block is all zeros
                bp.add_copy_constraint({var(0, start_row_index + 1, false, var::column_type::constant),
                                        var(component.W(0), start_row_index + component.rows_amount - 1, false)});
                bp.add_copy_constraint({var(0, start_row_index + 1, false, var::column_type::constant),
                                        var(component.W(1), start_row_index + component.rows_amount - 1, false)});
                bp.add_copy_constraint({var(0, start_row_index + 1, false, var::column_type::constant),
                                        var(component.W(2), start_row_index + component.rows_amount - 1, false)});
            }

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                    const std::size_t start_row_index) {

                using var = typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                const std::size_t WA = component.WA;

                const std::size_t l = component.nine_bl_per_line;
                const std::size_t nineb_rows = lfit(component.n,l); // number of rows with 9-blocks
                const std::size_t last_l = component.n % l; // 9-blocks in transition row. If 0, no transition row exists
                const std::size_t bits = component.bits_blocks_count;

                std::size_t selector_index;

                std::vector<constraint_type> nine_block;
                std::vector<constraint_type> bit_line;
                constraint_type first_add_W1 = var(component.W(1),0) + 1;
                constraint_type first_add_W2 = var(component.W(2),0) * (1-var(component.W(2),0));
                constraint_type first_W4 = var(component.W(3),0)*var(component.W(7),0) + 1-var(component.W(7),0) - var(component.W(4),0);

                // Store typical constraints for every column
                nine_block.resize(WA);
                for(std::size_t j = 0; j < l; j++) {
                    var W0 = var(component.W(9*j),0),     // x/2^j
                        W1 = var(component.W(9*j + 1),0), // (p-1)/2^j
                        W2 = var(component.W(9*j + 2),0), // sgn( (p-1-x)/2^j )
                        W3 = var(component.W(9*j + 3),0), // omega^{2^j}
                        W4 = var(component.W(9*j + 4),0), // omega^{b_j...b_0}
                        W5 = var(component.W(9*j + 5),0), // (omega^{2^{n-1-j}})^x
                        W6 = var(component.W(9*j + 6),0), // -(omega^{2^{n-1-j}})^x
                        W7 = var(component.W(9*j + 7),0), // b_j = the j-th bit of x binary decomposition
                        W8 = var(component.W(9*j + 8),0), // c_j = the j-th bit of (p-1) binary decomposition
                        W0next = var(component.W(9*((j+1) % l)),(j+1)/l),
                        W1next = var(component.W(9*((j+1) % l) + 1),(j+1)/l),
                        W2next = var(component.W(9*((j+1) % l) + 2),(j+1)/l),
                        W3prev = var(component.W(9*((l+j-1) % l) + 3), -(j == 0)),
                        W4prev = var(component.W(9*((l+j-1) % l) + 4), -(j == 0)),
                        W5next = var(component.W(9*((j+1) % l) + 5),(j+1)/l);

                    nine_block[9*j]   = W0 - 2*W0next - W7;
                    nine_block[9*j+1] = W1 - 2*W1next - W8;
                    nine_block[9*j+2] = (W8 - W7)*(1 - W2next)*(1 + W2next) + W2next - W2;
                    nine_block[9*j+3] = W3 - W3prev * W3prev;
                    nine_block[9*j+4] = W4 - W4prev * (W3*W7 + 1-W7);
                    nine_block[9*j+5] = W5 - W5next * W5next;
                    nine_block[9*j+6] = W5 + W6;
                    nine_block[9*j+7] = (1 - W7) * W7;
                    nine_block[9*j+8] = (1 - W8) * W8;
                }

                bit_line.resize(WA);
                bit_line[0] = var(component.W(0),1);
                bit_line[1] = var(component.W(1),1);
                bit_line[2] = var(component.W(2),0) - var(component.W(5),0); // the first sign in the bit_line is just a copy of the 2nd
                for(std::size_t j = WA-3; j > 0; j -= 3) {
                    var Wj  = var(component.W(j),0),
                        Wj1 = var(component.W(j+1),0),
                        Wj2 = var(component.W(j+2),0),
                        Wj2next = var(component.W((j+5) % WA), (j+3 == WA)); // the sign in the next 3-block may be in the next line
                    bit_line[0] *= 2;
                    bit_line[0] += Wj;
                    bit_line[1] *= 2;
                    bit_line[1] += Wj1;
                    bit_line[j] = Wj * (Wj - 1);
                    bit_line[j+1] = Wj1 * (Wj1 - 1);
                    bit_line[j+2] = (Wj1 - Wj)*(1 - Wj2next)*(1 + Wj2next) + Wj2next - Wj2;
                }
                bit_line[0] -= var(component.W(0),0);
                bit_line[1] -= var(component.W(1),0);

                std::vector<constraint_type> cs1;
                if (nineb_rows > 1) { // there is a starting row which is not final (gate type 1)
                    cs1 = {nine_block[0],nine_block[1],nine_block[2]};
                    cs1.push_back(first_add_W1);
                    cs1.push_back(first_add_W2);
                    cs1.push_back(first_W4);
                    cs1.insert(cs1.end(),std::next(nine_block.begin(),5),nine_block.end());
                    selector_index = bp.add_gate(cs1); // type 1 gate
                    // Applying gate type 1 to line 0
                    assignment.enable_selector(selector_index, start_row_index);
                }

                if (nineb_rows > 2) { // there is a middle row (gate type 2)
                    selector_index = bp.add_gate(nine_block); // type 2 gate
                    // Applying gate type 2 to lines 1--(nineb_rows - 2)
                    for(std::size_t i = 1; i < nineb_rows - 1; i++) {
                        assignment.enable_selector(selector_index, start_row_index + i);
                    }
                }

                // The gate for the line where the 9-blocks end
                std::vector<constraint_type> cs3;
                std::size_t last = (last_l > 0)? last_l : l; // The number of the last 9-block in the row
                cs3 = {nine_block[0],nine_block[1],nine_block[2]};
                if (nineb_rows > 1) { // if the first 9-block is a regular middle 9-block, otherwise there's no "previous"
                    cs3.push_back(nine_block[3]);
                    cs3.push_back(nine_block[4]);
                } else {
                    cs3.push_back(first_add_W1);
                    cs3.push_back(first_add_W2);
                    cs3.push_back(first_W4);
                }
                cs3.insert(cs3.end(),std::next(nine_block.begin(),5),std::next(nine_block.begin(),9*(last-1)+5));
                cs3.push_back(var(component.W(9*(last - 1) + 5),0) - var(component.W(9*(last - 1) + 4),0));
                cs3.push_back(nine_block[9*(last-1)+6]);
                cs3.push_back(nine_block[9*(last-1)+7]);
                cs3.push_back(nine_block[9*(last-1)+8]);

                if (last_l > 0) { // there are bits on the transition line
                    constraint_type mid  = var(component.W(0),1),
                                    mid1 = var(component.W(1),1);

                    for(std::size_t j = WA-3; j > 9*last_l; j -= 3) {
                        mid *= 2;
                        mid += var(component.W(j),0);
                        mid1 *= 2;
                        mid1 += var(component.W(j+1),0);
                    }
                    mid  -= var(component.W(9*last_l),0);
                    mid1 -= var(component.W(9*last_l + 1),0);
                    cs3.push_back(mid);
                    cs3.push_back(mid1);

                    // the sign bit should be just a copy from the next block
                    var Wl2     = var(component.W(9*last_l + 2),0),
                        Wl2next = var(component.W(9*last_l + 5),0);
                    cs3.push_back( Wl2 - Wl2next );

                    cs3.insert(cs3.end(),
                              std::next(bit_line.begin(),9*last_l + 3),
                              bit_line.end());
                }
                selector_index = bp.add_gate(cs3); // type 3 gate
                // Applying gate type 3 to line (nineb_rows - 1)
                assignment.enable_selector(selector_index, start_row_index + nineb_rows - 1);

                // the number of bits not fitting on the "transition" line
                std::size_t remaining_bits = bits - (last_l > 0 ? 3*(l - last_l)-1 : 0);
                if (remaining_bits > 0) {
                    selector_index = bp.add_gate(bit_line); // type 4 gate
                    // Applying gate type 4 to lines nineb_rows -- (nineb_rows + lfit(remaining_bits,WA/3-1) - 2)
                    for(std::size_t i = 0; i < lfit(remaining_bits, WA/3 - 1); i++) {
                        assignment.enable_selector(selector_index, start_row_index + nineb_rows + i);
                    }
                }
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                generate_assignments_constant(component, assignment, instance_input, start_row_index);

                return typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_fri_cosets<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                assignment.constant(component.C(0), start_row_index) = component.omega;
                assignment.constant(component.C(0), start_row_index + 1) = 0; // a zero to make a copy-constraint with
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FRI_COSETS_HPP
