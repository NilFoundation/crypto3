//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_BASIC_COMPONENTS_HPP
#define CRYPTO3_ZK_BLUEPRINT_BASIC_COMPONENTS_HPP

#include <cassert>
#include <memory>

#include <nil/crypto3/zk/components/component.hpp>

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                /* forces lc to take value 0 or 1 by adding constraint lc * (1-lc) = 0 */
                template<typename FieldType>
                void generate_boolean_r1cs_constraint(blueprint<FieldType> &bp,
                                                      const blueprint_linear_combination<FieldType> &lc) {
                    bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(lc, 1 - lc, 0));
                }

                template<typename FieldType>
                void generate_r1cs_equals_const_constraint(blueprint<FieldType> &bp,
                                                           const blueprint_linear_combination<FieldType> &lc,
                                                           const typename FieldType::value_type &c) {
                    bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(1, lc, c));
                }

                template<typename FieldType>
                class packing_component : public component<FieldType> {
                private:
                    /* no internal variables */
                public:
                    const blueprint_linear_combination_vector<FieldType> bits;
                    const blueprint_linear_combination<FieldType> packed;

                    packing_component(blueprint<FieldType> &bp,
                                      const blueprint_linear_combination_vector<FieldType> &bits,
                                      const blueprint_linear_combination<FieldType> &packed) :
                        component<FieldType>(bp),
                        bits(bits), packed(packed) {
                    }

                    /* adds constraint result = \sum  bits[i] * 2^i */
                    void generate_r1cs_constraints(bool enforce_bitness) {
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<FieldType>(1, blueprint_packing_sum<FieldType>(bits), packed));

                        if (enforce_bitness) {
                            for (std::size_t i = 0; i < bits.size(); ++i) {
                                generate_boolean_r1cs_constraint<FieldType>(this->bp, bits[i]);
                            }
                        }
                    }

                    void generate_r1cs_witness_from_packed() {
                        packed.evaluate(this->bp);
                        auto lc_val = this->bp.lc_val(packed).data;

                        // assert(lc_val == 0 ||
                        //        multiprecision::msb(lc_val) + 1 <=
                        //            bits.size());    // `bits` is large enough to represent this packed value
                        bits.fill_with_bits_of_field_element(this->bp, this->bp.lc_val(packed));
                    }

                    void generate_r1cs_witness_from_bits() {
                        bits.evaluate(this->bp);
                        this->bp.lc_val(packed) = bits.get_field_element_from_bits(this->bp);
                    }
                };

                template<typename FieldType>
                class multipacking_component : public component<FieldType> {
                private:
                    std::vector<packing_component<FieldType>> packers;

                public:
                    const blueprint_linear_combination_vector<FieldType> bits;
                    const blueprint_linear_combination_vector<FieldType> packed_vars;

                    const std::size_t chunk_size;
                    const std::size_t num_chunks;
                    // const std::size_t last_chunk_size;

                    // last_chunk_size(bits.size() - (num_chunks-1) * chunk_size)
                    multipacking_component(blueprint<FieldType> &bp,
                                           const blueprint_linear_combination_vector<FieldType> &bits,
                                           const blueprint_linear_combination_vector<FieldType> &packed_vars,
                                           std::size_t chunk_size) :
                        component<FieldType>(bp),
                        bits(bits), packed_vars(packed_vars), chunk_size(chunk_size),
                        num_chunks((bits.size() + (chunk_size - 1)) / chunk_size) {

                        assert(packed_vars.size() == num_chunks);
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            packers.emplace_back(packing_component<FieldType>(
                                this->bp,
                                blueprint_linear_combination_vector<FieldType>(
                                    bits.begin() + i * chunk_size,
                                    bits.begin() + std::min((i + 1) * chunk_size, bits.size())),
                                packed_vars[i]));
                        }
                    }

                    void generate_r1cs_constraints(bool enforce_bitness) {
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            packers[i].generate_r1cs_constraints(enforce_bitness);
                        }
                    }

                    void generate_r1cs_witness_from_packed() {
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            packers[i].generate_r1cs_witness_from_packed();
                        }
                    }

                    void generate_r1cs_witness_from_bits() {
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            packers[i].generate_r1cs_witness_from_bits();
                        }
                    }
                };

                template<typename FieldType>
                class field_vector_copy_component : public component<FieldType> {
                public:
                    const blueprint_variable_vector<FieldType> source;
                    const blueprint_variable_vector<FieldType> target;
                    const blueprint_linear_combination<FieldType> do_copy;

                    field_vector_copy_component(blueprint<FieldType> &bp,
                                                const blueprint_variable_vector<FieldType> &source,
                                                const blueprint_variable_vector<FieldType> &target,
                                                const blueprint_linear_combination<FieldType> &do_copy) :
                        component<FieldType>(bp),
                        source(source), target(target), do_copy(do_copy) {

                        assert(source.size() == target.size());
                    }
                    void generate_r1cs_constraints() {
                        for (std::size_t i = 0; i < source.size(); ++i) {
                            this->bp.add_r1cs_constraint(
                                snark::r1cs_constraint<FieldType>(do_copy, source[i] - target[i], 0));
                        }
                    }

                    void generate_r1cs_witness() {
                        do_copy.evaluate(this->bp);
                        assert(this->bp.lc_val(do_copy) == FieldType::value_type::one() ||
                               this->bp.lc_val(do_copy) == FieldType::value_type::zero());
                        if (this->bp.lc_val(do_copy) != FieldType::value_type::zero()) {
                            for (std::size_t i = 0; i < source.size(); ++i) {
                                this->bp.val(target[i]) = this->bp.val(source[i]);
                            }
                        }
                    }
                };

                template<typename FieldType>
                class bit_vector_copy_component : public component<FieldType> {
                public:
                    const blueprint_variable_vector<FieldType> source_bits;
                    const blueprint_variable_vector<FieldType> target_bits;
                    const blueprint_linear_combination<FieldType> do_copy;

                    blueprint_variable_vector<FieldType> packed_source;
                    blueprint_variable_vector<FieldType> packed_target;

                    std::shared_ptr<multipacking_component<FieldType>> pack_source;
                    std::shared_ptr<multipacking_component<FieldType>> pack_target;
                    std::shared_ptr<field_vector_copy_component<FieldType>> copier;

                    const std::size_t chunk_size;
                    const std::size_t num_chunks;

                    bit_vector_copy_component(blueprint<FieldType> &bp,
                                              const blueprint_variable_vector<FieldType> &source_bits,
                                              const blueprint_variable_vector<FieldType> &target_bits,
                                              const blueprint_linear_combination<FieldType> &do_copy,
                                              std::size_t chunk_size) :
                        component<FieldType>(bp),
                        source_bits(source_bits), target_bits(target_bits), do_copy(do_copy), chunk_size(chunk_size),
                        num_chunks((source_bits.size() + (chunk_size - 1)) / chunk_size) {

                        assert(source_bits.size() == target_bits.size());

                        packed_source.allocate(bp, num_chunks);
                        pack_source.reset(
                            new multipacking_component<FieldType>(bp, source_bits, packed_source, chunk_size));

                        packed_target.allocate(bp, num_chunks);
                        pack_target.reset(
                            new multipacking_component<FieldType>(bp, target_bits, packed_target, chunk_size));

                        copier.reset(
                            new field_vector_copy_component<FieldType>(bp, packed_source, packed_target, do_copy));
                    }

                    void generate_r1cs_constraints(bool enforce_source_bitness, bool enforce_target_bitness) {
                        pack_source->generate_r1cs_constraints(enforce_source_bitness);
                        pack_target->generate_r1cs_constraints(enforce_target_bitness);

                        copier->generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        do_copy.evaluate(this->bp);
                        assert(this->bp.lc_val(do_copy) == FieldType::value_type::zero() ||
                               this->bp.lc_val(do_copy) == FieldType::value_type::one());
                        if (this->bp.lc_val(do_copy) == FieldType::value_type::one()) {
                            for (std::size_t i = 0; i < source_bits.size(); ++i) {
                                this->bp.val(target_bits[i]) = this->bp.val(source_bits[i]);
                            }
                        }

                        pack_source->generate_r1cs_witness_from_bits();
                        pack_target->generate_r1cs_witness_from_bits();
                    }
                };

                template<typename FieldType>
                class dual_variable_component : public component<FieldType> {
                private:
                    std::shared_ptr<packing_component<FieldType>> consistency_check;

                public:
                    blueprint_variable<FieldType> packed;
                    blueprint_variable_vector<FieldType> bits;

                    dual_variable_component(blueprint<FieldType> &bp, std::size_t width) : component<FieldType>(bp) {
                        packed.allocate(bp);
                        bits.allocate(bp, width);
                        consistency_check.reset(new packing_component<FieldType>(bp, bits, packed));
                    }

                    dual_variable_component(blueprint<FieldType> &bp,
                                            const blueprint_variable_vector<FieldType> &bits) :
                        component<FieldType>(bp),
                        bits(bits) {
                        packed.allocate(bp);
                        consistency_check.reset(new packing_component<FieldType>(bp, bits, packed));
                    }

                    dual_variable_component(blueprint<FieldType> &bp, const blueprint_variable<FieldType> &packed,
                                            std::size_t width) :
                        component<FieldType>(bp),
                        packed(packed) {
                        bits.allocate(bp, width);
                        consistency_check.reset(new packing_component<FieldType>(bp, bits, packed));
                    }

                    void generate_r1cs_constraints(bool enforce_bitness) {
                        consistency_check->generate_r1cs_constraints(enforce_bitness);
                    }

                    void generate_r1cs_witness_from_packed() {
                        consistency_check->generate_r1cs_witness_from_packed();
                    }
                    void generate_r1cs_witness_from_bits() {
                        consistency_check->generate_r1cs_witness_from_bits();
                    }
                };

                template<typename FieldType, typename VarT>
                void create_linear_combination_constraints(
                    blueprint<FieldType> &bp,
                    const std::vector<typename FieldType::value_type> &base,
                    const std::vector<std::pair<VarT, typename FieldType::value_type>> &v,
                    const VarT &target) {

                    for (std::size_t i = 0; i < base.size(); ++i) {
                        blueprint_linear_combination<FieldType> a, b, c;

                        a.add_term(blueprint_variable<FieldType>(0));
                        b.add_term(blueprint_variable<FieldType>(0), base[i]);

                        for (auto &p : v) {
                            b.add_term(p.first.all_vars[i], p.second);
                        }

                        c.add_term(target.all_vars[i]);

                        bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(a, b, c));
                    }
                }

                template<typename FieldType, typename VarT>
                void create_linear_combination_witness(
                    blueprint<FieldType> &bp,
                    const std::vector<typename FieldType::value_type> &base,
                    const std::vector<std::pair<VarT, typename FieldType::value_type>> &v,
                    const VarT &target) {
                    for (std::size_t i = 0; i < base.size(); ++i) {
                        bp.val(target.all_vars[i]) = base[i];

                        for (auto &p : v) {
                            bp.val(target.all_vars[i]) += p.second * bp.val(p.first.all_vars[i]);
                        }
                    }
                }

                template<typename FieldType>
                std::size_t multipacking_num_chunks(const std::size_t num_bits) {
                    return (num_bits + (FieldType::capacity()) - 1) / FieldType::capacity();
                }

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_BASIC_COMPONENTS_HPP
