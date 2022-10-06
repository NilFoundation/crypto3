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

#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/zk/snark/arithmetization/constraint_satisfaction_problems/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                /* forces lc to take value 0 or 1 by adding constraint lc * (1-lc) = 0 */
                template<typename Field>
                void generate_boolean_r1cs_constraint(blueprint<Field> &bp,
                                                      const detail::blueprint_linear_combination<Field> &lc) {
                    bp.add_r1cs_constraint(
                        snark::r1cs_constraint<Field>(lc, Field::value_type::one() - lc, Field::value_type::zero()));
                }

                template<typename Field>
                void generate_r1cs_equals_const_constraint(blueprint<Field> &bp,
                                                           const detail::blueprint_linear_combination<Field> &lc,
                                                           const typename Field::value_type &c) {
                    bp.add_r1cs_constraint(snark::r1cs_constraint<Field>(Field::value_type::one(), lc, c));
                }

                template<typename Field>
                struct packing : public component<Field> {
                    using field_type = Field;
                    using field_value_type = typename field_type::value_type;

                    const detail::blueprint_linear_combination_vector<field_type> bits;
                    const detail::blueprint_linear_combination<field_type> packed;

                    packing(blueprint<field_type> &bp,
                            const detail::blueprint_linear_combination_vector<field_type> &bits,
                            const detail::blueprint_linear_combination<field_type> &packed) :
                        component<field_type>(bp),
                        bits(bits), packed(packed) {
                    }

                    /* adds constraint result = \sum  bits[i] * 2^i */
                    void generate_r1cs_constraints(bool enforce_bitness) {
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
                            field_type::value_type::one(), detail::blueprint_packing_sum<field_type>(bits), packed));

                        if (enforce_bitness) {
                            for (std::size_t i = 0; i < bits.size(); ++i) {
                                generate_boolean_r1cs_constraint<field_type>(this->bp, bits[i]);
                            }
                        }
                    }

                    void generate_r1cs_witness_from_packed() {
                        packed.evaluate(this->bp);

                        // `bits` is large enough to represent this packed value
                        assert(multiprecision::msb(
                                   static_cast<typename field_type::integral_type>(this->bp.lc_val(packed).data)) +
                                   1 <=
                               bits.size());
                        bits.fill_with_bits_of_field_element(this->bp, this->bp.lc_val(packed));
                    }

                    void generate_r1cs_witness_from_bits() {
                        bits.evaluate(this->bp);
                        this->bp.lc_val(packed) = bits.get_field_element_from_bits(this->bp);
                    }
                };

                template<typename Field>
                class multipacking_component : public component<Field> {
                private:
                    std::vector<packing<Field>> packers;

                public:
                    const detail::blueprint_linear_combination_vector<Field> bits;
                    const detail::blueprint_linear_combination_vector<Field> packed_vars;

                    const std::size_t chunk_size;
                    const std::size_t num_chunks;
                    // const std::size_t last_chunk_size;

                    // last_chunk_size(bits.size() - (num_chunks-1) * chunk_size)
                    multipacking_component(blueprint<Field> &bp,
                                           const detail::blueprint_linear_combination_vector<Field> &bits,
                                           const detail::blueprint_linear_combination_vector<Field> &packed_vars,
                                           std::size_t chunk_size) :
                        component<Field>(bp),
                        bits(bits), packed_vars(packed_vars), chunk_size(chunk_size),
                        num_chunks((bits.size() + (chunk_size - 1)) / chunk_size) {

                        assert(packed_vars.size() == num_chunks);
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            packers.emplace_back(
                                packing<Field>(this->bp,
                                               detail::blueprint_linear_combination_vector<Field>(
                                                   bits.begin() + i * chunk_size,
                                                   bits.begin() + std::min((i + 1) * chunk_size, bits.size())),
                                               packed_vars[i]));
                        }
                    }

                    void generate_r1cs_constraints(const bool enforce_bitness) {
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

                template<typename Field>
                class field_vector_copy_component : public component<Field> {
                public:
                    const detail::blueprint_variable_vector<Field> source;
                    const detail::blueprint_variable_vector<Field> target;
                    const detail::blueprint_linear_combination<Field> do_copy;

                    field_vector_copy_component(blueprint<Field> &bp,
                                                const detail::blueprint_variable_vector<Field> &source,
                                                const detail::blueprint_variable_vector<Field> &target,
                                                const detail::blueprint_linear_combination<Field> &do_copy) :
                        component<Field>(bp),
                        source(source), target(target), do_copy(do_copy) {

                        assert(source.size() == target.size());
                    }
                    void generate_r1cs_constraints() {
                        for (std::size_t i = 0; i < source.size(); ++i) {
                            this->bp.add_r1cs_constraint(
                                snark::r1cs_constraint<Field>(do_copy, source[i] - target[i], 0));
                        }
                    }

                    void generate_r1cs_witness() {
                        do_copy.evaluate(this->bp);
                        assert(this->bp.lc_val(do_copy) == Field::value_type::one() ||
                               this->bp.lc_val(do_copy) == Field::value_type::zero());
                        if (this->bp.lc_val(do_copy) != Field::value_type::zero()) {
                            for (std::size_t i = 0; i < source.size(); ++i) {
                                this->bp.val(target[i]) = this->bp.val(source[i]);
                            }
                        }
                    }
                };

                template<typename Field>
                class bit_vector_copy_component : public component<Field> {
                public:
                    const detail::blueprint_variable_vector<Field> source_bits;
                    const detail::blueprint_variable_vector<Field> target_bits;
                    const detail::blueprint_linear_combination<Field> do_copy;

                    detail::blueprint_variable_vector<Field> packed_source;
                    detail::blueprint_variable_vector<Field> packed_target;

                    std::shared_ptr<multipacking_component<Field>> pack_source;
                    std::shared_ptr<multipacking_component<Field>> pack_target;
                    std::shared_ptr<field_vector_copy_component<Field>> copier;

                    const std::size_t chunk_size;
                    const std::size_t num_chunks;

                    bit_vector_copy_component(blueprint<Field> &bp,
                                              const detail::blueprint_variable_vector<Field> &source_bits,
                                              const detail::blueprint_variable_vector<Field> &target_bits,
                                              const detail::blueprint_linear_combination<Field> &do_copy,
                                              std::size_t chunk_size) :
                        component<Field>(bp),
                        source_bits(source_bits), target_bits(target_bits), do_copy(do_copy), chunk_size(chunk_size),
                        num_chunks((source_bits.size() + (chunk_size - 1)) / chunk_size) {

                        assert(source_bits.size() == target_bits.size());

                        packed_source.allocate(bp, num_chunks);
                        pack_source.reset(
                            new multipacking_component<Field>(bp, source_bits, packed_source, chunk_size));

                        packed_target.allocate(bp, num_chunks);
                        pack_target.reset(
                            new multipacking_component<Field>(bp, target_bits, packed_target, chunk_size));

                        copier.reset(new field_vector_copy_component<Field>(bp, packed_source, packed_target, do_copy));
                    }

                    void generate_r1cs_constraints(bool enforce_source_bitness, bool enforce_target_bitness) {
                        pack_source->generate_r1cs_constraints(enforce_source_bitness);
                        pack_target->generate_r1cs_constraints(enforce_target_bitness);

                        copier->generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        do_copy.evaluate(this->bp);
                        assert(this->bp.lc_val(do_copy) == Field::value_type::zero() ||
                               this->bp.lc_val(do_copy) == Field::value_type::one());
                        if (this->bp.lc_val(do_copy) == Field::value_type::one()) {
                            for (std::size_t i = 0; i < source_bits.size(); ++i) {
                                this->bp.val(target_bits[i]) = this->bp.val(source_bits[i]);
                            }
                        }

                        pack_source->generate_r1cs_witness_from_bits();
                        pack_target->generate_r1cs_witness_from_bits();
                    }
                };

                template<typename Field>
                class dual_variable_component : public component<Field> {
                private:
                    std::shared_ptr<packing<Field>> consistency_check;

                public:
                    detail::blueprint_variable<Field> packed;
                    detail::blueprint_variable_vector<Field> bits;

                    dual_variable_component(blueprint<Field> &bp, std::size_t width) : component<Field>(bp) {
                        packed.allocate(bp);
                        bits.allocate(bp, width);
                        consistency_check.reset(new packing<Field>(bp, bits, packed));
                    }

                    dual_variable_component(blueprint<Field> &bp, const detail::blueprint_variable_vector<Field> &bits) :
                        component<Field>(bp), bits(bits) {
                        packed.allocate(bp);
                        consistency_check.reset(new packing<Field>(bp, bits, packed));
                    }

                    dual_variable_component(blueprint<Field> &bp, const detail::blueprint_variable<Field> &packed,
                                            std::size_t width) :
                        component<Field>(bp),
                        packed(packed) {
                        bits.allocate(bp, width);
                        consistency_check.reset(new packing<Field>(bp, bits, packed));
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

                template<typename Field, typename VarT>
                void create_linear_combination_constraints(
                    blueprint<Field> &bp,
                    const std::vector<typename Field::value_type> &base,
                    const std::vector<std::pair<VarT, typename Field::value_type>> &v,
                    const VarT &target) {

                    for (std::size_t i = 0; i < base.size(); ++i) {
                        detail::blueprint_linear_combination<Field> a, b, c;

                        a.add_term(detail::blueprint_variable<Field>(0));
                        b.add_term(detail::blueprint_variable<Field>(0), base[i]);

                        for (auto &p : v) {
                            b.add_term(p.first.all_vars[i], p.second);
                        }

                        c.add_term(target.all_vars[i]);

                        bp.add_r1cs_constraint(snark::r1cs_constraint<Field>(a, b, c));
                    }
                }

                template<typename Field, typename VarT>
                void
                    create_linear_combination_witness(blueprint<Field> &bp,
                                                      const std::vector<typename Field::value_type> &base,
                                                      const std::vector<std::pair<VarT, typename Field::value_type>> &v,
                                                      const VarT &target) {
                    for (std::size_t i = 0; i < base.size(); ++i) {
                        bp.val(target.all_vars[i]) = base[i];

                        for (auto &p : v) {
                            bp.val(target.all_vars[i]) += p.second * bp.val(p.first.all_vars[i]);
                        }
                    }
                }

                template<typename Field>
                std::size_t multipacking_num_chunks(const std::size_t num_bits) {
                    return (num_bits + (Field::capacity()) - 1) / Field::capacity();
                }

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_BASIC_COMPONENTS_HPP
