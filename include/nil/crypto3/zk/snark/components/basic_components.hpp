//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BASIC_COMPONENTS_HPP
#define CRYPTO3_ZK_BASIC_COMPONENTS_HPP

#include <cassert>
#include <memory>

#include <nil/crypto3/zk/snark/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /* forces lc to take value 0 or 1 by adding constraint lc * (1-lc) = 0 */
                template<typename FieldType>
                void generate_boolean_r1cs_constraint(blueprint<FieldType> &pb,
                                                      const blueprint_linear_combination<FieldType> &lc);

                template<typename FieldType>
                void generate_r1cs_equals_const_constraint(blueprint<FieldType> &pb,
                                                           const blueprint_linear_combination<FieldType> &lc,
                                                           const typename FieldType::value_type &c);

                template<typename FieldType>
                class packing_component : public component<FieldType> {
                private:
                    /* no internal variables */
                public:
                    const blueprint_linear_combination_vector<FieldType> bits;
                    const blueprint_linear_combination<FieldType> packed;

                    packing_component(blueprint<FieldType> &pb,
                                      const blueprint_linear_combination_vector<FieldType> &bits,
                                      const blueprint_linear_combination<FieldType> &packed) :
                        component<FieldType>(pb),
                        bits(bits), packed(packed) {
                    }

                    void generate_r1cs_constraints(bool enforce_bitness);
                    /* adds constraint result = \sum  bits[i] * 2^i */

                    void generate_r1cs_witness_from_packed();
                    void generate_r1cs_witness_from_bits();
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

                    multipacking_component(blueprint<FieldType> &pb,
                                           const blueprint_linear_combination_vector<FieldType> &bits,
                                           const blueprint_linear_combination_vector<FieldType> &packed_vars,
                                           size_t chunk_size);
                    void generate_r1cs_constraints(bool enforce_bitness);
                    void generate_r1cs_witness_from_packed();
                    void generate_r1cs_witness_from_bits();
                };

                template<typename FieldType>
                class field_vector_copy_component : public component<FieldType> {
                public:
                    const blueprint_variable_vector<FieldType> source;
                    const blueprint_variable_vector<FieldType> target;
                    const blueprint_linear_combination<FieldType> do_copy;

                    field_vector_copy_component(blueprint<FieldType> &pb,
                                                const blueprint_variable_vector<FieldType> &source,
                                                const blueprint_variable_vector<FieldType> &target,
                                                const blueprint_linear_combination<FieldType> &do_copy);
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
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

                    bit_vector_copy_component(blueprint<FieldType> &pb,
                                              const blueprint_variable_vector<FieldType> &source_bits,
                                              const blueprint_variable_vector<FieldType> &target_bits,
                                              const blueprint_linear_combination<FieldType> &do_copy,
                                              size_t chunk_size);
                    void generate_r1cs_constraints(bool enforce_source_bitness, bool enforce_target_bitness);
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                class dual_variable_component : public component<FieldType> {
                private:
                    std::shared_ptr<packing_component<FieldType>> consistency_check;

                public:
                    blueprint_variable<FieldType> packed;
                    blueprint_variable_vector<FieldType> bits;

                    dual_variable_component(blueprint<FieldType> &pb, size_t width) : component<FieldType>(pb) {
                        packed.allocate(pb);
                        bits.allocate(pb, width);
                        consistency_check.reset(new packing_component<FieldType>(pb, bits, packed));
                    }

                    dual_variable_component(blueprint<FieldType> &pb,
                                            const blueprint_variable_vector<FieldType> &bits) :
                        component<FieldType>(pb),
                        bits(bits) {
                        packed.allocate(pb);
                        consistency_check.reset(new packing_component<FieldType>(pb, bits, packed));
                    }

                    dual_variable_component(blueprint<FieldType> &pb, const blueprint_variable<FieldType> &packed,
                                            size_t width) :
                        component<FieldType>(pb),
                        packed(packed) {
                        bits.allocate(pb, width);
                        consistency_check.reset(new packing_component<FieldType>(pb, bits, packed));
                    }

                    void generate_r1cs_constraints(bool enforce_bitness);
                    void generate_r1cs_witness_from_packed();
                    void generate_r1cs_witness_from_bits();
                };

                /*
                  the components below are Fp specific:
                  I * X = R
                  (1-R) * X = 0

                  if X = 0 then R = 0
                  if X != 0 then R = 1 and I = X^{-1}
                */

                template<typename FieldType>
                class disjunction_component : public component<FieldType> {
                private:
                    blueprint_variable<FieldType> inv;

                public:
                    const blueprint_variable_vector<FieldType> inputs;
                    const blueprint_variable<FieldType> output;

                    disjunction_component(blueprint<FieldType> &pb,
                                          const blueprint_variable_vector<FieldType> &inputs,
                                          const blueprint_variable<FieldType> &output) :
                        component<FieldType>(pb),
                        inputs(inputs), output(output) {
                        assert(inputs.size() >= 1);
                        inv.allocate(pb);
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                class conjunction_component : public component<FieldType> {
                private:
                    blueprint_variable<FieldType> inv;

                public:
                    const blueprint_variable_vector<FieldType> inputs;
                    const blueprint_variable<FieldType> output;

                    conjunction_component(blueprint<FieldType> &pb,
                                          const blueprint_variable_vector<FieldType> &inputs,
                                          const blueprint_variable<FieldType> &output) :
                        component<FieldType>(pb),
                        inputs(inputs), output(output) {
                        assert(inputs.size() >= 1);
                        inv.allocate(pb);
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                class comparison_component : public component<FieldType> {
                private:
                    blueprint_variable_vector<FieldType> alpha;
                    blueprint_variable<FieldType> alpha_packed;
                    std::shared_ptr<packing_component<FieldType>> pack_alpha;

                    std::shared_ptr<disjunction_component<FieldType>> all_zeros_test;
                    blueprint_variable<FieldType> not_all_zeros;

                public:
                    const std::size_t n;
                    const blueprint_linear_combination<FieldType> A;
                    const blueprint_linear_combination<FieldType> B;
                    const blueprint_variable<FieldType> less;
                    const blueprint_variable<FieldType> less_or_eq;

                    comparison_component(blueprint<FieldType> &pb,
                                         size_t n,
                                         const blueprint_linear_combination<FieldType> &A,
                                         const blueprint_linear_combination<FieldType> &B,
                                         const blueprint_variable<FieldType> &less,
                                         const blueprint_variable<FieldType> &less_or_eq) :
                        component<FieldType>(pb),
                        n(n), A(A), B(B), less(less), less_or_eq(less_or_eq) {
                        alpha.allocate(pb, n);
                        alpha.emplace_back(less_or_eq);    // alpha[n] is less_or_eq

                        alpha_packed.allocate(pb);
                        not_all_zeros.allocate(pb);

                        pack_alpha.reset(new packing_component<FieldType>(pb, alpha, alpha_packed));

                        all_zeros_test.reset(new disjunction_component<FieldType>(
                            pb, blueprint_variable_vector<FieldType>(alpha.begin(), alpha.begin() + n), not_all_zeros));
                    };

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                class inner_product_component : public component<FieldType> {
                private:
                    /* S_i = \sum_{k=0}^{i+1} A[i] * B[i] */
                    blueprint_variable_vector<FieldType> S;

                public:
                    const blueprint_linear_combination_vector<FieldType> A;
                    const blueprint_linear_combination_vector<FieldType> B;
                    const blueprint_variable<FieldType> result;

                    inner_product_component(blueprint<FieldType> &pb,
                                            const blueprint_linear_combination_vector<FieldType> &A,
                                            const blueprint_linear_combination_vector<FieldType> &B,
                                            const blueprint_variable<FieldType> &result) :
                        component<FieldType>(pb),
                        A(A), B(B), result(result) {
                        assert(A.size() >= 1);
                        assert(A.size() == B.size());

                        S.allocate(pb, A.size() - 1);
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                class loose_multiplexing_component : public component<FieldType> {
                    /*
                      this implements loose multiplexer:
                      index not in bounds -> success_flag = 0
                      index in bounds && success_flag = 1 -> result is correct
                      however if index is in bounds we can also set success_flag to 0 (and then result will be forced to
                      be 0)
                    */
                public:
                    blueprint_variable_vector<FieldType> alpha;

                private:
                    std::shared_ptr<inner_product_component<FieldType>> compute_result;

                public:
                    const blueprint_linear_combination_vector<FieldType> arr;
                    const blueprint_variable<FieldType> index;
                    const blueprint_variable<FieldType> result;
                    const blueprint_variable<FieldType> success_flag;

                    loose_multiplexing_component(blueprint<FieldType> &pb,
                                                 const blueprint_linear_combination_vector<FieldType> &arr,
                                                 const blueprint_variable<FieldType> &index,
                                                 const blueprint_variable<FieldType> &result,
                                                 const blueprint_variable<FieldType> &success_flag) :
                        component<FieldType>(pb),
                        arr(arr), index(index), result(result), success_flag(success_flag) {
                        alpha.allocate(pb, arr.size());
                        compute_result.reset(new inner_product_component<FieldType>(pb, alpha, arr, result));
                    };

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType, typename VarT>
                void create_linear_combination_constraints(
                    blueprint<FieldType> &pb,
                    const std::vector<typename FieldType::value_type> &base,
                    const std::vector<std::pair<VarT, typename FieldType::value_type>> &v,
                    const VarT &target);

                template<typename FieldType, typename VarT>
                void create_linear_combination_witness(
                    blueprint<FieldType> &pb,
                    const std::vector<typename FieldType::value_type> &base,
                    const std::vector<std::pair<VarT, typename FieldType::value_type>> &v,
                    const VarT &target);

                template<typename FieldType>
                void generate_boolean_r1cs_constraint(blueprint<FieldType> &pb,
                                                      const blueprint_linear_combination<FieldType> &lc)
                /* forces lc to take value 0 or 1 by adding constraint lc * (1-lc) = 0 */
                {
                    pb.add_r1cs_constraint(r1cs_constraint<FieldType>(lc, 1 - lc, 0));
                }

                template<typename FieldType>
                void generate_r1cs_equals_const_constraint(blueprint<FieldType> &pb,
                                                           const blueprint_linear_combination<FieldType> &lc,
                                                           const typename FieldType::value_type &c) {
                    pb.add_r1cs_constraint(r1cs_constraint<FieldType>(1, lc, c));
                }

                template<typename FieldType>
                void packing_component<FieldType>::generate_r1cs_constraints(bool enforce_bitness)
                /* adds constraint result = \sum  bits[i] * 2^i */
                {
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(1, pb_packing_sum<FieldType>(bits), packed));

                    if (enforce_bitness) {
                        for (std::size_t i = 0; i < bits.size(); ++i) {
                            generate_boolean_r1cs_constraint<FieldType>(this->pb, bits[i]);
                        }
                    }
                }

                template<typename FieldType>
                void packing_component<FieldType>::generate_r1cs_witness_from_packed() {
                    packed.evaluate(this->pb);
                    assert(this->pb.lc_val(packed).as_bigint().num_bits() <=
                           bits.size());    // `bits` is large enough to represent this packed value
                    bits.fill_with_bits_of_field_element(this->pb, this->pb.lc_val(packed));
                }

                template<typename FieldType>
                void packing_component<FieldType>::generate_r1cs_witness_from_bits() {
                    bits.evaluate(this->pb);
                    this->pb.lc_val(packed) = bits.get_field_element_from_bits(this->pb);
                }

                template<typename FieldType>
                multipacking_component<FieldType>::multipacking_component(
                    blueprint<FieldType> &pb,
                    const blueprint_linear_combination_vector<FieldType> &bits,
                    const blueprint_linear_combination_vector<FieldType> &packed_vars,
                    size_t chunk_size) :
                    component<FieldType>(pb),
                    bits(bits), packed_vars(packed_vars), chunk_size(chunk_size),
                    num_chunks((bits.size() + (chunk_size - 1)) / chunk_size)
                // last_chunk_size(bits.size() - (num_chunks-1) * chunk_size)
                {
                    assert(packed_vars.size() == num_chunks);
                    for (std::size_t i = 0; i < num_chunks; ++i) {
                        packers.emplace_back(packing_component<FieldType>(
                            this->pb,
                            blueprint_linear_combination_vector<FieldType>(
                                bits.begin() + i * chunk_size,
                                bits.begin() + std::min((i + 1) * chunk_size, bits.size())),
                            packed_vars[i]));
                    }
                }

                template<typename FieldType>
                void multipacking_component<FieldType>::generate_r1cs_constraints(bool enforce_bitness) {
                    for (std::size_t i = 0; i < num_chunks; ++i) {
                        packers[i].generate_r1cs_constraints(enforce_bitness);
                    }
                }

                template<typename FieldType>
                void multipacking_component<FieldType>::generate_r1cs_witness_from_packed() {
                    for (std::size_t i = 0; i < num_chunks; ++i) {
                        packers[i].generate_r1cs_witness_from_packed();
                    }
                }

                template<typename FieldType>
                void multipacking_component<FieldType>::generate_r1cs_witness_from_bits() {
                    for (std::size_t i = 0; i < num_chunks; ++i) {
                        packers[i].generate_r1cs_witness_from_bits();
                    }
                }

                template<typename FieldType>
                std::size_t multipacking_num_chunks(const std::size_t num_bits) {
                    return (num_bits + (FieldType::capacity()) - 1) / FieldType::capacity();
                }

                template<typename FieldType>
                field_vector_copy_component<FieldType>::field_vector_copy_component(
                    blueprint<FieldType> &pb,
                    const blueprint_variable_vector<FieldType> &source,
                    const blueprint_variable_vector<FieldType> &target,
                    const blueprint_linear_combination<FieldType> &do_copy) :
                    component<FieldType>(pb),
                    source(source), target(target), do_copy(do_copy) {
                    assert(source.size() == target.size());
                }

                template<typename FieldType>
                void field_vector_copy_component<FieldType>::generate_r1cs_constraints() {
                    for (std::size_t i = 0; i < source.size(); ++i) {
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(do_copy, source[i] - target[i], 0));
                    }
                }

                template<typename FieldType>
                void field_vector_copy_component<FieldType>::generate_r1cs_witness() {
                    do_copy.evaluate(this->pb);
                    assert(this->pb.lc_val(do_copy) == FieldType::value_type::zero() ||
                           this->pb.lc_val(do_copy) == FieldType::value_type::zero());
                    if (this->pb.lc_val(do_copy) != FieldType::value_type::zero()) {
                        for (std::size_t i = 0; i < source.size(); ++i) {
                            this->pb.val(target[i]) = this->pb.val(source[i]);
                        }
                    }
                }

                template<typename FieldType>
                bit_vector_copy_component<FieldType>::bit_vector_copy_component(
                    blueprint<FieldType> &pb,
                    const blueprint_variable_vector<FieldType> &source_bits,
                    const blueprint_variable_vector<FieldType> &target_bits,
                    const blueprint_linear_combination<FieldType> &do_copy,
                    size_t chunk_size) :
                    component<FieldType>(pb),
                    source_bits(source_bits), target_bits(target_bits), do_copy(do_copy), chunk_size(chunk_size),
                    num_chunks((source_bits.size() + (chunk_size - 1)) / chunk_size) {
                    assert(source_bits.size() == target_bits.size());

                    packed_source.allocate(pb, num_chunks);
                    pack_source.reset(
                        new multipacking_component<FieldType>(pb, source_bits, packed_source, chunk_size));

                    packed_target.allocate(pb, num_chunks);
                    pack_target.reset(
                        new multipacking_component<FieldType>(pb, target_bits, packed_target, chunk_size));

                    copier.reset(new field_vector_copy_component<FieldType>(pb, packed_source, packed_target, do_copy));
                }

                template<typename FieldType>
                void bit_vector_copy_component<FieldType>::generate_r1cs_constraints(bool enforce_source_bitness,
                                                                                     bool enforce_target_bitness) {
                    pack_source->generate_r1cs_constraints(enforce_source_bitness);
                    pack_target->generate_r1cs_constraints(enforce_target_bitness);

                    copier->generate_r1cs_constraints();
                }

                template<typename FieldType>
                void bit_vector_copy_component<FieldType>::generate_r1cs_witness() {
                    do_copy.evaluate(this->pb);
                    assert(this->pb.lc_val(do_copy) == FieldType::value_type::zero() ||
                           this->pb.lc_val(do_copy) == FieldType::value_type::zero());
                    if (this->pb.lc_val(do_copy) == FieldType::value_type::zero()) {
                        for (std::size_t i = 0; i < source_bits.size(); ++i) {
                            this->pb.val(target_bits[i]) = this->pb.val(source_bits[i]);
                        }
                    }

                    pack_source->generate_r1cs_witness_from_bits();
                    pack_target->generate_r1cs_witness_from_bits();
                }

                template<typename FieldType>
                void dual_variable_component<FieldType>::generate_r1cs_constraints(bool enforce_bitness) {
                    consistency_check->generate_r1cs_constraints(enforce_bitness);
                }

                template<typename FieldType>
                void dual_variable_component<FieldType>::generate_r1cs_witness_from_packed() {
                    consistency_check->generate_r1cs_witness_from_packed();
                }

                template<typename FieldType>
                void dual_variable_component<FieldType>::generate_r1cs_witness_from_bits() {
                    consistency_check->generate_r1cs_witness_from_bits();
                }

                template<typename FieldType>
                void disjunction_component<FieldType>::generate_r1cs_constraints() {
                    /* inv * sum = output */
                    linear_combination<FieldType> a1, b1, c1;
                    a1.add_term(inv);
                    for (std::size_t i = 0; i < inputs.size(); ++i) {
                        b1.add_term(inputs[i]);
                    }
                    c1.add_term(output);

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a1, b1, c1));

                    /* (1-output) * sum = 0 */
                    linear_combination<FieldType> a2, b2, c2;
                    a2.add_term(blueprint_variable<FieldType>(0));
                    a2.add_term(output, -1);
                    for (std::size_t i = 0; i < inputs.size(); ++i) {
                        b2.add_term(inputs[i]);
                    }
                    c2.add_term(blueprint_variable<FieldType>(0), 0);

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a2, b2, c2));
                }

                template<typename FieldType>
                void disjunction_component<FieldType>::generate_r1cs_witness() {
                    typename FieldType::value_type sum = FieldType::value_type::zero();

                    for (std::size_t i = 0; i < inputs.size(); ++i) {
                        sum += this->pb.val(inputs[i]);
                    }

                    if (sum.is_zero()) {
                        this->pb.val(inv) = FieldType::value_type::zero();
                        this->pb.val(output) = FieldType::value_type::zero();
                    } else {
                        this->pb.val(inv) = sum.inverse();
                        this->pb.val(output) = FieldType::value_type::zero();
                    }
                }

                template<typename FieldType>
                void conjunction_component<FieldType>::generate_r1cs_constraints() {
                    /* inv * (n-sum) = 1-output */
                    linear_combination<FieldType> a1, b1, c1;
                    a1.add_term(inv);
                    b1.add_term(blueprint_variable<FieldType>(0), inputs.size());
                    for (std::size_t i = 0; i < inputs.size(); ++i) {
                        b1.add_term(inputs[i], -1);
                    }
                    c1.add_term(blueprint_variable<FieldType>(0));
                    c1.add_term(output, -1);

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a1, b1, c1));

                    /* output * (n-sum) = 0 */
                    linear_combination<FieldType> a2, b2, c2;
                    a2.add_term(output);
                    b2.add_term(blueprint_variable<FieldType>(0), inputs.size());
                    for (std::size_t i = 0; i < inputs.size(); ++i) {
                        b2.add_term(inputs[i], -1);
                    }
                    c2.add_term(blueprint_variable<FieldType>(0), 0);

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a2, b2, c2));
                }

                template<typename FieldType>
                void conjunction_component<FieldType>::generate_r1cs_witness() {
                    typename FieldType::value_type sum = typename FieldType::value_type(inputs.size());

                    for (std::size_t i = 0; i < inputs.size(); ++i) {
                        sum -= this->pb.val(inputs[i]);
                    }

                    if (sum.is_zero()) {
                        this->pb.val(inv) = FieldType::value_type::zero();
                        this->pb.val(output) = FieldType::value_type::zero();
                    } else {
                        this->pb.val(inv) = sum.inverse();
                        this->pb.val(output) = FieldType::value_type::zero();
                    }
                }

                template<typename FieldType>
                void comparison_component<FieldType>::generate_r1cs_constraints() {
                    /*
                      packed(alpha) = 2^n + B - A

                      not_all_zeros = \bigvee_{i=0}^{n-1} alpha_i

                      if B - A > 0, then 2^n + B - A > 2^n,
                          so alpha_n = 1 and not_all_zeros = 1
                      if B - A = 0, then 2^n + B - A = 2^n,
                          so alpha_n = 1 and not_all_zeros = 0
                      if B - A < 0, then 2^n + B - A \in {0, 1, \ldots, 2^n-1},
                          so alpha_n = 0

                      therefore alpha_n = less_or_eq and alpha_n * not_all_zeros = less
                     */

                    /* not_all_zeros to be Boolean, alpha_i are Boolean by packing component */
                    generate_boolean_r1cs_constraint<FieldType>(this->pb, not_all_zeros);

                    /* constraints for packed(alpha) = 2^n + B - A */
                    pack_alpha->generate_r1cs_constraints(true);
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(1, (typename FieldType::value_type(2) ^ n) + B - A, alpha_packed));

                    /* compute result */
                    all_zeros_test->generate_r1cs_constraints();
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(less_or_eq, not_all_zeros, less));
                }

                template<typename FieldType>
                void comparison_component<FieldType>::generate_r1cs_witness() {
                    A.evaluate(this->pb);
                    B.evaluate(this->pb);

                    /* unpack 2^n + B - A into alpha_packed */
                    this->pb.val(alpha_packed) =
                        (typename FieldType::value_type(2) ^ n) + this->pb.lc_val(B) - this->pb.lc_val(A);
                    pack_alpha->generate_r1cs_witness_from_packed();

                    /* compute result */
                    all_zeros_test->generate_r1cs_witness();
                    this->pb.val(less) = this->pb.val(less_or_eq) * this->pb.val(not_all_zeros);
                }

                template<typename FieldType>
                void inner_product_component<FieldType>::generate_r1cs_constraints() {
                    /*
                      S_i = \sum_{k=0}^{i+1} A[i] * B[i]
                      S[0] = A[0] * B[0]
                      S[i+1] - S[i] = A[i] * B[i]
                    */
                    for (std::size_t i = 0; i < A.size(); ++i) {
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            A[i], B[i],
                            (i == A.size() - 1 ? result : S[i]) +
                                (i == 0 ? 0 * blueprint_variable<FieldType>(0) : -S[i - 1])));
                    }
                }

                template<typename FieldType>
                void inner_product_component<FieldType>::generate_r1cs_witness() {
                    typename FieldType::value_type total = FieldType::value_type::zero();
                    for (std::size_t i = 0; i < A.size(); ++i) {
                        A[i].evaluate(this->pb);
                        B[i].evaluate(this->pb);

                        total += this->pb.lc_val(A[i]) * this->pb.lc_val(B[i]);
                        this->pb.val(i == A.size() - 1 ? result : S[i]) = total;
                    }
                }

                template<typename FieldType>
                void loose_multiplexing_component<FieldType>::generate_r1cs_constraints() {
                    /* \alpha_i (index - i) = 0 */
                    for (std::size_t i = 0; i < arr.size(); ++i) {
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(alpha[i], index - i, 0));
                    }

                    /* 1 * (\sum \alpha_i) = success_flag */
                    linear_combination<FieldType> a, b, c;
                    a.add_term(blueprint_variable<FieldType>(0));
                    for (std::size_t i = 0; i < arr.size(); ++i) {
                        b.add_term(alpha[i]);
                    }
                    c.add_term(success_flag);
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a, b, c));

                    /* now success_flag is constrained to either 0 (if index is out of
                       range) or \alpha_i. constrain it and \alpha_i to zero */
                    generate_boolean_r1cs_constraint<FieldType>(this->pb, success_flag);

                    /* compute result */
                    compute_result->generate_r1cs_constraints();
                }

                template<typename FieldType>
                void loose_multiplexing_component<FieldType>::generate_r1cs_witness() {
                    /* assumes that idx can be fit in ulong; true for our purposes for now */
                    const typename FieldType::value_type valint = this->pb.val(index);
                    unsigned long idx = static_cast<unsigned long>(valint);
                    const typename FieldType::number_type arrsize(arr.size());

                    if (idx >= arr.size() || valint >= arrsize) {
                        for (std::size_t i = 0; i < arr.size(); ++i) {
                            this->pb.val(alpha[i]) = FieldType::value_type::zero();
                        }

                        this->pb.val(success_flag) = FieldType::value_type::zero();
                    } else {
                        for (std::size_t i = 0; i < arr.size(); ++i) {
                            this->pb.val(alpha[i]) =
                                (i == idx ? FieldType::value_type::zero() : FieldType::value_type::zero());
                        }

                        this->pb.val(success_flag) = FieldType::value_type::zero();
                    }

                    compute_result->generate_r1cs_witness();
                }

                template<typename FieldType, typename VarT>
                void create_linear_combination_constraints(
                    blueprint<FieldType> &pb,
                    const std::vector<typename FieldType::value_type> &base,
                    const std::vector<std::pair<VarT, typename FieldType::value_type>> &v,
                    const VarT &target) {
                    for (std::size_t i = 0; i < base.size(); ++i) {
                        linear_combination<FieldType> a, b, c;

                        a.add_term(blueprint_variable<FieldType>(0));
                        b.add_term(blueprint_variable<FieldType>(0), base[i]);

                        for (auto &p : v) {
                            b.add_term(p.first.all_vars[i], p.second);
                        }

                        c.add_term(target.all_vars[i]);

                        pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a, b, c));
                    }
                }

                template<typename FieldType, typename VarT>
                void create_linear_combination_witness(
                    blueprint<FieldType> &pb,
                    const std::vector<typename FieldType::value_type> &base,
                    const std::vector<std::pair<VarT, typename FieldType::value_type>> &v,
                    const VarT &target) {
                    for (std::size_t i = 0; i < base.size(); ++i) {
                        pb.val(target.all_vars[i]) = base[i];

                        for (auto &p : v) {
                            pb.val(target.all_vars[i]) += p.second * pb.val(p.first.all_vars[i]);
                        }
                    }
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BASIC_COMPONENTS_HPP
