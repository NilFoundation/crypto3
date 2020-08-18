//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BASIC_GADGETS_HPP_
#define BASIC_GADGETS_HPP_

#include <cassert>
#include <memory>

#include <nil/crypto3/zk/snark/gadget.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /* forces lc to take value 0 or 1 by adding constraint lc * (1-lc) = 0 */
                template<typename FieldType>
                void generate_boolean_r1cs_constraint(protoboard<FieldType> &pb,
                                                      const pb_linear_combination<FieldType> &lc);

                template<typename FieldType>
                void generate_r1cs_equals_const_constraint(protoboard<FieldType> &pb,
                                                           const pb_linear_combination<FieldType> &lc,
                                                           const FieldType &c);

                template<typename FieldType>
                class packing_gadget : public gadget<FieldType> {
                private:
                    /* no internal variables */
                public:
                    const pb_linear_combination_array<FieldType> bits;
                    const pb_linear_combination<FieldType> packed;

                    packing_gadget(protoboard<FieldType> &pb, const pb_linear_combination_array<FieldType> &bits,
                                   const pb_linear_combination<FieldType> &packed) :
                        gadget<FieldType>(pb),
                        bits(bits), packed(packed) {
                    }

                    void generate_r1cs_constraints(bool enforce_bitness);
                    /* adds constraint result = \sum  bits[i] * 2^i */

                    void generate_r1cs_witness_from_packed();
                    void generate_r1cs_witness_from_bits();
                };

                template<typename FieldType>
                class multipacking_gadget : public gadget<FieldType> {
                private:
                    std::vector<packing_gadget<FieldType>> packers;

                public:
                    const pb_linear_combination_array<FieldType> bits;
                    const pb_linear_combination_array<FieldType> packed_vars;

                    const std::size_t chunk_size;
                    const std::size_t num_chunks;
                    // const std::size_t last_chunk_size;

                    multipacking_gadget(protoboard<FieldType> &pb,
                                        const pb_linear_combination_array<FieldType> &bits,
                                        const pb_linear_combination_array<FieldType> &packed_vars,
                                        size_t chunk_size);
                    void generate_r1cs_constraints(bool enforce_bitness);
                    void generate_r1cs_witness_from_packed();
                    void generate_r1cs_witness_from_bits();
                };

                template<typename FieldType>
                class field_vector_copy_gadget : public gadget<FieldType> {
                public:
                    const pb_variable_array<FieldType> source;
                    const pb_variable_array<FieldType> target;
                    const pb_linear_combination<FieldType> do_copy;

                    field_vector_copy_gadget(protoboard<FieldType> &pb,
                                             const pb_variable_array<FieldType> &source,
                                             const pb_variable_array<FieldType> &target,
                                             const pb_linear_combination<FieldType> &do_copy);
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                class bit_vector_copy_gadget : public gadget<FieldType> {
                public:
                    const pb_variable_array<FieldType> source_bits;
                    const pb_variable_array<FieldType> target_bits;
                    const pb_linear_combination<FieldType> do_copy;

                    pb_variable_array<FieldType> packed_source;
                    pb_variable_array<FieldType> packed_target;

                    std::shared_ptr<multipacking_gadget<FieldType>> pack_source;
                    std::shared_ptr<multipacking_gadget<FieldType>> pack_target;
                    std::shared_ptr<field_vector_copy_gadget<FieldType>> copier;

                    const std::size_t chunk_size;
                    const std::size_t num_chunks;

                    bit_vector_copy_gadget(protoboard<FieldType> &pb,
                                           const pb_variable_array<FieldType> &source_bits,
                                           const pb_variable_array<FieldType> &target_bits,
                                           const pb_linear_combination<FieldType> &do_copy,
                                           size_t chunk_size);
                    void generate_r1cs_constraints(bool enforce_source_bitness, bool enforce_target_bitness);
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                class dual_variable_gadget : public gadget<FieldType> {
                private:
                    std::shared_ptr<packing_gadget<FieldType>> consistency_check;

                public:
                    pb_variable<FieldType> packed;
                    pb_variable_array<FieldType> bits;

                    dual_variable_gadget(protoboard<FieldType> &pb, size_t width) : gadget<FieldType>(pb) {
                        packed.allocate(pb);
                        bits.allocate(pb, width);
                        consistency_check.reset(new packing_gadget<FieldType>(pb, bits, packed));
                    }

                    dual_variable_gadget(protoboard<FieldType> &pb, const pb_variable_array<FieldType> &bits) :
                        gadget<FieldType>(pb), bits(bits) {
                        packed.allocate(pb);
                        consistency_check.reset(new packing_gadget<FieldType>(pb, bits, packed));
                    }

                    dual_variable_gadget(protoboard<FieldType> &pb,
                                         const pb_variable<FieldType> &packed,
                                         size_t width) :
                        gadget<FieldType>(pb),
                        packed(packed) {
                        bits.allocate(pb, width);
                        consistency_check.reset(new packing_gadget<FieldType>(pb, bits, packed));
                    }

                    void generate_r1cs_constraints(bool enforce_bitness);
                    void generate_r1cs_witness_from_packed();
                    void generate_r1cs_witness_from_bits();
                };

                /*
                  the gadgets below are Fp specific:
                  I * X = R
                  (1-R) * X = 0

                  if X = 0 then R = 0
                  if X != 0 then R = 1 and I = X^{-1}
                */

                template<typename FieldType>
                class disjunction_gadget : public gadget<FieldType> {
                private:
                    pb_variable<FieldType> inv;

                public:
                    const pb_variable_array<FieldType> inputs;
                    const pb_variable<FieldType> output;

                    disjunction_gadget(protoboard<FieldType> &pb,
                                       const pb_variable_array<FieldType> &inputs,
                                       const pb_variable<FieldType> &output) :
                        gadget<FieldType>(pb),
                        inputs(inputs), output(output) {
                        assert(inputs.size() >= 1);
                        inv.allocate(pb);
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_disjunction_gadget(size_t n);

                template<typename FieldType>
                class conjunction_gadget : public gadget<FieldType> {
                private:
                    pb_variable<FieldType> inv;

                public:
                    const pb_variable_array<FieldType> inputs;
                    const pb_variable<FieldType> output;

                    conjunction_gadget(protoboard<FieldType> &pb,
                                       const pb_variable_array<FieldType> &inputs,
                                       const pb_variable<FieldType> &output) :
                        gadget<FieldType>(pb),
                        inputs(inputs), output(output) {
                        assert(inputs.size() >= 1);
                        inv.allocate(pb);
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_conjunction_gadget(size_t n);

                template<typename FieldType>
                class comparison_gadget : public gadget<FieldType> {
                private:
                    pb_variable_array<FieldType> alpha;
                    pb_variable<FieldType> alpha_packed;
                    std::shared_ptr<packing_gadget<FieldType>> pack_alpha;

                    std::shared_ptr<disjunction_gadget<FieldType>> all_zeros_test;
                    pb_variable<FieldType> not_all_zeros;

                public:
                    const std::size_t n;
                    const pb_linear_combination<FieldType> A;
                    const pb_linear_combination<FieldType> B;
                    const pb_variable<FieldType> less;
                    const pb_variable<FieldType> less_or_eq;

                    comparison_gadget(protoboard<FieldType> &pb,
                                      size_t n,
                                      const pb_linear_combination<FieldType> &A,
                                      const pb_linear_combination<FieldType> &B,
                                      const pb_variable<FieldType> &less,
                                      const pb_variable<FieldType> &less_or_eq) :
                        gadget<FieldType>(pb),
                        n(n), A(A), B(B), less(less), less_or_eq(less_or_eq) {
                        alpha.allocate(pb, n);
                        alpha.emplace_back(less_or_eq);    // alpha[n] is less_or_eq

                        alpha_packed.allocate(pb);
                        not_all_zeros.allocate(pb);

                        pack_alpha.reset(new packing_gadget<FieldType>(pb, alpha, alpha_packed));

                        all_zeros_test.reset(new disjunction_gadget<FieldType>(
                            pb, pb_variable_array<FieldType>(alpha.begin(), alpha.begin() + n), not_all_zeros));
                    };

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_comparison_gadget(size_t n);

                template<typename FieldType>
                class inner_product_gadget : public gadget<FieldType> {
                private:
                    /* S_i = \sum_{k=0}^{i+1} A[i] * B[i] */
                    pb_variable_array<FieldType> S;

                public:
                    const pb_linear_combination_array<FieldType> A;
                    const pb_linear_combination_array<FieldType> B;
                    const pb_variable<FieldType> result;

                    inner_product_gadget(protoboard<FieldType> &pb,
                                         const pb_linear_combination_array<FieldType> &A,
                                         const pb_linear_combination_array<FieldType> &B,
                                         const pb_variable<FieldType> &result) :
                        gadget<FieldType>(pb),
                        A(A), B(B), result(result) {
                        assert(A.size() >= 1);
                        assert(A.size() == B.size());

                        S.allocate(pb, A.size() - 1);
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_inner_product_gadget(size_t n);

                template<typename FieldType>
                class loose_multiplexing_gadget : public gadget<FieldType> {
                    /*
                      this implements loose multiplexer:
                      index not in bounds -> success_flag = 0
                      index in bounds && success_flag = 1 -> result is correct
                      however if index is in bounds we can also set success_flag to 0 (and then result will be forced to
                      be 0)
                    */
                public:
                    pb_variable_array<FieldType> alpha;

                private:
                    std::shared_ptr<inner_product_gadget<FieldType>> compute_result;

                public:
                    const pb_linear_combination_array<FieldType> arr;
                    const pb_variable<FieldType> index;
                    const pb_variable<FieldType> result;
                    const pb_variable<FieldType> success_flag;

                    loose_multiplexing_gadget(protoboard<FieldType> &pb,
                                              const pb_linear_combination_array<FieldType> &arr,
                                              const pb_variable<FieldType> &index,
                                              const pb_variable<FieldType> &result,
                                              const pb_variable<FieldType> &success_flag) :
                        gadget<FieldType>(pb),
                        arr(arr), index(index), result(result), success_flag(success_flag) {
                        alpha.allocate(pb, arr.size());
                        compute_result.reset(new inner_product_gadget<FieldType>(pb, alpha, arr, result));
                    };

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_loose_multiplexing_gadget(size_t n);

                template<typename FieldType, typename VarT>
                void create_linear_combination_constraints(protoboard<FieldType> &pb,
                                                           const std::vector<typename FieldType::value_type> &base,
                                                           const std::vector<std::pair<VarT, typename FieldType::value_type>> &v,
                                                           const VarT &target);

                template<typename FieldType, typename VarT>
                void create_linear_combination_witness(protoboard<FieldType> &pb,
                                                       const std::vector<typename FieldType::value_type> &base,
                                                       const std::vector<std::pair<VarT, typename FieldType::value_type>> &v,
                                                       const VarT &target);

                template<typename FieldType>
                void generate_boolean_r1cs_constraint(protoboard<FieldType> &pb,
                                                      const pb_linear_combination<FieldType> &lc)
                /* forces lc to take value 0 or 1 by adding constraint lc * (1-lc) = 0 */
                {
                    pb.add_r1cs_constraint(r1cs_constraint<FieldType>(lc, 1 - lc, 0));
                }

                template<typename FieldType>
                void generate_r1cs_equals_const_constraint(protoboard<FieldType> &pb,
                                                           const pb_linear_combination<FieldType> &lc,
                                                           const typename FieldType::value_type &c) {
                    pb.add_r1cs_constraint(r1cs_constraint<FieldType>(1, lc, c));
                }

                template<typename FieldType>
                void packing_gadget<FieldType>::generate_r1cs_constraints(bool enforce_bitness)
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
                void packing_gadget<FieldType>::generate_r1cs_witness_from_packed() {
                    packed.evaluate(this->pb);
                    assert(this->pb.lc_val(packed).as_bigint().num_bits() <=
                           bits.size());    // `bits` is large enough to represent this packed value
                    bits.fill_with_bits_of_field_element(this->pb, this->pb.lc_val(packed));
                }

                template<typename FieldType>
                void packing_gadget<FieldType>::generate_r1cs_witness_from_bits() {
                    bits.evaluate(this->pb);
                    this->pb.lc_val(packed) = bits.get_field_element_from_bits(this->pb);
                }

                template<typename FieldType>
                multipacking_gadget<FieldType>::multipacking_gadget(
                    protoboard<FieldType> &pb,
                    const pb_linear_combination_array<FieldType> &bits,
                    const pb_linear_combination_array<FieldType> &packed_vars,
                    size_t chunk_size) :
                    gadget<FieldType>(pb),
                    bits(bits), packed_vars(packed_vars), chunk_size(chunk_size),
                    num_chunks((bits.size() + (chunk_size - 1)) / chunk_size)
                // last_chunk_size(bits.size() - (num_chunks-1) * chunk_size)
                {
                    assert(packed_vars.size() == num_chunks);
                    for (std::size_t i = 0; i < num_chunks; ++i) {
                        packers.emplace_back(
                            packing_gadget<FieldType>(this->pb,
                                                      pb_linear_combination_array<FieldType>(
                                                          bits.begin() + i * chunk_size,
                                                          bits.begin() + std::min((i + 1) * chunk_size, bits.size())),
                                                      packed_vars[i]));
                    }
                }

                template<typename FieldType>
                void multipacking_gadget<FieldType>::generate_r1cs_constraints(bool enforce_bitness) {
                    for (std::size_t i = 0; i < num_chunks; ++i) {
                        packers[i].generate_r1cs_constraints(enforce_bitness);
                    }
                }

                template<typename FieldType>
                void multipacking_gadget<FieldType>::generate_r1cs_witness_from_packed() {
                    for (std::size_t i = 0; i < num_chunks; ++i) {
                        packers[i].generate_r1cs_witness_from_packed();
                    }
                }

                template<typename FieldType>
                void multipacking_gadget<FieldType>::generate_r1cs_witness_from_bits() {
                    for (std::size_t i = 0; i < num_chunks; ++i) {
                        packers[i].generate_r1cs_witness_from_bits();
                    }
                }

                template<typename FieldType>
                std::size_t multipacking_num_chunks(const std::size_t num_bits) {
                    return (num_bits + (FieldType::capacity()) - 1) / FieldType::capacity();
                }

                template<typename FieldType>
                field_vector_copy_gadget<FieldType>::field_vector_copy_gadget(
                    protoboard<FieldType> &pb,
                    const pb_variable_array<FieldType> &source,
                    const pb_variable_array<FieldType> &target,
                    const pb_linear_combination<FieldType> &do_copy) :
                    gadget<FieldType>(pb),
                    source(source), target(target), do_copy(do_copy) {
                    assert(source.size() == target.size());
                }

                template<typename FieldType>
                void field_vector_copy_gadget<FieldType>::generate_r1cs_constraints() {
                    for (std::size_t i = 0; i < source.size(); ++i) {
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(do_copy, source[i] - target[i], 0));
                    }
                }

                template<typename FieldType>
                void field_vector_copy_gadget<FieldType>::generate_r1cs_witness() {
                    do_copy.evaluate(this->pb);
                    assert(this->pb.lc_val(do_copy) == FieldType::one() ||
                           this->pb.lc_val(do_copy) == FieldType::zero());
                    if (this->pb.lc_val(do_copy) != FieldType::zero()) {
                        for (std::size_t i = 0; i < source.size(); ++i) {
                            this->pb.val(target[i]) = this->pb.val(source[i]);
                        }
                    }
                }

                template<typename FieldType>
                bit_vector_copy_gadget<FieldType>::bit_vector_copy_gadget(
                    protoboard<FieldType> &pb,
                    const pb_variable_array<FieldType> &source_bits,
                    const pb_variable_array<FieldType> &target_bits,
                    const pb_linear_combination<FieldType> &do_copy,
                    size_t chunk_size) :
                    gadget<FieldType>(pb),
                    source_bits(source_bits), target_bits(target_bits), do_copy(do_copy), chunk_size(chunk_size),
                    num_chunks((source_bits.size() + (chunk_size - 1)) / chunk_size) {
                    assert(source_bits.size() == target_bits.size());

                    packed_source.allocate(pb, num_chunks);
                    pack_source.reset(new multipacking_gadget<FieldType>(pb, source_bits, packed_source, chunk_size));

                    packed_target.allocate(pb, num_chunks);
                    pack_target.reset(new multipacking_gadget<FieldType>(pb, target_bits, packed_target, chunk_size));

                    copier.reset(new field_vector_copy_gadget<FieldType>(pb, packed_source, packed_target, do_copy));
                }

                template<typename FieldType>
                void bit_vector_copy_gadget<FieldType>::generate_r1cs_constraints(bool enforce_source_bitness,
                                                                                  bool enforce_target_bitness) {
                    pack_source->generate_r1cs_constraints(enforce_source_bitness);
                    pack_target->generate_r1cs_constraints(enforce_target_bitness);

                    copier->generate_r1cs_constraints();
                }

                template<typename FieldType>
                void bit_vector_copy_gadget<FieldType>::generate_r1cs_witness() {
                    do_copy.evaluate(this->pb);
                    assert(this->pb.lc_val(do_copy) == FieldType::zero() ||
                           this->pb.lc_val(do_copy) == FieldType::one());
                    if (this->pb.lc_val(do_copy) == FieldType::one()) {
                        for (std::size_t i = 0; i < source_bits.size(); ++i) {
                            this->pb.val(target_bits[i]) = this->pb.val(source_bits[i]);
                        }
                    }

                    pack_source->generate_r1cs_witness_from_bits();
                    pack_target->generate_r1cs_witness_from_bits();
                }

                template<typename FieldType>
                void dual_variable_gadget<FieldType>::generate_r1cs_constraints(bool enforce_bitness) {
                    consistency_check->generate_r1cs_constraints(enforce_bitness);
                }

                template<typename FieldType>
                void dual_variable_gadget<FieldType>::generate_r1cs_witness_from_packed() {
                    consistency_check->generate_r1cs_witness_from_packed();
                }

                template<typename FieldType>
                void dual_variable_gadget<FieldType>::generate_r1cs_witness_from_bits() {
                    consistency_check->generate_r1cs_witness_from_bits();
                }

                template<typename FieldType>
                void disjunction_gadget<FieldType>::generate_r1cs_constraints() {
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
                    a2.add_term(pb_variable<FieldType>(0));
                    a2.add_term(output, -1);
                    for (std::size_t i = 0; i < inputs.size(); ++i) {
                        b2.add_term(inputs[i]);
                    }
                    c2.add_term(pb_variable<FieldType>(0), 0);

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a2, b2, c2));
                }

                template<typename FieldType>
                void disjunction_gadget<FieldType>::generate_r1cs_witness() {
                    FieldType sum = FieldType::zero();

                    for (std::size_t i = 0; i < inputs.size(); ++i) {
                        sum += this->pb.val(inputs[i]);
                    }

                    if (sum.is_zero()) {
                        this->pb.val(inv) = FieldType::zero();
                        this->pb.val(output) = FieldType::zero();
                    } else {
                        this->pb.val(inv) = sum.inverse();
                        this->pb.val(output) = FieldType::one();
                    }
                }

                template<typename FieldType>
                void test_disjunction_gadget(size_t n) {
                    protoboard<FieldType> pb;
                    pb_variable_array<FieldType> inputs;
                    inputs.allocate(pb, n);

                    pb_variable<FieldType> output;
                    output.allocate(pb);

                    disjunction_gadget<FieldType> d(pb, inputs, output);
                    d.generate_r1cs_constraints();

                    for (std::size_t w = 0; w < 1ul << n; ++w) {
                        for (std::size_t j = 0; j < n; ++j) {
                            pb.val(inputs[j]) = typename FieldType::value_type((w & (1ul << j)) ? 1 : 0);
                        }

                        d.generate_r1cs_witness();

                        assert(pb.val(output) == (w ? FieldType::one() : FieldType::zero()));
                        assert(pb.is_satisfied());

                        pb.val(output) = (w ? FieldType::zero() : FieldType::one());
                        assert(!pb.is_satisfied());
                    }
                }

                template<typename FieldType>
                void conjunction_gadget<FieldType>::generate_r1cs_constraints() {
                    /* inv * (n-sum) = 1-output */
                    linear_combination<FieldType> a1, b1, c1;
                    a1.add_term(inv);
                    b1.add_term(pb_variable<FieldType>(0), inputs.size());
                    for (std::size_t i = 0; i < inputs.size(); ++i) {
                        b1.add_term(inputs[i], -1);
                    }
                    c1.add_term(pb_variable<FieldType>(0));
                    c1.add_term(output, -1);

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a1, b1, c1));

                    /* output * (n-sum) = 0 */
                    linear_combination<FieldType> a2, b2, c2;
                    a2.add_term(output);
                    b2.add_term(pb_variable<FieldType>(0), inputs.size());
                    for (std::size_t i = 0; i < inputs.size(); ++i) {
                        b2.add_term(inputs[i], -1);
                    }
                    c2.add_term(pb_variable<FieldType>(0), 0);

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a2, b2, c2));
                }

                template<typename FieldType>
                void conjunction_gadget<FieldType>::generate_r1cs_witness() {
                    FieldType sum = typename FieldType::value_type(inputs.size());

                    for (std::size_t i = 0; i < inputs.size(); ++i) {
                        sum -= this->pb.val(inputs[i]);
                    }

                    if (sum.is_zero()) {
                        this->pb.val(inv) = FieldType::zero();
                        this->pb.val(output) = FieldType::one();
                    } else {
                        this->pb.val(inv) = sum.inverse();
                        this->pb.val(output) = FieldType::zero();
                    }
                }

                template<typename FieldType>
                void test_conjunction_gadget(size_t n) {
                    protoboard<FieldType> pb;
                    pb_variable_array<FieldType> inputs;
                    inputs.allocate(pb, n);

                    pb_variable<FieldType> output;
                    output.allocate(pb);

                    conjunction_gadget<FieldType> c(pb, inputs, output);
                    c.generate_r1cs_constraints();

                    for (std::size_t w = 0; w < 1ul << n; ++w) {
                        for (std::size_t j = 0; j < n; ++j) {
                            pb.val(inputs[j]) = (w & (1ul << j)) ? FieldType::one() : FieldType::zero();
                        }

                        c.generate_r1cs_witness();

                        assert(pb.val(output) == (w == (1ul << n) - 1 ? FieldType::one() : FieldType::zero()));
                        assert(pb.is_satisfied());

                        pb.val(output) = (w == (1ul << n) - 1 ? FieldType::zero() : FieldType::one());
                        assert(!pb.is_satisfied());
                    }
                }

                template<typename FieldType>
                void comparison_gadget<FieldType>::generate_r1cs_constraints() {
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

                    /* not_all_zeros to be Boolean, alpha_i are Boolean by packing gadget */
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
                void comparison_gadget<FieldType>::generate_r1cs_witness() {
                    A.evaluate(this->pb);
                    B.evaluate(this->pb);

                    /* unpack 2^n + B - A into alpha_packed */
                    this->pb.val(alpha_packed) = (typename FieldType::value_type(2) ^ n) + this->pb.lc_val(B) - this->pb.lc_val(A);
                    pack_alpha->generate_r1cs_witness_from_packed();

                    /* compute result */
                    all_zeros_test->generate_r1cs_witness();
                    this->pb.val(less) = this->pb.val(less_or_eq) * this->pb.val(not_all_zeros);
                }

                template<typename FieldType>
                void test_comparison_gadget(size_t n) {
                    protoboard<FieldType> pb;

                    pb_variable<FieldType> A, B, less, less_or_eq;
                    A.allocate(pb);
                    B.allocate(pb);
                    less.allocate(pb);
                    less_or_eq.allocate(pb);

                    comparison_gadget<FieldType> cmp(pb, n, A, B, less, less_or_eq);
                    cmp.generate_r1cs_constraints();

                    for (std::size_t a = 0; a < 1ul << n; ++a) {
                        for (std::size_t b = 0; b < 1ul << n; ++b) {
                            pb.val(A) = typename FieldType::value_type(a);
                            pb.val(B) = typename FieldType::value_type(b);

                            cmp.generate_r1cs_witness();

                            assert(pb.val(less) == (a < b ? FieldType::one() : FieldType::zero()));
                            assert(pb.val(less_or_eq) == (a <= b ? FieldType::one() : FieldType::zero()));
                            assert(pb.is_satisfied());
                        }
                    }
                }

                template<typename FieldType>
                void inner_product_gadget<FieldType>::generate_r1cs_constraints() {
                    /*
                      S_i = \sum_{k=0}^{i+1} A[i] * B[i]
                      S[0] = A[0] * B[0]
                      S[i+1] - S[i] = A[i] * B[i]
                    */
                    for (std::size_t i = 0; i < A.size(); ++i) {
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            A[i], B[i], (i == A.size() - 1 ? result : S[i]) + (i == 0 ? 0 * pb_variable<FieldType>(0) : -S[i - 1])));
                    }
                }

                template<typename FieldType>
                void inner_product_gadget<FieldType>::generate_r1cs_witness() {
                    FieldType total = FieldType::zero();
                    for (std::size_t i = 0; i < A.size(); ++i) {
                        A[i].evaluate(this->pb);
                        B[i].evaluate(this->pb);

                        total += this->pb.lc_val(A[i]) * this->pb.lc_val(B[i]);
                        this->pb.val(i == A.size() - 1 ? result : S[i]) = total;
                    }
                }

                template<typename FieldType>
                void test_inner_product_gadget(size_t n) {
                    protoboard<FieldType> pb;
                    pb_variable_array<FieldType> A;
                    A.allocate(pb, n);
                    pb_variable_array<FieldType> B;
                    B.allocate(pb, n);

                    pb_variable<FieldType> result;
                    result.allocate(pb);

                    inner_product_gadget<FieldType> g(pb, A, B, result);
                    g.generate_r1cs_constraints();

                    for (std::size_t i = 0; i < 1ul << n; ++i) {
                        for (std::size_t j = 0; j < 1ul << n; ++j) {
                            std::size_t correct = 0;
                            for (std::size_t k = 0; k < n; ++k) {
                                pb.val(A[k]) = (i & (1ul << k) ? FieldType::one() : FieldType::zero());
                                pb.val(B[k]) = (j & (1ul << k) ? FieldType::one() : FieldType::zero());
                                correct += ((i & (1ul << k)) && (j & (1ul << k)) ? 1 : 0);
                            }

                            g.generate_r1cs_witness();

                            assert(pb.val(result) == typename FieldType::value_type(correct));
                            assert(pb.is_satisfied());

                            pb.val(result) = typename FieldType::value_type(100 * n + 19);
                            assert(!pb.is_satisfied());
                        }
                    }
                }

                template<typename FieldType>
                void loose_multiplexing_gadget<FieldType>::generate_r1cs_constraints() {
                    /* \alpha_i (index - i) = 0 */
                    for (std::size_t i = 0; i < arr.size(); ++i) {
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(alpha[i], index - i, 0));
                    }

                    /* 1 * (\sum \alpha_i) = success_flag */
                    linear_combination<FieldType> a, b, c;
                    a.add_term(pb_variable<FieldType>(0));
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
                void loose_multiplexing_gadget<FieldType>::generate_r1cs_witness() {
                    /* assumes that idx can be fit in ulong; true for our purposes for now */
                    const typename FieldType::value_type valint = this->pb.val(index);
                    unsigned long idx = static_cast<unsigned long>(valint);
                    const typename FieldType::number_type arrsize(arr.size());

                    if (idx >= arr.size() || valint >= arrsize) {
                        for (std::size_t i = 0; i < arr.size(); ++i) {
                            this->pb.val(alpha[i]) = FieldType::zero();
                        }

                        this->pb.val(success_flag) = FieldType::zero();
                    } else {
                        for (std::size_t i = 0; i < arr.size(); ++i) {
                            this->pb.val(alpha[i]) = (i == idx ? FieldType::one() : FieldType::zero());
                        }

                        this->pb.val(success_flag) = FieldType::one();
                    }

                    compute_result->generate_r1cs_witness();
                }

                template<typename FieldType>
                void test_loose_multiplexing_gadget(size_t n) {
                    protoboard<FieldType> pb;

                    pb_variable_array<FieldType> arr;
                    arr.allocate(pb, 1ul << n);
                    pb_variable<FieldType> index, result, success_flag;
                    index.allocate(pb);
                    result.allocate(pb);
                    success_flag.allocate(pb);

                    loose_multiplexing_gadget<FieldType> g(pb, arr, index, result, success_flag);
                    g.generate_r1cs_constraints();

                    for (std::size_t i = 0; i < 1ul << n; ++i) {
                        pb.val(arr[i]) = typename FieldType::value_type((19 * i) % (1ul << n));
                    }

                    for (int idx = -1; idx <= (int)(1ul << n); ++idx) {
                        pb.val(index) = typename FieldType::value_type(idx);
                        g.generate_r1cs_witness();

                        if (0 <= idx && idx <= (int)(1ul << n) - 1) {
                            assert(pb.val(result) == typename FieldType::value_type((19 * idx) % (1ul << n)));
                            assert(pb.val(success_flag) == FieldType::one());
                            assert(pb.is_satisfied());
                            pb.val(result) -= FieldType::one();
                            assert(!pb.is_satisfied());
                        } else {
                            assert(pb.val(success_flag) == FieldType::zero());
                            assert(pb.is_satisfied());
                            pb.val(success_flag) = FieldType::one();
                            assert(!pb.is_satisfied());
                        }
                    }
                }

                template<typename FieldType, typename VarT>
                void create_linear_combination_constraints(protoboard<FieldType> &pb,
                                                           const std::vector<typename FieldType::value_type> &base,
                                                           const std::vector<std::pair<VarT, typename FieldType::value_type>> &v,
                                                           const VarT &target) {
                    for (std::size_t i = 0; i < base.size(); ++i) {
                        linear_combination<FieldType> a, b, c;

                        a.add_term(pb_variable<FieldType>(0));
                        b.add_term(pb_variable<FieldType>(0), base[i]);

                        for (auto &p : v) {
                            b.add_term(p.first.all_vars[i], p.second);
                        }

                        c.add_term(target.all_vars[i]);

                        pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a, b, c));
                    }
                }

                template<typename FieldType, typename VarT>
                void create_linear_combination_witness(protoboard<FieldType> &pb,
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
#endif    // BASIC_GADGETS_HPP_
