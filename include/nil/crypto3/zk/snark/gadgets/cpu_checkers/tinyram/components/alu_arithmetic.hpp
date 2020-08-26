//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for the TinyRAM ALU arithmetic gadgets.
//
// This gadget check the correct execution of arithmetic TinyRAM instructions.
//---------------------------------------------------------------------------//

#ifndef ALU_ARITHMETIC_HPP_
#define ALU_ARITHMETIC_HPP_

#include <memory>

#include <nil/crypto3/zk/snark/gadgets/basic_gadgets.hpp>
#include <nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/tinyram_protoboard.hpp>
#include <nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/word_variable_gadget.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {
                    size_t to_twos_complement(int i, size_t w)
                    {
                        assert(i >= -(1l<<(w-1)));
                        assert(i < (1l<<(w-1)));
                        return (i >= 0) ? i : i + (1l<<w);
                    }

                    int from_twos_complement(size_t i, size_t w)
                    {
                        assert(i < (1ul<<w));
                        return (i < (1ul<<(w-1))) ? i : i - (1ul<<w);
                    }
                }

                /* arithmetic gadgets */
                template<typename FieldType>
                class ALU_arithmetic_gadget : public tinyram_standard_gadget<FieldType> {
                public:
                    const pb_variable_array<FieldType> opcode_indicators;
                    const word_variable_gadget<FieldType> desval;
                    const word_variable_gadget<FieldType> arg1val;
                    const word_variable_gadget<FieldType> arg2val;
                    const pb_variable<FieldType> flag;
                    const pb_variable<FieldType> result;
                    const pb_variable<FieldType> result_flag;

                    ALU_arithmetic_gadget(tinyram_protoboard<FieldType> &pb,
                                          const pb_variable_array<FieldType> &opcode_indicators,
                                          const word_variable_gadget<FieldType> &desval,
                                          const word_variable_gadget<FieldType> &arg1val,
                                          const word_variable_gadget<FieldType> &arg2val,
                                          const pb_variable<FieldType> &flag,
                                          const pb_variable<FieldType> &result,
                                          const pb_variable<FieldType> &result_flag) :
                        tinyram_standard_gadget<FieldType>(pb),
                        opcode_indicators(opcode_indicators), desval(desval), arg1val(arg1val), arg2val(arg2val),
                        flag(flag), result(result), result_flag(result_flag) {
                    }
                };

                template<typename FieldType>
                class ALU_and_gadget : public ALU_arithmetic_gadget<FieldType> {
                private:
                    pb_variable_array<FieldType> res_word;
                    std::shared_ptr<packing_gadget<FieldType>> pack_result;
                    std::shared_ptr<disjunction_gadget<FieldType>> not_all_zeros;
                    pb_variable<FieldType> not_all_zeros_result;

                public:
                    ALU_and_gadget(tinyram_protoboard<FieldType> &pb,
                                   const pb_variable_array<FieldType> &opcode_indicators,
                                   const word_variable_gadget<FieldType> &desval,
                                   const word_variable_gadget<FieldType> &arg1val,
                                   const word_variable_gadget<FieldType> &arg2val,
                                   const pb_variable<FieldType> &flag,
                                   const pb_variable<FieldType> &result,
                                   const pb_variable<FieldType> &result_flag) :
                        ALU_arithmetic_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag, result,
                                                         result_flag) {
                        res_word.allocate(pb, pb.ap.w);
                        not_all_zeros_result.allocate(pb);

                        pack_result.reset(new packing_gadget<FieldType>(pb, res_word, result));
                        not_all_zeros.reset(new disjunction_gadget<FieldType>(pb, res_word, not_all_zeros_result));
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_ALU_and_gadget(const std::size_t w);

                template<typename FieldType>
                class ALU_or_gadget : public ALU_arithmetic_gadget<FieldType> {
                private:
                    pb_variable_array<FieldType> res_word;
                    std::shared_ptr<packing_gadget<FieldType>> pack_result;
                    std::shared_ptr<disjunction_gadget<FieldType>> not_all_zeros;
                    pb_variable<FieldType> not_all_zeros_result;

                public:
                    ALU_or_gadget(tinyram_protoboard<FieldType> &pb,
                                  const pb_variable_array<FieldType> &opcode_indicators,
                                  const word_variable_gadget<FieldType> &desval,
                                  const word_variable_gadget<FieldType> &arg1val,
                                  const word_variable_gadget<FieldType> &arg2val,
                                  const pb_variable<FieldType> &flag,
                                  const pb_variable<FieldType> &result,
                                  const pb_variable<FieldType> &result_flag) :
                        ALU_arithmetic_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag, result,
                                                         result_flag) {
                        res_word.allocate(pb, pb.ap.w);
                        not_all_zeros_result.allocate(pb);

                        pack_result.reset(new packing_gadget<FieldType>(pb, res_word, result));
                        not_all_zeros.reset(new disjunction_gadget<FieldType>(pb, res_word, not_all_zeros_result));
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_ALU_or_gadget(const std::size_t w);

                template<typename FieldType>
                class ALU_xor_gadget : public ALU_arithmetic_gadget<FieldType> {
                private:
                    pb_variable_array<FieldType> res_word;
                    std::shared_ptr<packing_gadget<FieldType>> pack_result;
                    std::shared_ptr<disjunction_gadget<FieldType>> not_all_zeros;
                    pb_variable<FieldType> not_all_zeros_result;

                public:
                    ALU_xor_gadget(tinyram_protoboard<FieldType> &pb,
                                   const pb_variable_array<FieldType> &opcode_indicators,
                                   const word_variable_gadget<FieldType> &desval,
                                   const word_variable_gadget<FieldType> &arg1val,
                                   const word_variable_gadget<FieldType> &arg2val,
                                   const pb_variable<FieldType> &flag,
                                   const pb_variable<FieldType> &result,
                                   const pb_variable<FieldType> &result_flag) :
                        ALU_arithmetic_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag, result,
                                                         result_flag) {
                        res_word.allocate(pb, pb.ap.w);
                        not_all_zeros_result.allocate(pb);

                        pack_result.reset(new packing_gadget<FieldType>(pb, res_word, result));
                        not_all_zeros.reset(new disjunction_gadget<FieldType>(pb, res_word, not_all_zeros_result));
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_ALU_xor_gadget(const std::size_t w);

                template<typename FieldType>
                class ALU_not_gadget : public ALU_arithmetic_gadget<FieldType> {
                    /* we do bitwise not, because we need to compute flag */
                private:
                    pb_variable_array<FieldType> res_word;
                    std::shared_ptr<packing_gadget<FieldType>> pack_result;
                    std::shared_ptr<disjunction_gadget<FieldType>> not_all_zeros;
                    pb_variable<FieldType> not_all_zeros_result;

                public:
                    ALU_not_gadget(tinyram_protoboard<FieldType> &pb,
                                   const pb_variable_array<FieldType> &opcode_indicators,
                                   const word_variable_gadget<FieldType> &desval,
                                   const word_variable_gadget<FieldType> &arg1val,
                                   const word_variable_gadget<FieldType> &arg2val,
                                   const pb_variable<FieldType> &flag,
                                   const pb_variable<FieldType> &result,
                                   const pb_variable<FieldType> &result_flag) :
                        ALU_arithmetic_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag, result,
                                                         result_flag) {
                        res_word.allocate(pb, pb.ap.w);
                        not_all_zeros_result.allocate(pb);

                        pack_result.reset(new packing_gadget<FieldType>(pb, res_word, result));
                        not_all_zeros.reset(new disjunction_gadget<FieldType>(pb, res_word, not_all_zeros_result));
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_ALU_not_gadget(const std::size_t w);

                template<typename FieldType>
                class ALU_add_gadget : public ALU_arithmetic_gadget<FieldType> {
                private:
                    pb_variable<FieldType> addition_result;
                    pb_variable_array<FieldType> res_word;
                    pb_variable_array<FieldType> res_word_and_flag;
                    std::shared_ptr<packing_gadget<FieldType>> unpack_addition, pack_result;

                public:
                    ALU_add_gadget(tinyram_protoboard<FieldType> &pb,
                                   const pb_variable_array<FieldType> &opcode_indicators,
                                   const word_variable_gadget<FieldType> &desval,
                                   const word_variable_gadget<FieldType> &arg1val,
                                   const word_variable_gadget<FieldType> &arg2val,
                                   const pb_variable<FieldType> &flag,
                                   const pb_variable<FieldType> &result,
                                   const pb_variable<FieldType> &result_flag) :
                        ALU_arithmetic_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag, result,
                                                         result_flag) {
                        addition_result.allocate(pb);
                        res_word.allocate(pb, pb.ap.w);

                        res_word_and_flag = res_word;
                        res_word_and_flag.emplace_back(result_flag);

                        unpack_addition.reset(new packing_gadget<FieldType>(pb, res_word_and_flag, addition_result));
                        pack_result.reset(new packing_gadget<FieldType>(pb, res_word, result));
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                void test_ALU_add_gadget(const std::size_t w);

                template<typename FieldType>
                class ALU_sub_gadget : public ALU_arithmetic_gadget<FieldType> {
                private:
                    pb_variable<FieldType> intermediate_result;
                    pb_variable<FieldType> negated_flag;
                    pb_variable_array<FieldType> res_word;
                    pb_variable_array<FieldType> res_word_and_negated_flag;

                    std::shared_ptr<packing_gadget<FieldType>> unpack_intermediate, pack_result;

                public:
                    ALU_sub_gadget(tinyram_protoboard<FieldType> &pb,
                                   const pb_variable_array<FieldType> &opcode_indicators,
                                   const word_variable_gadget<FieldType> &desval,
                                   const word_variable_gadget<FieldType> &arg1val,
                                   const word_variable_gadget<FieldType> &arg2val,
                                   const pb_variable<FieldType> &flag,
                                   const pb_variable<FieldType> &result,
                                   const pb_variable<FieldType> &result_flag) :
                        ALU_arithmetic_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag, result,
                                                         result_flag) {
                        intermediate_result.allocate(pb);
                        negated_flag.allocate(pb);
                        res_word.allocate(pb, pb.ap.w);

                        res_word_and_negated_flag = res_word;
                        res_word_and_negated_flag.emplace_back(negated_flag);

                        unpack_intermediate.reset(
                            new packing_gadget<FieldType>(pb, res_word_and_negated_flag, intermediate_result));
                        pack_result.reset(new packing_gadget<FieldType>(pb, res_word, result));
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                void test_ALU_sub_gadget(const std::size_t w);

                template<typename FieldType>
                class ALU_mov_gadget : public ALU_arithmetic_gadget<FieldType> {
                public:
                    ALU_mov_gadget(tinyram_protoboard<FieldType> &pb,
                                   const pb_variable_array<FieldType> &opcode_indicators,
                                   const word_variable_gadget<FieldType> &desval,
                                   const word_variable_gadget<FieldType> &arg1val,
                                   const word_variable_gadget<FieldType> &arg2val,
                                   const pb_variable<FieldType> &flag,
                                   const pb_variable<FieldType> &result,
                                   const pb_variable<FieldType> &result_flag) :
                        ALU_arithmetic_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag, result,
                                                         result_flag) {
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_ALU_mov_gadget(const std::size_t w);

                template<typename FieldType>
                class ALU_cmov_gadget : public ALU_arithmetic_gadget<FieldType> {
                public:
                    ALU_cmov_gadget(tinyram_protoboard<FieldType> &pb,
                                    const pb_variable_array<FieldType> &opcode_indicators,
                                    const word_variable_gadget<FieldType> &desval,
                                    const word_variable_gadget<FieldType> &arg1val,
                                    const word_variable_gadget<FieldType> &arg2val,
                                    const pb_variable<FieldType> &flag,
                                    const pb_variable<FieldType> &result,
                                    const pb_variable<FieldType> &result_flag) :
                        ALU_arithmetic_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag, result,
                                                         result_flag) {
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_ALU_cmov_gadget(const std::size_t w);

                template<typename FieldType>
                class ALU_cmp_gadget : public ALU_arithmetic_gadget<FieldType> {
                private:
                    comparison_gadget<FieldType> comparator;

                public:
                    const pb_variable<FieldType> cmpe_result;
                    const pb_variable<FieldType> cmpe_result_flag;
                    const pb_variable<FieldType> cmpa_result;
                    const pb_variable<FieldType> cmpa_result_flag;
                    const pb_variable<FieldType> cmpae_result;
                    const pb_variable<FieldType> cmpae_result_flag;

                    ALU_cmp_gadget(tinyram_protoboard<FieldType> &pb,
                                   const pb_variable_array<FieldType> &opcode_indicators,
                                   const word_variable_gadget<FieldType> &desval,
                                   const word_variable_gadget<FieldType> &arg1val,
                                   const word_variable_gadget<FieldType> &arg2val,
                                   const pb_variable<FieldType> &flag,
                                   const pb_variable<FieldType> &cmpe_result,
                                   const pb_variable<FieldType> &cmpe_result_flag,
                                   const pb_variable<FieldType> &cmpa_result,
                                   const pb_variable<FieldType> &cmpa_result_flag,
                                   const pb_variable<FieldType> &cmpae_result,
                                   const pb_variable<FieldType> &cmpae_result_flag) :
                        ALU_arithmetic_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                         cmpa_result, cmpa_result_flag),
                        comparator(pb, pb.ap.w, arg2val.packed, arg1val.packed, cmpa_result_flag, cmpae_result_flag),
                        cmpe_result(cmpe_result), cmpe_result_flag(cmpe_result_flag), cmpa_result(cmpa_result),
                        cmpa_result_flag(cmpa_result_flag), cmpae_result(cmpae_result),
                        cmpae_result_flag(cmpae_result_flag) {
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_ALU_cmpe_gadget(const std::size_t w);

                template<typename FieldType>
                void test_ALU_cmpa_gadget(const std::size_t w);

                template<typename FieldType>
                void test_ALU_cmpae_gadget(const std::size_t w);

                template<typename FieldType>
                class ALU_cmps_gadget : public ALU_arithmetic_gadget<FieldType> {
                private:
                    pb_variable<FieldType> negated_arg1val_sign;
                    pb_variable<FieldType> negated_arg2val_sign;
                    pb_variable_array<FieldType> modified_arg1;
                    pb_variable_array<FieldType> modified_arg2;
                    pb_variable<FieldType> packed_modified_arg1;
                    pb_variable<FieldType> packed_modified_arg2;
                    std::shared_ptr<packing_gadget<FieldType>> pack_modified_arg1;
                    std::shared_ptr<packing_gadget<FieldType>> pack_modified_arg2;
                    std::shared_ptr<comparison_gadget<FieldType>> comparator;

                public:
                    const pb_variable<FieldType> cmpg_result;
                    const pb_variable<FieldType> cmpg_result_flag;
                    const pb_variable<FieldType> cmpge_result;
                    const pb_variable<FieldType> cmpge_result_flag;

                    ALU_cmps_gadget(tinyram_protoboard<FieldType> &pb,
                                    const pb_variable_array<FieldType> &opcode_indicators,
                                    const word_variable_gadget<FieldType> &desval,
                                    const word_variable_gadget<FieldType> &arg1val,
                                    const word_variable_gadget<FieldType> &arg2val,
                                    const pb_variable<FieldType> &flag,
                                    const pb_variable<FieldType> &cmpg_result,
                                    const pb_variable<FieldType> &cmpg_result_flag,
                                    const pb_variable<FieldType> &cmpge_result,
                                    const pb_variable<FieldType> &cmpge_result_flag) :
                        ALU_arithmetic_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                         cmpg_result, cmpg_result_flag),
                        cmpg_result(cmpg_result), cmpg_result_flag(cmpg_result_flag), cmpge_result(cmpge_result),
                        cmpge_result_flag(cmpge_result_flag) {
                        negated_arg1val_sign.allocate(pb);
                        negated_arg2val_sign.allocate(pb);

                        modified_arg1 = pb_variable_array<FieldType>(arg1val.bits.begin(), --arg1val.bits.end());
                        modified_arg1.emplace_back(negated_arg1val_sign);

                        modified_arg2 = pb_variable_array<FieldType>(arg2val.bits.begin(), --arg2val.bits.end());
                        modified_arg2.emplace_back(negated_arg2val_sign);

                        packed_modified_arg1.allocate(pb);
                        packed_modified_arg2.allocate(pb);

                        pack_modified_arg1.reset(
                            new packing_gadget<FieldType>(pb, modified_arg1, packed_modified_arg1));
                        pack_modified_arg2.reset(
                            new packing_gadget<FieldType>(pb, modified_arg2, packed_modified_arg2));

                        comparator.reset(new comparison_gadget<FieldType>(pb, pb.ap.w, packed_modified_arg2,
                                                                          packed_modified_arg1, cmpg_result_flag,
                                                                          cmpge_result_flag));
                    }
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_ALU_cmpg_gadget(const std::size_t w);

                template<typename FieldType>
                void test_ALU_cmpge_gadget(const std::size_t w);

                template<typename FieldType>
                class ALU_umul_gadget : public ALU_arithmetic_gadget<FieldType> {
                private:
                    dual_variable_gadget<FieldType> mul_result;
                    pb_variable_array<FieldType> mull_bits;
                    pb_variable_array<FieldType> umulh_bits;
                    pb_variable<FieldType> result_flag;
                    std::shared_ptr<packing_gadget<FieldType>> pack_mull_result;
                    std::shared_ptr<packing_gadget<FieldType>> pack_umulh_result;
                    std::shared_ptr<disjunction_gadget<FieldType>> compute_flag;

                public:
                    const pb_variable<FieldType> mull_result;
                    const pb_variable<FieldType> mull_flag;
                    const pb_variable<FieldType> umulh_result;
                    const pb_variable<FieldType> umulh_flag;

                    ALU_umul_gadget(tinyram_protoboard<FieldType> &pb,
                                    const pb_variable_array<FieldType> &opcode_indicators,
                                    const word_variable_gadget<FieldType> &desval,
                                    const word_variable_gadget<FieldType> &arg1val,
                                    const word_variable_gadget<FieldType> &arg2val,
                                    const pb_variable<FieldType> &flag,
                                    const pb_variable<FieldType> &mull_result,
                                    const pb_variable<FieldType> &mull_flag,
                                    const pb_variable<FieldType> &umulh_result,
                                    const pb_variable<FieldType> &umulh_flag) :
                        ALU_arithmetic_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                         mull_result, mull_flag),
                        mul_result(pb, 2 * pb.ap.w), mull_result(mull_result), mull_flag(mull_flag),
                        umulh_result(umulh_result), umulh_flag(umulh_flag) {
                        mull_bits.insert(mull_bits.end(), mul_result.bits.begin(), mul_result.bits.begin() + pb.ap.w);
                        umulh_bits.insert(umulh_bits.end(), mul_result.bits.begin() + pb.ap.w,
                                          mul_result.bits.begin() + 2 * pb.ap.w);

                        pack_mull_result.reset(new packing_gadget<FieldType>(pb, mull_bits, mull_result));
                        pack_umulh_result.reset(new packing_gadget<FieldType>(pb, umulh_bits, umulh_result));

                        result_flag.allocate(pb);
                        compute_flag.reset(new disjunction_gadget<FieldType>(pb, umulh_bits, result_flag));
                    }
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_ALU_mull_gadget(const std::size_t w);

                template<typename FieldType>
                void test_ALU_umulh_gadget(const std::size_t w);

                template<typename FieldType>
                class ALU_smul_gadget : public ALU_arithmetic_gadget<FieldType> {
                private:
                    dual_variable_gadget<FieldType> mul_result;
                    pb_variable_array<FieldType> smulh_bits;

                    pb_variable<FieldType> top;
                    std::shared_ptr<packing_gadget<FieldType>> pack_top;

                    pb_variable<FieldType> is_top_empty, is_top_empty_aux;
                    pb_variable<FieldType> is_top_full, is_top_full_aux;

                    pb_variable<FieldType> result_flag;
                    std::shared_ptr<packing_gadget<FieldType>> pack_smulh_result;

                public:
                    const pb_variable<FieldType> smulh_result;
                    const pb_variable<FieldType> smulh_flag;

                    ALU_smul_gadget(tinyram_protoboard<FieldType> &pb,
                                    const pb_variable_array<FieldType> &opcode_indicators,
                                    const word_variable_gadget<FieldType> &desval,
                                    const word_variable_gadget<FieldType> &arg1val,
                                    const word_variable_gadget<FieldType> &arg2val,
                                    const pb_variable<FieldType> &flag,
                                    const pb_variable<FieldType> &smulh_result,
                                    const pb_variable<FieldType> &smulh_flag) :
                        ALU_arithmetic_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                         smulh_result, smulh_flag),
                        mul_result(pb, 2 * pb.ap.w + 1), /* see witness map for explanation for 2w+1 */
                        smulh_result(smulh_result), smulh_flag(smulh_flag) {
                        smulh_bits.insert(smulh_bits.end(), mul_result.bits.begin() + pb.ap.w,
                                          mul_result.bits.begin() + 2 * pb.ap.w);

                        pack_smulh_result.reset(new packing_gadget<FieldType>(pb, smulh_bits, smulh_result));

                        top.allocate(pb);
                        pack_top.reset(new packing_gadget<FieldType>(
                            pb,
                            pb_variable_array<FieldType>(mul_result.bits.begin() + pb.ap.w - 1,
                                                         mul_result.bits.begin() + 2 * pb.ap.w),
                            top));

                        is_top_empty.allocate(pb);
                        is_top_empty_aux.allocate(pb);

                        is_top_full.allocate(pb);
                        is_top_full_aux.allocate(pb);

                        result_flag.allocate(pb);
                    }
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_ALU_smulh_gadget(const std::size_t w);

                template<typename FieldType>
                class ALU_divmod_gadget : public ALU_arithmetic_gadget<FieldType> {
                    /*
                      <<<<<<< Updated upstream
                      B * q + r = A_aux = A * B_nonzero
                      q * (1-B_nonzero) = 0
                      A<B_gadget<FieldType>(r < B, less=B_nonzero, leq=ONE)
                      =======
                      B * q + r = A

                      r <= B
                      >>>>>>> Stashed changes
                    */
                private:
                    pb_variable<FieldType> B_inv;
                    pb_variable<FieldType> B_nonzero;
                    pb_variable<FieldType> A_aux;
                    std::shared_ptr<comparison_gadget<FieldType>> r_less_B;

                public:
                    const pb_variable<FieldType> udiv_result;
                    const pb_variable<FieldType> udiv_flag;
                    const pb_variable<FieldType> umod_result;
                    const pb_variable<FieldType> umod_flag;

                    ALU_divmod_gadget(tinyram_protoboard<FieldType> &pb,
                                      const pb_variable_array<FieldType> &opcode_indicators,
                                      const word_variable_gadget<FieldType> &desval,
                                      const word_variable_gadget<FieldType> &arg1val,
                                      const word_variable_gadget<FieldType> &arg2val,
                                      const pb_variable<FieldType> &flag,
                                      const pb_variable<FieldType> &udiv_result,
                                      const pb_variable<FieldType> &udiv_flag,
                                      const pb_variable<FieldType> &umod_result,
                                      const pb_variable<FieldType> &umod_flag) :
                        ALU_arithmetic_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                         udiv_result, udiv_flag),
                        udiv_result(udiv_result), udiv_flag(udiv_flag), umod_result(umod_result), umod_flag(umod_flag) {
                        B_inv.allocate(pb);
                        B_nonzero.allocate(pb);
                        A_aux.allocate(pb);
                        r_less_B.reset(
                            new comparison_gadget<FieldType>(pb, pb.ap.w, umod_result, arg2val.packed, B_nonzero, pb_variable<FieldType>(0)));
                    }
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_ALU_udiv_gadget(const std::size_t w);

                template<typename FieldType>
                void test_ALU_umod_gadget(const std::size_t w);

                template<typename FieldType>
                class ALU_shr_shl_gadget : public ALU_arithmetic_gadget<FieldType> {
                private:
                    pb_variable<FieldType> reversed_input;
                    std::shared_ptr<packing_gadget<FieldType>> pack_reversed_input;

                    pb_variable_array<FieldType> barrel_right_internal;
                    std::vector<pb_variable_array<FieldType>> shifted_out_bits;

                    pb_variable<FieldType> is_oversize_shift;
                    std::shared_ptr<disjunction_gadget<FieldType>> check_oversize_shift;
                    pb_variable<FieldType> result;

                    pb_variable_array<FieldType> result_bits;
                    std::shared_ptr<packing_gadget<FieldType>> unpack_result;
                    pb_variable<FieldType> reversed_result;
                    std::shared_ptr<packing_gadget<FieldType>> pack_reversed_result;

                public:
                    pb_variable<FieldType> shr_result;
                    pb_variable<FieldType> shr_flag;
                    pb_variable<FieldType> shl_result;
                    pb_variable<FieldType> shl_flag;

                    std::size_t logw;

                    ALU_shr_shl_gadget(tinyram_protoboard<FieldType> &pb,
                                       const pb_variable_array<FieldType> &opcode_indicators,
                                       const word_variable_gadget<FieldType> &desval,
                                       const word_variable_gadget<FieldType> &arg1val,
                                       const word_variable_gadget<FieldType> &arg2val,
                                       const pb_variable<FieldType> &flag,
                                       const pb_variable<FieldType> &shr_result,
                                       const pb_variable<FieldType> &shr_flag,
                                       const pb_variable<FieldType> &shl_result,
                                       const pb_variable<FieldType> &shl_flag) :
                        ALU_arithmetic_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                         shr_result, shr_flag),
                        shr_result(shr_result), shr_flag(shr_flag), shl_result(shl_result), shl_flag(shl_flag) {
                        logw = static_cast<std::size_t>(std::ceil(std::log2(pb.ap.w)));

                        reversed_input.allocate(pb);
                        pack_reversed_input.reset(new packing_gadget<FieldType>(
                            pb, pb_variable_array<FieldType>(arg1val.bits.rbegin(), arg1val.bits.rend()),
                            reversed_input));

                        barrel_right_internal.allocate(pb, logw + 1);

                        shifted_out_bits.resize(logw);
                        for (std::size_t i = 0; i < logw; ++i) {
                            shifted_out_bits[i].allocate(pb, 1ul << i);
                        }

                        is_oversize_shift.allocate(pb);
                        check_oversize_shift.reset(new disjunction_gadget<FieldType>(
                            pb,
                            pb_variable_array<FieldType>(arg2val.bits.begin() + logw, arg2val.bits.end()),
                            is_oversize_shift));
                        result.allocate(pb);

                        result_bits.allocate(pb, pb.ap.w);
                        unpack_result.reset(new packing_gadget<FieldType>(pb, result_bits, result));

                        reversed_result.allocate(pb);
                        pack_reversed_result.reset(new packing_gadget<FieldType>(
                            pb, pb_variable_array<FieldType>(result_bits.rbegin(), result_bits.rend()),
                            reversed_result));
                    }
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_ALU_shr_gadget(const std::size_t w);

                template<typename FieldType>
                void test_ALU_shl_gadget(const std::size_t w);

                /* the code here is full of template lambda magic, but it is better to
                   have limited presence of such code than to have code duplication in
                   testing functions, which basically do the same thing: brute force
                   the range of inputs which different success predicates */

                template<class T, typename FieldType>
                using initializer_fn = std::function<T *(tinyram_protoboard<FieldType> &,      // pb
                                                         pb_variable_array<FieldType> &,       // opcode_indicators
                                                         word_variable_gadget<FieldType> &,    // desval
                                                         word_variable_gadget<FieldType> &,    // arg1val
                                                         word_variable_gadget<FieldType> &,    // arg2val
                                                         pb_variable<FieldType> &,             // flag
                                                         pb_variable<FieldType> &,             // result
                                                         pb_variable<FieldType> &              // result_flag
                                                         )>;

                template<class T, typename FieldType>
                void brute_force_arithmetic_gadget(const std::size_t w,
                                                   const std::size_t opcode,
                                                   initializer_fn<T, FieldType>
                                                       initializer,
                                                   std::function<std::size_t(std::size_t, bool, std::size_t, std::size_t)>
                                                       res_function,
                                                   std::function<bool(std::size_t, bool, std::size_t, std::size_t)>
                                                       flag_function)
                /* parameters for res_function and flag_function are both desval, flag, arg1val, arg2val */
                {
                    tinyram_architecture_params ap(w, 16);
                    tinyram_program P;
                    P.instructions = generate_tinyram_prelude(ap);
                    tinyram_protoboard<FieldType> pb(ap, P.size(), 0, 10);

                    pb_variable_array<FieldType> opcode_indicators;
                    opcode_indicators.allocate(pb, 1ul << ap.opcode_width());
                    for (std::size_t i = 0; i < 1ul << ap.opcode_width(); ++i) {
                        pb.val(opcode_indicators[i]) = (i == opcode ? FieldType::one() : FieldType::zero());
                    }

                    word_variable_gadget<FieldType> desval(pb);
                    desval.generate_r1cs_constraints(true);
                    word_variable_gadget<FieldType> arg1val(pb);
                    arg1val.generate_r1cs_constraints(true);
                    word_variable_gadget<FieldType> arg2val(pb);
                    arg2val.generate_r1cs_constraints(true);
                    pb_variable<FieldType> flag;
                    flag.allocate(pb);
                    pb_variable<FieldType> result;
                    result.allocate(pb);
                    pb_variable<FieldType> result_flag;
                    result_flag.allocate(pb);

                    std::unique_ptr<T> g;
                    g.reset(initializer(pb, opcode_indicators, desval, arg1val, arg2val, flag, result, result_flag));
                    g->generate_r1cs_constraints();

                    for (std::size_t des = 0; des < (1u << w); ++des) {
                        pb.val(desval.packed) = typename FieldType::value_type(des);
                        desval.generate_r1cs_witness_from_packed();

                        for (char f = 0; f <= 1; ++f) {
                            pb.val(flag) = (f ? FieldType::one() : FieldType::zero());

                            for (std::size_t arg1 = 0; arg1 < (1u << w); ++arg1) {
                                pb.val(arg1val.packed) = typename FieldType::value_type(arg1);
                                arg1val.generate_r1cs_witness_from_packed();

                                for (std::size_t arg2 = 0; arg2 < (1u << w); ++arg2) {
                                    pb.val(arg2val.packed) = typename FieldType::value_type(arg2);
                                    arg2val.generate_r1cs_witness_from_packed();

                                    std::size_t res = res_function(des, f, arg1, arg2);
                                    bool res_f = flag_function(des, f, arg1, arg2);

                                    g->generate_r1cs_witness();

                                    assert(pb.is_satisfied());
                                    assert(pb.val(result) == typename FieldType::value_type(res));
                                    assert(pb.val(result_flag) == (res_f ? FieldType::one() : FieldType::zero()));
                                }
                            }
                        }
                    }
                }

                /* and */
                template<typename FieldType>
                void ALU_and_gadget<FieldType>::generate_r1cs_constraints() {
                    for (std::size_t i = 0; i < this->pb.ap.w; ++i) {
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            {this->arg1val.bits[i]}, {this->arg2val.bits[i]}, {this->res_word[i]}));
                    }

                    /* generate result */
                    pack_result->generate_r1cs_constraints(false);
                    not_all_zeros->generate_r1cs_constraints();

                    /* result_flag = 1 - not_all_zeros = result is 0^w */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        {pb_variable<FieldType>(0)}, {pb_variable<FieldType>(0), this->not_all_zeros_result * (-1)}, {this->result_flag}));
                }

                template<typename FieldType>
                void ALU_and_gadget<FieldType>::generate_r1cs_witness() {
                    for (std::size_t i = 0; i < this->pb.ap.w; ++i) {
                        bool b1 = this->pb.val(this->arg1val.bits[i]) == FieldType::one();
                        bool b2 = this->pb.val(this->arg2val.bits[i]) == FieldType::one();

                        this->pb.val(this->res_word[i]) = (b1 && b2 ? FieldType::one() : FieldType::zero());
                    }

                    pack_result->generate_r1cs_witness_from_bits();
                    not_all_zeros->generate_r1cs_witness();
                    this->pb.val(this->result_flag) = FieldType::one() - this->pb.val(not_all_zeros_result);
                }

                template<typename FieldType>
                void test_ALU_and_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_and_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_AND,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_and_gadget<FieldType> * {
                            return new ALU_and_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                                 result, result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return x & y; },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool { return (x & y) == 0; });
                }

                /* or */
                template<typename FieldType>
                void ALU_or_gadget<FieldType>::generate_r1cs_constraints() {
                    for (std::size_t i = 0; i < this->pb.ap.w; ++i) {
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>({pb_variable<FieldType>(0), this->arg1val.bits[i] * (-1)},
                                                                                {pb_variable<FieldType>(0), this->arg2val.bits[i] * (-1)},
                                                                                {pb_variable<FieldType>(0), this->res_word[i] * (-1)}));
                    }

                    /* generate result */
                    pack_result->generate_r1cs_constraints(false);
                    not_all_zeros->generate_r1cs_constraints();

                    /* result_flag = 1 - not_all_zeros = result is 0^w */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        {pb_variable<FieldType>(0)}, {pb_variable<FieldType>(0), this->not_all_zeros_result * (-1)}, {this->result_flag}));
                }

                template<typename FieldType>
                void ALU_or_gadget<FieldType>::generate_r1cs_witness() {
                    for (std::size_t i = 0; i < this->pb.ap.w; ++i) {
                        bool b1 = this->pb.val(this->arg1val.bits[i]) == FieldType::one();
                        bool b2 = this->pb.val(this->arg2val.bits[i]) == FieldType::one();

                        this->pb.val(this->res_word[i]) = (b1 || b2 ? FieldType::one() : FieldType::zero());
                    }

                    pack_result->generate_r1cs_witness_from_bits();
                    not_all_zeros->generate_r1cs_witness();
                    this->pb.val(this->result_flag) = FieldType::one() - this->pb.val(this->not_all_zeros_result);
                }

                template<typename FieldType>
                void test_ALU_or_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_or_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_OR,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_or_gadget<FieldType> * {
                            return new ALU_or_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                                result, result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return x | y; },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool { return (x | y) == 0; });
                }

                /* xor */
                template<typename FieldType>
                void ALU_xor_gadget<FieldType>::generate_r1cs_constraints() {
                    for (std::size_t i = 0; i < this->pb.ap.w; ++i) {
                        /* a = b ^ c <=> a = b + c - 2*b*c, (2*b)*c = b+c - a */
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            {this->arg1val.bits[i] * 2},
                            {this->arg2val.bits[i]},
                            {this->arg1val.bits[i], this->arg2val.bits[i], this->res_word[i] * (-1)}));
                    }

                    /* generate result */
                    pack_result->generate_r1cs_constraints(false);
                    not_all_zeros->generate_r1cs_constraints();

                    /* result_flag = 1 - not_all_zeros = result is 0^w */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        {pb_variable<FieldType>(0)}, {pb_variable<FieldType>(0), this->not_all_zeros_result * (-1)}, {this->result_flag}));
                }

                template<typename FieldType>
                void ALU_xor_gadget<FieldType>::generate_r1cs_witness() {
                    for (std::size_t i = 0; i < this->pb.ap.w; ++i) {
                        bool b1 = this->pb.val(this->arg1val.bits[i]) == FieldType::one();
                        bool b2 = this->pb.val(this->arg2val.bits[i]) == FieldType::one();

                        this->pb.val(this->res_word[i]) = (b1 ^ b2 ? FieldType::one() : FieldType::zero());
                    }

                    pack_result->generate_r1cs_witness_from_bits();
                    not_all_zeros->generate_r1cs_witness();
                    this->pb.val(this->result_flag) = FieldType::one() - this->pb.val(this->not_all_zeros_result);
                }

                template<typename FieldType>
                void test_ALU_xor_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_xor_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_XOR,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_xor_gadget<FieldType> * {
                            return new ALU_xor_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                                 result, result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return x ^ y; },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool { return (x ^ y) == 0; });
                }

                /* not */
                template<typename FieldType>
                void ALU_not_gadget<FieldType>::generate_r1cs_constraints() {
                    for (std::size_t i = 0; i < this->pb.ap.w; ++i) {
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            {pb_variable<FieldType>(0)}, {pb_variable<FieldType>(0), this->arg2val.bits[i] * (-1)}, {this->res_word[i]}));
                    }

                    /* generate result */
                    pack_result->generate_r1cs_constraints(false);
                    not_all_zeros->generate_r1cs_constraints();

                    /* result_flag = 1 - not_all_zeros = result is 0^w */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        {pb_variable<FieldType>(0)}, {pb_variable<FieldType>(0), this->not_all_zeros_result * (-1)}, {this->result_flag}));
                }

                template<typename FieldType>
                void ALU_not_gadget<FieldType>::generate_r1cs_witness() {
                    for (std::size_t i = 0; i < this->pb.ap.w; ++i) {
                        bool b2 = this->pb.val(this->arg2val.bits[i]) == FieldType::one();

                        this->pb.val(this->res_word[i]) = (!b2 ? FieldType::one() : FieldType::zero());
                    }

                    pack_result->generate_r1cs_witness_from_bits();
                    not_all_zeros->generate_r1cs_witness();
                    this->pb.val(this->result_flag) = FieldType::one() - this->pb.val(this->not_all_zeros_result);
                }

                template<typename FieldType>
                void test_ALU_not_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_not_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_NOT,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_not_gadget<FieldType> * {
                            return new ALU_not_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                                 result, result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return (1ul << w) - 1 - y; },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool { return ((1ul << w) - 1 - y) == 0; });
                }

                /* add */
                template<typename FieldType>
                void ALU_add_gadget<FieldType>::generate_r1cs_constraints() {
                    /* addition_result = 1 * (arg1val + arg2val) */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        {pb_variable<FieldType>(0)}, {this->arg1val.packed, this->arg2val.packed}, {this->addition_result}));

                    /* unpack into bits */
                    unpack_addition->generate_r1cs_constraints(true);

                    /* generate result */
                    pack_result->generate_r1cs_constraints(false);
                }

                template<typename FieldType>
                void ALU_add_gadget<FieldType>::generate_r1cs_witness() {
                    this->pb.val(addition_result) =
                        this->pb.val(this->arg1val.packed) + this->pb.val(this->arg2val.packed);
                    unpack_addition->generate_r1cs_witness_from_packed();
                    pack_result->generate_r1cs_witness_from_bits();
                }

                template<typename FieldType>
                void test_ALU_add_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_add_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_ADD,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_add_gadget<FieldType> * {
                            return new ALU_add_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                                 result, result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return (x + y) % (1ul << w); },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool { return (x + y) >= (1ul << w); });
                }

                /* sub */
                template<typename FieldType>
                void ALU_sub_gadget<FieldType>::generate_r1cs_constraints() {
                    /* intermediate_result = 2^w + (arg1val - arg2val) */
                    FieldType twoi = FieldType::one();

                    linear_combination<FieldType> a, b, c;

                    a.add_term(0, 1);
                    for (std::size_t i = 0; i < this->pb.ap.w; ++i) {
                        twoi = twoi + twoi;
                    }
                    b.add_term(0, twoi);
                    b.add_term(this->arg1val.packed, 1);
                    b.add_term(this->arg2val.packed, -1);
                    c.add_term(intermediate_result, 1);

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a, b, c));

                    /* unpack into bits */
                    unpack_intermediate->generate_r1cs_constraints(true);

                    /* generate result */
                    pack_result->generate_r1cs_constraints(false);
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({pb_variable<FieldType>(0)}, {pb_variable<FieldType>(0), this->negated_flag * (-1)}, {this->result_flag}));
                }

                template<typename FieldType>
                void ALU_sub_gadget<FieldType>::generate_r1cs_witness() {
                    FieldType twoi = FieldType::one();
                    for (std::size_t i = 0; i < this->pb.ap.w; ++i) {
                        twoi = twoi + twoi;
                    }

                    this->pb.val(intermediate_result) =
                        twoi + this->pb.val(this->arg1val.packed) - this->pb.val(this->arg2val.packed);
                    unpack_intermediate->generate_r1cs_witness_from_packed();
                    pack_result->generate_r1cs_witness_from_bits();
                    this->pb.val(this->result_flag) = FieldType::one() - this->pb.val(this->negated_flag);
                }

                template<typename FieldType>
                void test_ALU_sub_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_sub_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_SUB,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_sub_gadget<FieldType> * {
                            return new ALU_sub_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                                 result, result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t {
                            const std::size_t unsigned_result = ((1ul << w) + x - y) % (1ul << w);
                            return unsigned_result;
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool {
                            const std::size_t msb = ((1ul << w) + x - y) >> w;
                            return (msb == 0);
                        });
                }

                /* mov */
                template<typename FieldType>
                void ALU_mov_gadget<FieldType>::generate_r1cs_constraints() {
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({pb_variable<FieldType>(0)}, {this->arg2val.packed}, {this->result}));

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>({pb_variable<FieldType>(0)}, {this->flag}, {this->result_flag}));
                }

                template<typename FieldType>
                void ALU_mov_gadget<FieldType>::generate_r1cs_witness() {
                    this->pb.val(this->result) = this->pb.val(this->arg2val.packed);
                    this->pb.val(this->result_flag) = this->pb.val(this->flag);
                }

                template<typename FieldType>
                void test_ALU_mov_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_mov_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_MOV,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_mov_gadget<FieldType> * {
                            return new ALU_mov_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                                 result, result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return y; },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool { return f; });
                }

                /* cmov */
                template<typename FieldType>
                void ALU_cmov_gadget<FieldType>::generate_r1cs_constraints() {
                    /*
                      flag1 * arg2val + (1-flag1) * desval = result
                      flag1 * (arg2val - desval) = result - desval
                    */
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({this->flag},
                                                   {this->arg2val.packed, this->desval.packed * (-1)},
                                                   {this->result, this->desval.packed * (-1)}));

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>({pb_variable<FieldType>(0)}, {this->flag}, {this->result_flag}));
                }

                template<typename FieldType>
                void ALU_cmov_gadget<FieldType>::generate_r1cs_witness() {
                    this->pb.val(this->result) =
                        ((this->pb.val(this->flag) == FieldType::one()) ? this->pb.val(this->arg2val.packed) :
                                                                          this->pb.val(this->desval.packed));
                    this->pb.val(this->result_flag) = this->pb.val(this->flag);
                }

                template<typename FieldType>
                void test_ALU_cmov_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_cmov_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_CMOV,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_cmov_gadget<FieldType> * {
                            return new ALU_cmov_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                                  result, result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return f ? y : des; },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool { return f; });
                }

                /* unsigned comparison */
                template<typename FieldType>
                void ALU_cmp_gadget<FieldType>::generate_r1cs_constraints() {
                    comparator.generate_r1cs_constraints();
                    /*
                      cmpe = cmpae * (1-cmpa)
                    */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        {cmpae_result_flag}, {pb_variable<FieldType>(0), cmpa_result_flag * (-1)}, {cmpe_result_flag}));

                    /* copy over results */
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({pb_variable<FieldType>(0)}, {this->desval.packed}, {cmpe_result}));

                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({pb_variable<FieldType>(0)}, {this->desval.packed}, {cmpa_result}));

                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({pb_variable<FieldType>(0)}, {this->desval.packed}, {cmpae_result}));
                }

                template<typename FieldType>
                void ALU_cmp_gadget<FieldType>::generate_r1cs_witness() {
                    comparator.generate_r1cs_witness();

                    this->pb.val(cmpe_result) = this->pb.val(this->desval.packed);
                    this->pb.val(cmpa_result) = this->pb.val(this->desval.packed);
                    this->pb.val(cmpae_result) = this->pb.val(this->desval.packed);

                    this->pb.val(cmpe_result_flag) = ((this->pb.val(cmpae_result_flag) == FieldType::one()) &&
                                                              (this->pb.val(cmpa_result_flag) == FieldType::zero()) ?
                                                          FieldType::one() :
                                                          FieldType::zero());
                }

                template<typename FieldType>
                void test_ALU_cmpe_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_cmp_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_CMPE,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_cmp_gadget<FieldType> * {
                            pb_variable<FieldType> cmpa_result;
                            cmpa_result.allocate(pb);
                            pb_variable<FieldType> cmpa_result_flag;
                            cmpa_result_flag.allocate(pb);
                            pb_variable<FieldType> cmpae_result;
                            cmpae_result.allocate(pb);
                            pb_variable<FieldType> cmpae_result_flag;
                            cmpae_result_flag.allocate(pb);
                            return new ALU_cmp_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                                 result, result_flag, cmpa_result, cmpa_result_flag,
                                                                 cmpae_result, cmpae_result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return des; },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool { return x == y; });
                }

                template<typename FieldType>
                void test_ALU_cmpa_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_cmp_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_CMPA,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_cmp_gadget<FieldType> * {
                            pb_variable<FieldType> cmpe_result;
                            cmpe_result.allocate(pb);
                            pb_variable<FieldType> cmpe_result_flag;
                            cmpe_result_flag.allocate(pb);
                            pb_variable<FieldType> cmpae_result;
                            cmpae_result.allocate(pb);
                            pb_variable<FieldType> cmpae_result_flag;
                            cmpae_result_flag.allocate(pb);
                            return new ALU_cmp_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                                 cmpe_result, cmpe_result_flag, result, result_flag,
                                                                 cmpae_result, cmpae_result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return des; },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool { return x > y; });
                }

                template<typename FieldType>
                void test_ALU_cmpae_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_cmp_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_CMPAE,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_cmp_gadget<FieldType> * {
                            pb_variable<FieldType> cmpe_result;
                            cmpe_result.allocate(pb);
                            pb_variable<FieldType> cmpe_result_flag;
                            cmpe_result_flag.allocate(pb);
                            pb_variable<FieldType> cmpa_result;
                            cmpa_result.allocate(pb);
                            pb_variable<FieldType> cmpa_result_flag;
                            cmpa_result_flag.allocate(pb);
                            return new ALU_cmp_gadget<FieldType>(
                                pb, opcode_indicators, desval, arg1val, arg2val, flag, cmpe_result, cmpe_result_flag,
                                cmpa_result, cmpa_result_flag, result, result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return des; },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool { return x >= y; });
                }

                /* signed comparison */
                template<typename FieldType>
                void ALU_cmps_gadget<FieldType>::generate_r1cs_constraints() {
                    /* negate sign bits */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        {pb_variable<FieldType>(0)}, {pb_variable<FieldType>(0), this->arg1val.bits[this->pb.ap.w - 1] * (-1)}, {negated_arg1val_sign}));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        {pb_variable<FieldType>(0)}, {pb_variable<FieldType>(0), this->arg2val.bits[this->pb.ap.w - 1] * (-1)}, {negated_arg2val_sign}));

                    /* pack */
                    pack_modified_arg1->generate_r1cs_constraints(false);
                    pack_modified_arg2->generate_r1cs_constraints(false);

                    /* compare */
                    comparator->generate_r1cs_constraints();

                    /* copy over results */
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({pb_variable<FieldType>(0)}, {this->desval.packed}, {cmpg_result}));

                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({pb_variable<FieldType>(0)}, {this->desval.packed}, {cmpge_result}));
                }

                template<typename FieldType>
                void ALU_cmps_gadget<FieldType>::generate_r1cs_witness() {
                    /* negate sign bits */
                    this->pb.val(negated_arg1val_sign) =
                        FieldType::one() - this->pb.val(this->arg1val.bits[this->pb.ap.w - 1]);
                    this->pb.val(negated_arg2val_sign) =
                        FieldType::one() - this->pb.val(this->arg2val.bits[this->pb.ap.w - 1]);

                    /* pack */
                    pack_modified_arg1->generate_r1cs_witness_from_bits();
                    pack_modified_arg2->generate_r1cs_witness_from_bits();

                    /* produce result */
                    comparator->generate_r1cs_witness();

                    this->pb.val(cmpg_result) = this->pb.val(this->desval.packed);
                    this->pb.val(cmpge_result) = this->pb.val(this->desval.packed);
                }

                template<typename FieldType>
                void test_ALU_cmpg_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_cmps_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_CMPG,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_cmps_gadget<FieldType> * {
                            pb_variable<FieldType> cmpge_result;
                            cmpge_result.allocate(pb);
                            pb_variable<FieldType> cmpge_result_flag;
                            cmpge_result_flag.allocate(pb);
                            return new ALU_cmps_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                                  result, result_flag, cmpge_result, cmpge_result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return des; },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool {
                            return (detail::from_twos_complement(x, w) > detail::from_twos_complement(y, w));
                        });
                }

                template<typename FieldType>
                void test_ALU_cmpge_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_cmps_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_CMPGE,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_cmps_gadget<FieldType> * {
                            pb_variable<FieldType> cmpg_result;
                            cmpg_result.allocate(pb);
                            pb_variable<FieldType> cmpg_result_flag;
                            cmpg_result_flag.allocate(pb);
                            return new ALU_cmps_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                                  cmpg_result, cmpg_result_flag, result, result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return des; },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool {
                            return (detail::from_twos_complement(x, w) >= detail::from_twos_complement(y, w));
                        });
                }

                template<typename FieldType>
                void ALU_umul_gadget<FieldType>::generate_r1cs_constraints() {
                    /* do multiplication */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        {this->arg1val.packed}, {this->arg2val.packed}, {mul_result.packed}));
                    mul_result.generate_r1cs_constraints(true);

                    /* pack result */
                    pack_mull_result->generate_r1cs_constraints(false);
                    pack_umulh_result->generate_r1cs_constraints(false);

                    /* compute flag */
                    compute_flag->generate_r1cs_constraints();

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>({pb_variable<FieldType>(0)}, {this->result_flag}, {mull_flag}));

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>({pb_variable<FieldType>(0)}, {this->result_flag}, {umulh_flag}));
                }

                template<typename FieldType>
                void ALU_umul_gadget<FieldType>::generate_r1cs_witness() {
                    /* do multiplication */
                    this->pb.val(mul_result.packed) =
                        this->pb.val(this->arg1val.packed) * this->pb.val(this->arg2val.packed);
                    mul_result.generate_r1cs_witness_from_packed();

                    /* pack result */
                    pack_mull_result->generate_r1cs_witness_from_bits();
                    pack_umulh_result->generate_r1cs_witness_from_bits();

                    /* compute flag */
                    compute_flag->generate_r1cs_witness();

                    this->pb.val(mull_flag) = this->pb.val(this->result_flag);
                    this->pb.val(umulh_flag) = this->pb.val(this->result_flag);
                }

                template<typename FieldType>
                void test_ALU_mull_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_umul_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_MULL,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_umul_gadget<FieldType> * {
                            pb_variable<FieldType> umulh_result;
                            umulh_result.allocate(pb);
                            pb_variable<FieldType> umulh_flag;
                            umulh_flag.allocate(pb);
                            return new ALU_umul_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                                  result, result_flag, umulh_result, umulh_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return (x * y) % (1ul << w); },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool { return ((x * y) >> w) != 0; });
                }

                template<typename FieldType>
                void test_ALU_umulh_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_umul_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_UMULH,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_umul_gadget<FieldType> * {
                            pb_variable<FieldType> mull_result;
                            mull_result.allocate(pb);
                            pb_variable<FieldType> mull_flag;
                            mull_flag.allocate(pb);
                            return new ALU_umul_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                                  mull_result, mull_flag, result, result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return (x * y) >> w; },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool { return ((x * y) >> w) != 0; });
                }

                template<typename FieldType>
                void ALU_smul_gadget<FieldType>::generate_r1cs_constraints() {
                    /* do multiplication */
                    /*
                      from two's complement: (packed - 2^w * bits[w-1])
                      to two's complement: lower order bits of 2^{2w} + result_of_*
                    */

                    linear_combination<FieldType> a, b, c;
                    a.add_term(this->arg1val.packed, 1);
                    a.add_term(this->arg1val.bits[this->pb.ap.w - 1], -(typename FieldType::value_type(2) ^ this->pb.ap.w));
                    b.add_term(this->arg2val.packed, 1);
                    b.add_term(this->arg2val.bits[this->pb.ap.w - 1], -(typename FieldType::value_type(2) ^ this->pb.ap.w));
                    c.add_term(mul_result.packed, 1);
                    c.add_term(pb_variable<FieldType>(0), -(typename FieldType::value_type(2) ^ (2 * this->pb.ap.w)));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a, b, c));

                    mul_result.generate_r1cs_constraints(true);

                    /* pack result */
                    pack_smulh_result->generate_r1cs_constraints(false);

                    /* compute flag */
                    pack_top->generate_r1cs_constraints(false);

                    /*
                      the gadgets below are FieldType specific:
                      I * X = (1-R)
                      R * X = 0

                      if X = 0 then R = 1
                      if X != 0 then R = 0 and I = X^{-1}
                    */
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({is_top_empty_aux}, {top}, {pb_variable<FieldType>(0), is_top_empty * (-1)}));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>({is_top_empty}, {top}, {pb_variable<FieldType>(0) * 0}));

                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({is_top_full_aux},
                                                   {top, pb_variable<FieldType>(0) * (1l - (1ul << (this->pb.ap.w + 1)))},
                                                   {pb_variable<FieldType>(0), is_top_full * (-1)}));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        {is_top_full}, {top, pb_variable<FieldType>(0) * (1l - (1ul << (this->pb.ap.w + 1)))}, {pb_variable<FieldType>(0) * 0}));

                    /* smulh_flag = 1 - (is_top_full + is_top_empty) */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        {pb_variable<FieldType>(0)}, {pb_variable<FieldType>(0), is_top_full * (-1), is_top_empty * (-1)}, {smulh_flag}));
                }

                template<typename FieldType>
                void ALU_smul_gadget<FieldType>::generate_r1cs_witness() {
                    /* do multiplication */
                    /*
                      from two's complement: (packed - 2^w * bits[w-1])
                      to two's complement: lower order bits of (2^{2w} + result_of_mul)
                    */
                    this->pb.val(mul_result.packed) =
                        (this->pb.val(this->arg1val.packed) -
                         (this->pb.val(this->arg1val.bits[this->pb.ap.w - 1]) * (typename FieldType::value_type(2) ^ this->pb.ap.w))) *
                            (this->pb.val(this->arg2val.packed) -
                             (this->pb.val(this->arg2val.bits[this->pb.ap.w - 1]) * (typename FieldType::value_type(2) ^ this->pb.ap.w))) +
                        (typename FieldType::value_type(2) ^ (2 * this->pb.ap.w));

                    mul_result.generate_r1cs_witness_from_packed();

                    /* pack result */
                    pack_smulh_result->generate_r1cs_witness_from_bits();

                    /* compute flag */
                    pack_top->generate_r1cs_witness_from_bits();
                    std::size_t topval = static_cast<unsigned long>(this->pb.val(top));

                    if (topval == 0) {
                        this->pb.val(is_top_empty) = FieldType::one();
                        this->pb.val(is_top_empty_aux) = FieldType::zero();
                    } else {
                        this->pb.val(is_top_empty) = FieldType::zero();
                        this->pb.val(is_top_empty_aux) = this->pb.val(top).inverse();
                    }

                    if (topval == ((1ul << (this->pb.ap.w + 1)) - 1)) {
                        this->pb.val(is_top_full) = FieldType::one();
                        this->pb.val(is_top_full_aux) = FieldType::zero();
                    } else {
                        this->pb.val(is_top_full) = FieldType::zero();
                        this->pb.val(is_top_full_aux) =
                            (this->pb.val(top) - typename FieldType::value_type((1ul << (this->pb.ap.w + 1)) - 1)).inverse();
                    }

                    /* smulh_flag = 1 - (is_top_full + is_top_empty) */
                    this->pb.val(smulh_flag) =
                        FieldType::one() - (this->pb.val(is_top_full) + this->pb.val(is_top_empty));
                }

                template<typename FieldType>
                void test_ALU_smulh_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_smul_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_SMULH,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_smul_gadget<FieldType> * {
                            return new ALU_smul_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val, flag,
                                                                  result, result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t {
                            const std::size_t res = detail::to_twos_complement(
                                (detail::from_twos_complement(x, w) * detail::from_twos_complement(y, w)), 2 * w);
                            return res >> w;
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool {
                            const int res = detail::from_twos_complement(x, w) * detail::from_twos_complement(y, w);
                            const int truncated_res = detail::from_twos_complement(
                                detail::to_twos_complement(res, 2 * w) & ((1ul << w) - 1), w);
                            return (res != truncated_res);
                        });
                }

                template<typename FieldType>
                void ALU_divmod_gadget<FieldType>::generate_r1cs_constraints() {
                    /* B_inv * B = B_nonzero */
                    linear_combination<FieldType> a1, b1, c1;
                    a1.add_term(B_inv, 1);
                    b1.add_term(this->arg2val.packed, 1);
                    c1.add_term(B_nonzero, 1);

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a1, b1, c1));

                    /* (1-B_nonzero) * B = 0 */
                    linear_combination<FieldType> a2, b2, c2;
                    a2.add_term(pb_variable<FieldType>(0), 1);
                    a2.add_term(B_nonzero, -1);
                    b2.add_term(this->arg2val.packed, 1);
                    c2.add_term(pb_variable<FieldType>(0), 0);

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a2, b2, c2));

                    /* B * q + r = A_aux = A * B_nonzero */
                    linear_combination<FieldType> a3, b3, c3;
                    a3.add_term(this->arg2val.packed, 1);
                    b3.add_term(udiv_result, 1);
                    c3.add_term(A_aux, 1);
                    c3.add_term(umod_result, -1);

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a3, b3, c3));

                    linear_combination<FieldType> a4, b4, c4;
                    a4.add_term(this->arg1val.packed, 1);
                    b4.add_term(B_nonzero, 1);
                    c4.add_term(A_aux, 1);

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a4, b4, c4));

                    /* q * (1-B_nonzero) = 0 */
                    linear_combination<FieldType> a5, b5, c5;
                    a5.add_term(udiv_result, 1);
                    b5.add_term(pb_variable<FieldType>(0), 1);
                    b5.add_term(B_nonzero, -1);
                    c5.add_term(pb_variable<FieldType>(0), 0);

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a5, b5, c5));

                    /* A<B_gadget<FieldType>(B, r, less=B_nonzero, leq=ONE) */
                    r_less_B->generate_r1cs_constraints();
                }

                template<typename FieldType>
                void ALU_divmod_gadget<FieldType>::generate_r1cs_witness() {
                    if (this->pb.val(this->arg2val.packed) == FieldType::zero()) {
                        this->pb.val(B_inv) = FieldType::zero();
                        this->pb.val(B_nonzero) = FieldType::zero();

                        this->pb.val(A_aux) = FieldType::zero();

                        this->pb.val(udiv_result) = FieldType::zero();
                        this->pb.val(umod_result) = FieldType::zero();

                        this->pb.val(udiv_flag) = FieldType::one();
                        this->pb.val(umod_flag) = FieldType::one();
                    } else {
                        this->pb.val(B_inv) = this->pb.val(this->arg2val.packed).inverse();
                        this->pb.val(B_nonzero) = FieldType::one();

                        std::size_t A = static_cast<unsigned long>(this->pb.val(this->arg1val.packed));
                        std::size_t B = static_cast<unsigned long>(this->pb.val(this->arg2val.packed));

                        this->pb.val(A_aux) = this->pb.val(this->arg1val.packed);

                        this->pb.val(udiv_result) = typename FieldType::value_type(A / B);
                        this->pb.val(umod_result) = typename FieldType::value_type(A % B);

                        this->pb.val(udiv_flag) = FieldType::zero();
                        this->pb.val(umod_flag) = FieldType::zero();
                    }

                    r_less_B->generate_r1cs_witness();
                }

                template<typename FieldType>
                void test_ALU_udiv_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_divmod_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_UDIV,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_divmod_gadget<FieldType> * {
                            pb_variable<FieldType> umod_result;
                            umod_result.allocate(pb);
                            pb_variable<FieldType> umod_flag;
                            umod_flag.allocate(pb);
                            return new ALU_divmod_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val,
                                                                    flag, result, result_flag, umod_result, umod_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return (y == 0 ? 0 : x / y); },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool { return (y == 0); });
                }

                template<typename FieldType>
                void test_ALU_umod_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_divmod_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_UMOD,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_divmod_gadget<FieldType> * {
                            pb_variable<FieldType> udiv_result;
                            udiv_result.allocate(pb);
                            pb_variable<FieldType> udiv_flag;
                            udiv_flag.allocate(pb);
                            return new ALU_divmod_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val,
                                                                    flag, udiv_result, udiv_flag, result, result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return (y == 0 ? 0 : x % y); },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool { return (y == 0); });
                }

                template<typename FieldType>
                void ALU_shr_shl_gadget<FieldType>::generate_r1cs_constraints() {
                    /*
                      select the input for barrel shifter:

                      r = arg1val * opcode_indicators[SHR] + reverse(arg1val) * (1-opcode_indicators[SHR])
                      r - reverse(arg1val) = (arg1val - reverse(arg1val)) * opcode_indicators[SHR]
                    */
                    pack_reversed_input->generate_r1cs_constraints(false);

                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({this->arg1val.packed, reversed_input * (-1)},
                                                   {this->opcode_indicators[tinyram_opcode_SHR]},
                                                   {barrel_right_internal[0], reversed_input * (-1)}));

                    /*
                      do logw iterations of barrel shifts
                    */
                    for (std::size_t i = 0; i < logw; ++i) {
                        /* assert that shifted out part is bits */
                        for (std::size_t j = 0; j < 1ul << i; ++j) {
                            generate_boolean_r1cs_constraint<FieldType>(this->pb, shifted_out_bits[i][j]);
                        }

                        /*
                          add main shifting constraint


                          old_result =
                          (shifted_result * 2^(i+1) + shifted_out_part) * need_to_shift +
                          (shfited_result) * (1-need_to_shift)

                          old_result - shifted_result = (shifted_result * (2^(i+1) - 1) + shifted_out_part) *
                          need_to_shift
                        */
                        linear_combination<FieldType> a, b, c;

                        a.add_term(barrel_right_internal[i + 1], (typename FieldType::value_type(2) ^ (i + 1)) - FieldType::one());
                        for (std::size_t j = 0; j < 1ul << i; ++j) {
                            a.add_term(shifted_out_bits[i][j], (typename FieldType::value_type(2) ^ j));
                        }

                        b.add_term(this->arg2val.bits[i], 1);

                        c.add_term(barrel_right_internal[i], 1);
                        c.add_term(barrel_right_internal[i + 1], -1);

                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(a, b, c));
                    }

                    /*
                      get result as the logw iterations or zero if shift was oversized

                      result = (1-is_oversize_shift) * barrel_right_internal[logw]
                    */
                    check_oversize_shift->generate_r1cs_constraints();
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        {pb_variable<FieldType>(0), is_oversize_shift * (-1)}, {barrel_right_internal[logw]}, {this->result}));

                    /*
                      get reversed result for SHL
                    */
                    unpack_result->generate_r1cs_constraints(true);
                    pack_reversed_result->generate_r1cs_constraints(false);

                    /*
                      select the correct output:
                      r = result * opcode_indicators[SHR] + reverse(result) * (1-opcode_indicators[SHR])
                      r - reverse(result) = (result - reverse(result)) * opcode_indicators[SHR]
                    */
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({this->result, reversed_result * (-1)},
                                                   {this->opcode_indicators[tinyram_opcode_SHR]},
                                                   {shr_result, reversed_result * (-1)}));

                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({this->result, reversed_result * (-1)},
                                                   {this->opcode_indicators[tinyram_opcode_SHR]},
                                                   {shr_result, reversed_result * (-1)}));

                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({pb_variable<FieldType>(0)}, {this->arg1val.bits[0]}, {shr_flag}));

                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({pb_variable<FieldType>(0)}, {this->arg1val.bits[this->pb.ap.w - 1]}, {shl_flag}));
                }

                template<typename FieldType>
                void ALU_shr_shl_gadget<FieldType>::generate_r1cs_witness() {
                    /* select the input for barrel shifter */
                    pack_reversed_input->generate_r1cs_witness_from_bits();

                    this->pb.val(barrel_right_internal[0]) =
                        (this->pb.val(this->opcode_indicators[tinyram_opcode_SHR]) == FieldType::one() ?
                             this->pb.val(this->arg1val.packed) :
                             this->pb.val(reversed_input));

                    /*
                      do logw iterations of barrel shifts.

                      old_result =
                      (shifted_result * 2^i + shifted_out_part) * need_to_shift +
                      (shfited_result) * (1-need_to_shift)
                    */

                    for (std::size_t i = 0; i < logw; ++i) {
                        this->pb.val(barrel_right_internal[i + 1]) =
                            (this->pb.val(this->arg2val.bits[i]) == FieldType::zero()) ?
                                this->pb.val(barrel_right_internal[i]) :
                                typename FieldType::value_type(this->pb.val(barrel_right_internal[i]).as_ulong() >> (i + 1));

                        shifted_out_bits[i].fill_with_bits_of_ulong(
                            this->pb, this->pb.val(barrel_right_internal[i]).as_ulong() % (2u << i));
                    }

                    /*
                      get result as the logw iterations or zero if shift was oversized

                      result = (1-is_oversize_shift) * barrel_right_internal[logw]
                    */
                    check_oversize_shift->generate_r1cs_witness();
                    this->pb.val(this->result) = (FieldType::one() - this->pb.val(is_oversize_shift)) *
                                                 this->pb.val(barrel_right_internal[logw]);

                    /*
                      get reversed result for SHL
                    */
                    unpack_result->generate_r1cs_witness_from_packed();
                    pack_reversed_result->generate_r1cs_witness_from_bits();

                    /*
                      select the correct output:
                      r = result * opcode_indicators[SHR] + reverse(result) * (1-opcode_indicators[SHR])
                      r - reverse(result) = (result - reverse(result)) * opcode_indicators[SHR]
                    */
                    this->pb.val(shr_result) =
                        (this->pb.val(this->opcode_indicators[tinyram_opcode_SHR]) == FieldType::one()) ?
                            this->pb.val(this->result) :
                            this->pb.val(reversed_result);

                    this->pb.val(shl_result) = this->pb.val(shr_result);
                    this->pb.val(shr_flag) = this->pb.val(this->arg1val.bits[0]);
                    this->pb.val(shl_flag) = this->pb.val(this->arg1val.bits[this->pb.ap.w - 1]);
                }

                template<typename FieldType>
                void test_ALU_shr_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_shr_shl_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_SHR,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_shr_shl_gadget<FieldType> * {
                            pb_variable<FieldType> shl_result;
                            shl_result.allocate(pb);
                            pb_variable<FieldType> shl_flag;
                            shl_flag.allocate(pb);
                            return new ALU_shr_shl_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val,
                                                                     flag, result, result_flag, shl_result, shl_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return (x >> y); },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool { return (x & 1); });
                }

                template<typename FieldType>
                void test_ALU_shl_gadget(const std::size_t w) {
                    brute_force_arithmetic_gadget<ALU_shr_shl_gadget<FieldType>, FieldType>(
                        w,
                        tinyram_opcode_SHL,
                        [](tinyram_protoboard<FieldType> &pb,
                           pb_variable_array<FieldType> &opcode_indicators,
                           word_variable_gadget<FieldType> &desval,
                           word_variable_gadget<FieldType> &arg1val,
                           word_variable_gadget<FieldType> &arg2val,
                           pb_variable<FieldType> &flag,
                           pb_variable<FieldType> &result,
                           pb_variable<FieldType> &result_flag) -> ALU_shr_shl_gadget<FieldType> * {
                            pb_variable<FieldType> shr_result;
                            shr_result.allocate(pb);
                            pb_variable<FieldType> shr_flag;
                            shr_flag.allocate(pb);
                            return new ALU_shr_shl_gadget<FieldType>(pb, opcode_indicators, desval, arg1val, arg2val,
                                                                     flag, shr_result, shr_flag, result, result_flag);
                        },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> std::size_t { return (x << y) & ((1ul << w) - 1); },
                        [w](std::size_t des, bool f, std::size_t x, std::size_t y) -> bool { return (x >> (w - 1)); });
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // ALU_ARITHMETIC_HPP_
