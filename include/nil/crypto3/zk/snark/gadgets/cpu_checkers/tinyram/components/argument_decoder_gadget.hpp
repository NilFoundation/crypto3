//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for the TinyRAM argument decoder gadget.
//---------------------------------------------------------------------------//

#ifndef ARGUMENT_DECODER_GADGET_HPP_
#define ARGUMENT_DECODER_GADGET_HPP_

#include <nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/tinyram_protoboard.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class argument_decoder_gadget : public tinyram_standard_gadget<FieldType> {
                private:
                    pb_variable<FieldType> packed_desidx;
                    pb_variable<FieldType> packed_arg1idx;
                    pb_variable<FieldType> packed_arg2idx;

                    std::shared_ptr<packing_gadget<FieldType>> pack_desidx;
                    std::shared_ptr<packing_gadget<FieldType>> pack_arg1idx;
                    std::shared_ptr<packing_gadget<FieldType>> pack_arg2idx;

                    pb_variable<FieldType> arg2_demux_result;
                    pb_variable<FieldType> arg2_demux_success;

                    std::shared_ptr<loose_multiplexing_gadget<FieldType>> demux_des;
                    std::shared_ptr<loose_multiplexing_gadget<FieldType>> demux_arg1;
                    std::shared_ptr<loose_multiplexing_gadget<FieldType>> demux_arg2;

                public:
                    pb_variable<FieldType> arg2_is_imm;
                    pb_variable_array<FieldType> desidx;
                    pb_variable_array<FieldType> arg1idx;
                    pb_variable_array<FieldType> arg2idx;
                    pb_variable_array<FieldType> packed_registers;
                    pb_variable<FieldType> packed_desval;
                    pb_variable<FieldType> packed_arg1val;
                    pb_variable<FieldType> packed_arg2val;

                    argument_decoder_gadget(tinyram_protoboard<FieldType> &pb,
                                            const pb_variable<FieldType> &arg2_is_imm,
                                            const pb_variable_array<FieldType> &desidx,
                                            const pb_variable_array<FieldType> &arg1idx,
                                            const pb_variable_array<FieldType> &arg2idx,
                                            const pb_variable_array<FieldType> &packed_registers,
                                            const pb_variable<FieldType> &packed_desval,
                                            const pb_variable<FieldType> &packed_arg1val,
                                            const pb_variable<FieldType> &packed_arg2val);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_argument_decoder_gadget();

                template<typename FieldType>
                argument_decoder_gadget<FieldType>::argument_decoder_gadget(
                    tinyram_protoboard<FieldType> &pb,
                    const pb_variable<FieldType> &arg2_is_imm,
                    const pb_variable_array<FieldType> &desidx,
                    const pb_variable_array<FieldType> &arg1idx,
                    const pb_variable_array<FieldType> &arg2idx,
                    const pb_variable_array<FieldType> &packed_registers,
                    const pb_variable<FieldType> &packed_desval,
                    const pb_variable<FieldType> &packed_arg1val,
                    const pb_variable<FieldType> &packed_arg2val) :
                    tinyram_standard_gadget<FieldType>(pb),
                    arg2_is_imm(arg2_is_imm), desidx(desidx), arg1idx(arg1idx), arg2idx(arg2idx),
                    packed_registers(packed_registers), packed_desval(packed_desval), packed_arg1val(packed_arg1val),
                    packed_arg2val(packed_arg2val) {
                    assert(desidx.size() == pb.ap.reg_arg_width());
                    assert(arg1idx.size() == pb.ap.reg_arg_width());
                    assert(arg2idx.size() == pb.ap.reg_arg_or_imm_width());

                    /* decode accordingly */
                    packed_desidx.allocate(pb);
                    packed_arg1idx.allocate(pb);
                    packed_arg2idx.allocate(pb);

                    pack_desidx.reset(new packing_gadget<FieldType>(pb, desidx, packed_desidx));
                    pack_arg1idx.reset(new packing_gadget<FieldType>(pb, arg1idx, packed_arg1idx));
                    pack_arg2idx.reset(new packing_gadget<FieldType>(pb, arg2idx, packed_arg2idx));

                    arg2_demux_result.allocate(pb);
                    arg2_demux_success.allocate(pb);

                    demux_des.reset(new loose_multiplexing_gadget<FieldType>(pb, packed_registers, packed_desidx,
                                                                             packed_desval, pb_variable<FieldType>(0)));
                    demux_arg1.reset(new loose_multiplexing_gadget<FieldType>(pb, packed_registers, packed_arg1idx,
                                                                              packed_arg1val, pb_variable<FieldType>(0)));
                    demux_arg2.reset(new loose_multiplexing_gadget<FieldType>(pb, packed_registers, packed_arg2idx,
                                                                              arg2_demux_result, arg2_demux_success));
                }

                template<typename FieldType>
                void argument_decoder_gadget<FieldType>::generate_r1cs_constraints() {
                    /* pack */
                    pack_desidx->generate_r1cs_constraints(true);
                    pack_arg1idx->generate_r1cs_constraints(true);
                    pack_arg2idx->generate_r1cs_constraints(true);

                    /* demux */
                    demux_des->generate_r1cs_constraints();
                    demux_arg1->generate_r1cs_constraints();
                    demux_arg2->generate_r1cs_constraints();

                    /* enforce correct handling of arg2val */

                    /* it is false that arg2 is reg and demux failed:
                       (1 - arg2_is_imm) * (1 - arg2_demux_success) = 0 */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        {pb_variable<FieldType>(0), arg2_is_imm * (-1)}, {pb_variable<FieldType>(0), arg2_demux_success * (-1)}, {pb_variable<FieldType>(0) * 0}));

                    /*
                      arg2val = arg2_is_imm * packed_arg2idx +
                      (1 - arg2_is_imm) * arg2_demux_result

                      arg2val - arg2_demux_result = arg2_is_imm * (packed_arg2idx - arg2_demux_result)
                    */
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({arg2_is_imm},
                                                   {packed_arg2idx, arg2_demux_result * (-1)},
                                                   {packed_arg2val, arg2_demux_result * (-1)}));
                }

                template<typename FieldType>
                void argument_decoder_gadget<FieldType>::generate_r1cs_witness() {
                    /* pack */
                    pack_desidx->generate_r1cs_witness_from_bits();
                    pack_arg1idx->generate_r1cs_witness_from_bits();
                    pack_arg2idx->generate_r1cs_witness_from_bits();

                    /* demux */
                    demux_des->generate_r1cs_witness();
                    demux_arg1->generate_r1cs_witness();
                    demux_arg2->generate_r1cs_witness();

                    /* handle arg2val */
                    this->pb.val(packed_arg2val) =
                        (this->pb.val(arg2_is_imm) == FieldType::one() ? this->pb.val(packed_arg2idx) :
                                                                         this->pb.val(arg2_demux_result));
                }

                template<typename FieldType>
                void test_argument_decoder_gadget() {
                    algebra::print_time("starting argument_decoder_gadget test");

                    tinyram_architecture_params ap(16, 16);
                    tinyram_program P;
                    P.instructions = generate_tinyram_prelude(ap);
                    tinyram_protoboard<FieldType> pb(ap, P.size(), 0, 10);

                    pb_variable_array<FieldType> packed_registers;
                    packed_registers.allocate(pb, ap.k);

                    pb_variable<FieldType> arg2_is_imm;
                    arg2_is_imm.allocate(pb);

                    dual_variable_gadget<FieldType> desidx(pb, ap.reg_arg_width(), "desidx");
                    dual_variable_gadget<FieldType> arg1idx(pb, ap.reg_arg_width(), "arg1idx");
                    dual_variable_gadget<FieldType> arg2idx(pb, ap.reg_arg_or_imm_width(), "arg2idx");

                    pb_variable<FieldType> packed_desval, packed_arg1val, packed_arg2val;
                    packed_desval.allocate(pb);
                    packed_arg1val.allocate(pb);
                    packed_arg2val.allocate(pb);

                    argument_decoder_gadget<FieldType> g(pb, packed_registers, arg2_is_imm, desidx.bits, arg1idx.bits,
                                                         arg2idx.bits, packed_desval, packed_arg1val, packed_arg2val,
                                                         "g");

                    g.generate_r1cs_constraints();
                    for (std::size_t i = 0; i < ap.k; ++i) {
                        pb.val(packed_registers[i]) = FieldType(1000 + i);
                    }

                    pb.val(desidx.packed) = FieldType(2);
                    pb.val(arg1idx.packed) = FieldType(5);
                    pb.val(arg2idx.packed) = FieldType(7);
                    pb.val(arg2_is_imm) = FieldType::zero();

                    desidx.generate_r1cs_witness_from_packed();
                    arg1idx.generate_r1cs_witness_from_packed();
                    arg2idx.generate_r1cs_witness_from_packed();

                    g.generate_r1cs_witness();

                    assert(pb.val(packed_desval) == FieldType(1002));
                    assert(pb.val(packed_arg1val) == FieldType(1005));
                    assert(pb.val(packed_arg2val) == FieldType(1007));
                    assert(pb.is_satisfied());
                    printf("positive test (get reg) successful\n");

                    pb.val(arg2_is_imm) = FieldType::one();
                    g.generate_r1cs_witness();

                    assert(pb.val(packed_desval) == FieldType(1002));
                    assert(pb.val(packed_arg1val) == FieldType(1005));
                    assert(pb.val(packed_arg2val) == FieldType(7));
                    assert(pb.is_satisfied());
                    printf("positive test (get imm) successful\n");

                    algebra::print_time("argument_decoder_gadget tests successful");
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // ARGUMENT_DECODER_GADGET_HPP_
