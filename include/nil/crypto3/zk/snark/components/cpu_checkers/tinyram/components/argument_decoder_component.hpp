//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for the TinyRAM argument decoder component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_ARGUMENT_DECODER_COMPONENT_HPP
#define CRYPTO3_ZK_ARGUMENT_DECODER_COMPONENT_HPP

#include <nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/tinyram_blueprint.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class argument_decoder_component : public tinyram_standard_component<FieldType> {
                private:
                    blueprint_variable<FieldType> packed_desidx;
                    blueprint_variable<FieldType> packed_arg1idx;
                    blueprint_variable<FieldType> packed_arg2idx;

                    std::shared_ptr<packing_component<FieldType>> pack_desidx;
                    std::shared_ptr<packing_component<FieldType>> pack_arg1idx;
                    std::shared_ptr<packing_component<FieldType>> pack_arg2idx;

                    blueprint_variable<FieldType> arg2_demux_result;
                    blueprint_variable<FieldType> arg2_demux_success;

                    std::shared_ptr<loose_multiplexing_component<FieldType>> demux_des;
                    std::shared_ptr<loose_multiplexing_component<FieldType>> demux_arg1;
                    std::shared_ptr<loose_multiplexing_component<FieldType>> demux_arg2;

                public:
                    blueprint_variable<FieldType> arg2_is_imm;
                    blueprint_variable_vector<FieldType> desidx;
                    blueprint_variable_vector<FieldType> arg1idx;
                    blueprint_variable_vector<FieldType> arg2idx;
                    blueprint_variable_vector<FieldType> packed_registers;
                    blueprint_variable<FieldType> packed_desval;
                    blueprint_variable<FieldType> packed_arg1val;
                    blueprint_variable<FieldType> packed_arg2val;

                    argument_decoder_component(tinyram_blueprint<FieldType> &pb,
                                            const blueprint_variable<FieldType> &arg2_is_imm,
                                            const blueprint_variable_vector<FieldType> &desidx,
                                            const blueprint_variable_vector<FieldType> &arg1idx,
                                            const blueprint_variable_vector<FieldType> &arg2idx,
                                            const blueprint_variable_vector<FieldType> &packed_registers,
                                            const blueprint_variable<FieldType> &packed_desval,
                                            const blueprint_variable<FieldType> &packed_arg1val,
                                            const blueprint_variable<FieldType> &packed_arg2val);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_argument_decoder_component();

                template<typename FieldType>
                argument_decoder_component<FieldType>::argument_decoder_component(
                    tinyram_blueprint<FieldType> &pb,
                    const blueprint_variable<FieldType> &arg2_is_imm,
                    const blueprint_variable_vector<FieldType> &desidx,
                    const blueprint_variable_vector<FieldType> &arg1idx,
                    const blueprint_variable_vector<FieldType> &arg2idx,
                    const blueprint_variable_vector<FieldType> &packed_registers,
                    const blueprint_variable<FieldType> &packed_desval,
                    const blueprint_variable<FieldType> &packed_arg1val,
                    const blueprint_variable<FieldType> &packed_arg2val) :
                    tinyram_standard_component<FieldType>(pb),
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

                    pack_desidx.reset(new packing_component<FieldType>(pb, desidx, packed_desidx));
                    pack_arg1idx.reset(new packing_component<FieldType>(pb, arg1idx, packed_arg1idx));
                    pack_arg2idx.reset(new packing_component<FieldType>(pb, arg2idx, packed_arg2idx));

                    arg2_demux_result.allocate(pb);
                    arg2_demux_success.allocate(pb);

                    demux_des.reset(new loose_multiplexing_component<FieldType>(pb, packed_registers, packed_desidx,
                                                                             packed_desval, blueprint_variable<FieldType>(0)));
                    demux_arg1.reset(new loose_multiplexing_component<FieldType>(pb, packed_registers, packed_arg1idx,
                                                                              packed_arg1val, blueprint_variable<FieldType>(0)));
                    demux_arg2.reset(new loose_multiplexing_component<FieldType>(pb, packed_registers, packed_arg2idx,
                                                                              arg2_demux_result, arg2_demux_success));
                }

                template<typename FieldType>
                void argument_decoder_component<FieldType>::generate_r1cs_constraints() {
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
                        {blueprint_variable<FieldType>(0), arg2_is_imm * (-1)}, {blueprint_variable<FieldType>(0), arg2_demux_success * (-1)}, {blueprint_variable<FieldType>(0) * 0}));

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
                void argument_decoder_component<FieldType>::generate_r1cs_witness() {
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
                        (this->pb.val(arg2_is_imm) == FieldType::value_type::zero() ? this->pb.val(packed_arg2idx) :
                                                                         this->pb.val(arg2_demux_result));
                }

                template<typename FieldType>
                void test_argument_decoder_component() {
                    tinyram_architecture_params ap(16, 16);
                    tinyram_program P;
                    P.instructions = generate_tinyram_prelude(ap);
                    tinyram_blueprint<FieldType> pb(ap, P.size(), 0, 10);

                    blueprint_variable_vector<FieldType> packed_registers;
                    packed_registers.allocate(pb, ap.k);

                    blueprint_variable<FieldType> arg2_is_imm;
                    arg2_is_imm.allocate(pb);

                    dual_variable_component<FieldType> desidx(pb, ap.reg_arg_width());
                    dual_variable_component<FieldType> arg1idx(pb, ap.reg_arg_width());
                    dual_variable_component<FieldType> arg2idx(pb, ap.reg_arg_or_imm_width());

                    blueprint_variable<FieldType> packed_desval, packed_arg1val, packed_arg2val;
                    packed_desval.allocate(pb);
                    packed_arg1val.allocate(pb);
                    packed_arg2val.allocate(pb);

                    argument_decoder_component<FieldType> g(pb, packed_registers, arg2_is_imm, desidx.bits, arg1idx.bits,
                                                         arg2idx.bits, packed_desval, packed_arg1val, packed_arg2val);

                    g.generate_r1cs_constraints();
                    for (std::size_t i = 0; i < ap.k; ++i) {
                        pb.val(packed_registers[i]) = typename FieldType::value_type(1000 + i);
                    }

                    pb.val(desidx.packed) = typename FieldType::value_type(2);
                    pb.val(arg1idx.packed) = typename FieldType::value_type(5);
                    pb.val(arg2idx.packed) = typename FieldType::value_type(7);
                    pb.val(arg2_is_imm) = FieldType::value_type::zero();

                    desidx.generate_r1cs_witness_from_packed();
                    arg1idx.generate_r1cs_witness_from_packed();
                    arg2idx.generate_r1cs_witness_from_packed();

                    g.generate_r1cs_witness();

                    assert(pb.val(packed_desval) == typename FieldType::value_type(1002));
                    assert(pb.val(packed_arg1val) == typename FieldType::value_type(1005));
                    assert(pb.val(packed_arg2val) == typename FieldType::value_type(1007));
                    assert(pb.is_satisfied());
                    printf("positive test (get reg) successful\n");

                    pb.val(arg2_is_imm) = FieldType::value_type::zero();
                    g.generate_r1cs_witness();

                    assert(pb.val(packed_desval) == typename FieldType::value_type(1002));
                    assert(pb.val(packed_arg1val) == typename FieldType::value_type(1005));
                    assert(pb.val(packed_arg2val) == typename FieldType::value_type(7));
                    assert(pb.is_satisfied());
                    printf("positive test (get imm) successful\n");
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_ARGUMENT_DECODER_COMPONENT_HPP
