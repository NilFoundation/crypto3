//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for the TinyRAM consistency enforcer gadget.
//---------------------------------------------------------------------------//

#ifndef MEMORY_MASKING_GADGET_HPP_
#define MEMORY_MASKING_GADGET_HPP_

#include <nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/tinyram_protoboard.hpp>
#include <nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/word_variable_gadget.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * The memory masking gadget checks if a specified part of a double
                 * word is correctly modified. In TinyRAM CPU checker we use this to
                 * implement byte addressing and word addressing for the memory that
                 * consists of double words.
                 *
                 * More precisely, memory masking gadgets takes the following
                 * arguments:
                 *
                 * dw_contents_prev, dw_contents_next -- the contents of the memory
                 *
                 * double word before and after the access
                 *
                 * access_is_word -- a boolean indicating if access is word
                 *
                 * access_is_byte -- a boolean indicating if access is byte
                 *
                 * subaddress -- an integer specifying which byte (if access_is_byte=1)
                 * or word (if access_is_byte=1) this access is operating on
                 *
                 * subcontents -- contents of the byte, resp., word to be operated on
                 *
                 * Memory masking gadget enforces that dw_contents_prev is equal to
                 * dw_contents_next everywhere, except subaddres-th byte (if
                 * access_is_byte = 1), or MSB(subaddress)-th word (if access_is_word =
                 * 1). The corresponding byte, resp., word in dw_contents_next is
                 * required to equal subcontents.
                 *
                 * Note that indexing MSB(subaddress)-th word is the same as indexing
                 * the word specified by subaddress expressed in bytes and aligned to
                 * the word boundary by rounding the subaddress down.
                 *
                 * Requirements: The caller is required to perform bounds checks on
                 * subcontents. The caller is also required to ensure that exactly one
                 * of access_is_word and access_is_byte is set to 1.
                 */
                template<typename FieldType>
                class memory_masking_gadget : public tinyram_standard_gadget<FieldType> {
                private:
                    pb_linear_combination<FieldType> shift;
                    pb_variable<FieldType> is_word0;
                    pb_variable<FieldType> is_word1;
                    pb_variable_array<FieldType> is_subaddress;
                    pb_variable_array<FieldType> is_byte;

                    pb_linear_combination<FieldType> masked_out_word0;
                    pb_linear_combination<FieldType> masked_out_word1;
                    pb_linear_combination_array<FieldType> masked_out_bytes;

                    std::shared_ptr<inner_product_gadget<FieldType>> get_masked_out_dw_contents_prev;

                    pb_variable<FieldType> masked_out_dw_contents_prev;
                    pb_variable<FieldType> expected_dw_contents_next;

                public:
                    doubleword_variable_gadget<FieldType> dw_contents_prev;
                    dual_variable_gadget<FieldType> subaddress;
                    pb_linear_combination<FieldType> subcontents;
                    pb_linear_combination<FieldType> access_is_word;
                    pb_linear_combination<FieldType> access_is_byte;
                    doubleword_variable_gadget<FieldType> dw_contents_next;

                    memory_masking_gadget(tinyram_protoboard<FieldType> &pb,
                                          const doubleword_variable_gadget<FieldType> &dw_contents_prev,
                                          const dual_variable_gadget<FieldType> &subaddress,
                                          const pb_linear_combination<FieldType> &subcontents,
                                          const pb_linear_combination<FieldType> &access_is_word,
                                          const pb_linear_combination<FieldType> &access_is_byte,
                                          const doubleword_variable_gadget<FieldType> &dw_contents_next);
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                memory_masking_gadget<FieldType>::memory_masking_gadget(
                    tinyram_protoboard<FieldType> &pb,
                    const doubleword_variable_gadget<FieldType> &dw_contents_prev,
                    const dual_variable_gadget<FieldType> &subaddress,
                    const pb_linear_combination<FieldType> &subcontents,
                    const pb_linear_combination<FieldType> &access_is_word,
                    const pb_linear_combination<FieldType> &access_is_byte,
                    const doubleword_variable_gadget<FieldType> &dw_contents_next) :
                    tinyram_standard_gadget<FieldType>(pb),
                    dw_contents_prev(dw_contents_prev), subaddress(subaddress), subcontents(subcontents),
                    access_is_word(access_is_word), access_is_byte(access_is_byte), dw_contents_next(dw_contents_next) {
                    /*
                      Indicator variables for access being to word_0, word_1, and
                      byte_0, byte_1, ...

                      We use little-endian indexing here (least significant
                      bit/byte/word has the smallest address).
                    */
                    is_word0.allocate(pb);
                    is_word1.allocate(pb);
                    is_subaddress.allocate(pb, 2 * pb.ap.bytes_in_word());
                    is_byte.allocate(pb, 2 * pb.ap.bytes_in_word());

                    /*
                      Get value of the dw_contents_prev for which the specified entity
                      is masked out to be zero. E.g. the value of masked_out_bytes[3]
                      will be the same as the value of dw_contents_prev, when 3rd
                      (0-indexed) byte is set to all zeros.
                    */
                    masked_out_word0.assign(
                        pb,
                        (typename FieldType::value_type(2) ^ pb.ap.w) *
                            pb_packing_sum<FieldType>(pb_variable_array<FieldType>(
                                dw_contents_prev.bits.begin() + pb.ap.w, dw_contents_prev.bits.begin() + 2 * pb.ap.w)));
                    masked_out_word1.assign(
                        pb, pb_packing_sum<FieldType>(pb_variable_array<FieldType>(
                                dw_contents_prev.bits.begin(), dw_contents_prev.bits.begin() + pb.ap.w)));
                    masked_out_bytes.resize(2 * pb.ap.bytes_in_word());

                    for (std::size_t i = 0; i < 2 * pb.ap.bytes_in_word(); ++i) {
                        /* just subtract out the byte to be masked */
                        masked_out_bytes[i].assign(
                            pb, (dw_contents_prev.packed -
                                 (typename FieldType::value_type(2) ^ (8 * i)) * pb_packing_sum<FieldType>(pb_variable_array<FieldType>(
                                                                dw_contents_prev.bits.begin() + 8 * i,
                                                                dw_contents_prev.bits.begin() + 8 * (i + 1)))));
                    }

                    /*
                      Define masked_out_dw_contents_prev to be the correct masked out
                      contents for the current access type.
                    */

                    pb_linear_combination_array<FieldType> masked_out_indicators;
                    masked_out_indicators.emplace_back(is_word0);
                    masked_out_indicators.emplace_back(is_word1);
                    masked_out_indicators.insert(masked_out_indicators.end(), is_byte.begin(), is_byte.end());

                    pb_linear_combination_array<FieldType> masked_out_results;
                    masked_out_results.emplace_back(masked_out_word0);
                    masked_out_results.emplace_back(masked_out_word1);
                    masked_out_results.insert(masked_out_results.end(), masked_out_bytes.begin(),
                                              masked_out_bytes.end());

                    masked_out_dw_contents_prev.allocate(pb);
                    get_masked_out_dw_contents_prev.reset(new inner_product_gadget<FieldType>(
                        pb, masked_out_indicators, masked_out_results, masked_out_dw_contents_prev));

                    /*
                      Define shift so that masked_out_dw_contents_prev + shift * subcontents = dw_contents_next
                     */
                    linear_combination<FieldType> shift_lc = is_word0 * 1 + is_word1 * (typename FieldType::value_type(2) ^ this->pb.ap.w);
                    for (std::size_t i = 0; i < 2 * this->pb.ap.bytes_in_word(); ++i) {
                        shift_lc = shift_lc + is_byte[i] * (typename FieldType::value_type(2) ^ (8 * i));
                    }
                    shift.assign(pb, shift_lc);
                }

                template<typename FieldType>
                void memory_masking_gadget<FieldType>::generate_r1cs_constraints() {
                    /* get indicator variables for is_subaddress[i] by adding constraints
                       is_subaddress[i] * (subaddress - i) = 0 and \sum_i is_subaddress[i] = 1 */
                    for (std::size_t i = 0; i < 2 * this->pb.ap.bytes_in_word(); ++i) {
                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>(is_subaddress[i], subaddress.packed - i, 0));
                    }
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(1, pb_sum<FieldType>(is_subaddress), 1));

                    /* get indicator variables is_byte_X */
                    for (std::size_t i = 0; i < 2 * this->pb.ap.bytes_in_word(); ++i) {
                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>(access_is_byte, is_subaddress[i], is_byte[i]));
                    }

                    /* get indicator variables is_word_0/is_word_1 */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        access_is_word, 1 - subaddress.bits[this->pb.ap.subaddr_len() - 1], is_word0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        access_is_word, subaddress.bits[this->pb.ap.subaddr_len() - 1], is_word1));

                    /* compute masked_out_dw_contents_prev */
                    get_masked_out_dw_contents_prev->generate_r1cs_constraints();

                    /*
                       masked_out_dw_contents_prev + shift * subcontents = dw_contents_next
                     */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        shift, subcontents, dw_contents_next.packed - masked_out_dw_contents_prev));
                }

                template<typename FieldType>
                void memory_masking_gadget<FieldType>::generate_r1cs_witness() {
                    /* get indicator variables is_subaddress */
                    for (std::size_t i = 0; i < 2 * this->pb.ap.bytes_in_word(); ++i) {
                        this->pb.val(is_subaddress[i]) =
                            (this->pb.val(subaddress.packed) == typename FieldType::value_type(i)) ? FieldType::one() : FieldType::zero();
                    }

                    /* get indicator variables is_byte_X */
                    for (std::size_t i = 0; i < 2 * this->pb.ap.bytes_in_word(); ++i) {
                        this->pb.val(is_byte[i]) = this->pb.val(is_subaddress[i]) * this->pb.lc_val(access_is_byte);
                    }

                    /* get indicator variables is_word_0/is_word_1 */
                    this->pb.val(is_word0) =
                        (FieldType::one() - this->pb.val(subaddress.bits[this->pb.ap.subaddr_len() - 1])) *
                        this->pb.lc_val(access_is_word);
                    this->pb.val(is_word1) =
                        this->pb.val(subaddress.bits[this->pb.ap.subaddr_len() - 1]) * this->pb.lc_val(access_is_word);

                    /* calculate shift and masked out words/bytes */
                    shift.evaluate(this->pb);
                    masked_out_word0.evaluate(this->pb);
                    masked_out_word1.evaluate(this->pb);
                    masked_out_bytes.evaluate(this->pb);

                    /* get masked_out dw/word0/word1/bytes */
                    get_masked_out_dw_contents_prev->generate_r1cs_witness();

                    /* compute dw_contents_next */
                    this->pb.val(dw_contents_next.packed) = this->pb.val(masked_out_dw_contents_prev) +
                                                            this->pb.lc_val(shift) * this->pb.lc_val(subcontents);
                    dw_contents_next.generate_r1cs_witness_from_packed();
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // MEMORY_MASKING_GADGET_HPP_
