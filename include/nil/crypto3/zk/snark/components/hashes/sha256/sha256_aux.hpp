//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_SHA256_AUX_HPP
#define CRYPTO3_ZK_SHA256_AUX_HPP

#include <nil/crypto3/zk/snark/components/basic_components.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class lastbits_component : public component<FieldType> {
                public:
                    variable<FieldType> X;
                    std::size_t X_bits;
                    variable<FieldType> result;
                    blueprint_linear_combination_vector<FieldType> result_bits;

                    blueprint_linear_combination_vector<FieldType> full_bits;
                    std::shared_ptr<packing_component<FieldType>> unpack_bits;
                    std::shared_ptr<packing_component<FieldType>> pack_result;

                    lastbits_component(blueprint<FieldType> &pb,
                                    const variable<FieldType> &X,
                                    std::size_t X_bits,
                                    const variable<FieldType> &result,
                                    const blueprint_linear_combination_vector<FieldType> &result_bits);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                class XOR3_component : public component<FieldType> {
                private:
                    variable<FieldType> tmp;

                public:
                    blueprint_linear_combination<FieldType> A;
                    blueprint_linear_combination<FieldType> B;
                    blueprint_linear_combination<FieldType> C;
                    bool assume_C_is_zero;
                    blueprint_linear_combination<FieldType> out;

                    XOR3_component(blueprint<FieldType> &pb,
                                const blueprint_linear_combination<FieldType> &A,
                                const blueprint_linear_combination<FieldType> &B,
                                const blueprint_linear_combination<FieldType> &C,
                                bool assume_C_is_zero,
                                const blueprint_linear_combination<FieldType> &out);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                /* Page 10 of http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf */
                template<typename FieldType>
                class small_sigma_component : public component<FieldType> {
                private:
                    blueprint_variable_vector<FieldType> W;
                    variable<FieldType> result;

                public:
                    blueprint_variable_vector<FieldType> result_bits;
                    std::vector<std::shared_ptr<XOR3_component<FieldType>>> compute_bits;
                    std::shared_ptr<packing_component<FieldType>> pack_result;

                    small_sigma_component(blueprint<FieldType> &pb,
                                       const blueprint_variable_vector<FieldType> &W,
                                       const variable<FieldType> &result,
                                       std::size_t rot1,
                                       std::size_t rot2,
                                       std::size_t shift);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                /* Page 10 of http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf */
                template<typename FieldType>
                class big_sigma_component : public component<FieldType> {
                private:
                    blueprint_linear_combination_vector<FieldType> W;
                    variable<FieldType> result;

                public:
                    blueprint_variable_vector<FieldType> result_bits;
                    std::vector<std::shared_ptr<XOR3_component<FieldType>>> compute_bits;
                    std::shared_ptr<packing_component<FieldType>> pack_result;

                    big_sigma_component(blueprint<FieldType> &pb,
                                     const blueprint_linear_combination_vector<FieldType> &W,
                                     const variable<FieldType> &result,
                                     std::size_t rot1,
                                     std::size_t rot2,
                                     std::size_t rot3);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                /* Page 10 of http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf */
                template<typename FieldType>
                class choice_component : public component<FieldType> {
                private:
                    blueprint_variable_vector<FieldType> result_bits;

                public:
                    blueprint_linear_combination_vector<FieldType> X;
                    blueprint_linear_combination_vector<FieldType> Y;
                    blueprint_linear_combination_vector<FieldType> Z;
                    variable<FieldType> result;
                    std::shared_ptr<packing_component<FieldType>> pack_result;

                    choice_component(blueprint<FieldType> &pb, const blueprint_linear_combination_vector<FieldType> &X,
                                  const blueprint_linear_combination_vector<FieldType> &Y,
                                  const blueprint_linear_combination_vector<FieldType> &Z,
                                  const variable<FieldType> &result);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                /* Page 10 of http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf */
                template<typename FieldType>
                class majority_component : public component<FieldType> {
                private:
                    blueprint_variable_vector<FieldType> result_bits;
                    std::shared_ptr<packing_component<FieldType>> pack_result;

                public:
                    blueprint_linear_combination_vector<FieldType> X;
                    blueprint_linear_combination_vector<FieldType> Y;
                    blueprint_linear_combination_vector<FieldType> Z;
                    variable<FieldType> result;

                    majority_component(blueprint<FieldType> &pb,
                                    const blueprint_linear_combination_vector<FieldType> &X,
                                    const blueprint_linear_combination_vector<FieldType> &Y,
                                    const blueprint_linear_combination_vector<FieldType> &Z,
                                    const variable<FieldType> &result);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                lastbits_component<FieldType>::lastbits_component(blueprint<FieldType> &pb,
                                                            const variable<FieldType> &X,
                                                            std::size_t X_bits,
                                                            const variable<FieldType> &result,
                                                            const blueprint_linear_combination_vector<FieldType> &result_bits) :
                    component<FieldType>(pb),
                    X(X), X_bits(X_bits), result(result), result_bits(result_bits) {
                    full_bits = result_bits;
                    for (std::size_t i = result_bits.size(); i < X_bits; ++i) {
                        variable<FieldType> full_bits_overflow;
                        full_bits_overflow.allocate(pb);
                        full_bits.emplace_back(full_bits_overflow);
                    }

                    unpack_bits.reset(new packing_component<FieldType>(pb, full_bits, X));
                    pack_result.reset(new packing_component<FieldType>(pb, result_bits, result));
                }

                template<typename FieldType>
                void lastbits_component<FieldType>::generate_r1cs_constraints() {
                    unpack_bits->generate_r1cs_constraints(true);
                    pack_result->generate_r1cs_constraints(false);
                }

                template<typename FieldType>
                void lastbits_component<FieldType>::generate_r1cs_witness() {
                    unpack_bits->generate_r1cs_witness_from_packed();
                    pack_result->generate_r1cs_witness_from_bits();
                }

                template<typename FieldType>
                XOR3_component<FieldType>::XOR3_component(blueprint<FieldType> &pb,
                                                    const blueprint_linear_combination<FieldType> &A,
                                                    const blueprint_linear_combination<FieldType> &B,
                                                    const blueprint_linear_combination<FieldType> &C,
                                                    bool assume_C_is_zero,
                                                    const blueprint_linear_combination<FieldType> &out) :
                    component<FieldType>(pb),
                    A(A), B(B), C(C), assume_C_is_zero(assume_C_is_zero), out(out) {
                    if (!assume_C_is_zero) {
                        tmp.allocate(pb);
                    }
                }

                template<typename FieldType>
                void XOR3_component<FieldType>::generate_r1cs_constraints() {
                    /*
                      tmp = A + B - 2AB i.e. tmp = A xor B
                      out = tmp + C - 2tmp C i.e. out = tmp xor C
                    */
                    if (assume_C_is_zero) {
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(2 * A, B, A + B - out));
                    } else {
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(2 * A, B, A + B - tmp));
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(2 * tmp, C, tmp + C - out));
                    }
                }

                template<typename FieldType>
                void XOR3_component<FieldType>::generate_r1cs_witness() {
                    if (assume_C_is_zero) {
                        this->pb.lc_val(out) = this->pb.lc_val(A) + this->pb.lc_val(B) -
                                               typename FieldType::value_type(0x02) * this->pb.lc_val(A) * this->pb.lc_val(B);
                    } else {
                        this->pb.val(tmp) = this->pb.lc_val(A) + this->pb.lc_val(B) -
                                            typename FieldType::value_type(0x02) * this->pb.lc_val(A) * this->pb.lc_val(B);
                        this->pb.lc_val(out) = this->pb.val(tmp) + this->pb.lc_val(C) -
                                               typename FieldType::value_type(0x02) * this->pb.val(tmp) * this->pb.lc_val(C);
                    }
                }

#define SHA256_COMPONENT_ROTR(A, i, k) A[((i) + (k)) % 32]

                /* Page 10 of http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf */
                template<typename FieldType>
                small_sigma_component<FieldType>::small_sigma_component(blueprint<FieldType> &pb,
                                                                  const blueprint_variable_vector<FieldType> &W,
                                                                  const variable<FieldType> &result,
                                                                  std::size_t rot1,
                                                                  std::size_t rot2,
                                                                  std::size_t shift) :
                    component<FieldType>(pb),
                    W(W), result(result) {
                    result_bits.allocate(pb, 32);
                    compute_bits.resize(32);
                    for (std::size_t i = 0; i < 32; ++i) {
                        compute_bits[i].reset(new XOR3_component<FieldType>(
                            pb, SHA256_COMPONENT_ROTR(W, i, rot1), SHA256_COMPONENT_ROTR(W, i, rot2),
                            (i + shift < 32 ? W[i + shift] : variable<FieldType>(0)), (i + shift >= 32), result_bits[i]));
                    }
                    pack_result.reset(new packing_component<FieldType>(pb, result_bits, result));
                }

                template<typename FieldType>
                void small_sigma_component<FieldType>::generate_r1cs_constraints() {
                    for (std::size_t i = 0; i < 32; ++i) {
                        compute_bits[i]->generate_r1cs_constraints();
                    }

                    pack_result->generate_r1cs_constraints(false);
                }

                template<typename FieldType>
                void small_sigma_component<FieldType>::generate_r1cs_witness() {
                    for (std::size_t i = 0; i < 32; ++i) {
                        compute_bits[i]->generate_r1cs_witness();
                    }

                    pack_result->generate_r1cs_witness_from_bits();
                }

                template<typename FieldType>
                big_sigma_component<FieldType>::big_sigma_component(blueprint<FieldType> &pb,
                                                              const blueprint_linear_combination_vector<FieldType> &W,
                                                              const variable<FieldType> &result,
                                                              std::size_t rot1,
                                                              std::size_t rot2,
                                                              std::size_t rot3) :
                    component<FieldType>(pb),
                    W(W), result(result) {
                    result_bits.allocate(pb, 32);
                    compute_bits.resize(32);
                    for (std::size_t i = 0; i < 32; ++i) {
                        compute_bits[i].reset(new XOR3_component<FieldType>(
                            pb, SHA256_COMPONENT_ROTR(W, i, rot1), SHA256_COMPONENT_ROTR(W, i, rot2),
                            SHA256_COMPONENT_ROTR(W, i, rot3), false, result_bits[i]));
                    }

                    pack_result.reset(new packing_component<FieldType>(pb, result_bits, result));
                }

                template<typename FieldType>
                void big_sigma_component<FieldType>::generate_r1cs_constraints() {
                    for (std::size_t i = 0; i < 32; ++i) {
                        compute_bits[i]->generate_r1cs_constraints();
                    }

                    pack_result->generate_r1cs_constraints(false);
                }

                template<typename FieldType>
                void big_sigma_component<FieldType>::generate_r1cs_witness() {
                    for (std::size_t i = 0; i < 32; ++i) {
                        compute_bits[i]->generate_r1cs_witness();
                    }

                    pack_result->generate_r1cs_witness_from_bits();
                }

                /* Page 10 of http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf */
                template<typename FieldType>
                choice_component<FieldType>::choice_component(blueprint<FieldType> &pb,
                                                        const blueprint_linear_combination_vector<FieldType> &X,
                                                        const blueprint_linear_combination_vector<FieldType> &Y,
                                                        const blueprint_linear_combination_vector<FieldType> &Z,
                                                        const variable<FieldType> &result) :
                    component<FieldType>(pb),
                    X(X), Y(Y), Z(Z), result(result) {
                    result_bits.allocate(pb, 32);
                    pack_result.reset(new packing_component<FieldType>(pb, result_bits, result));
                }

                template<typename FieldType>
                void choice_component<FieldType>::generate_r1cs_constraints() {
                    for (std::size_t i = 0; i < 32; ++i) {
                        /*
                          result = x * y + (1-x) * z
                          result - z = x * (y - z)
                        */
                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>(X[i], Y[i] - Z[i], result_bits[i] - Z[i]));
                    }
                    pack_result->generate_r1cs_constraints(false);
                }

                template<typename FieldType>
                void choice_component<FieldType>::generate_r1cs_witness() {
                    for (std::size_t i = 0; i < 32; ++i) {
                        this->pb.val(result_bits[i]) =
                            this->pb.lc_val(X[i]) * this->pb.lc_val(Y[i]) +
                            (FieldType::value_type::zero() - this->pb.lc_val(X[i])) * this->pb.lc_val(Z[i]);
                    }
                    pack_result->generate_r1cs_witness_from_bits();
                }

                /* Page 10 of http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf */
                template<typename FieldType>
                majority_component<FieldType>::majority_component(blueprint<FieldType> &pb,
                                                            const blueprint_linear_combination_vector<FieldType> &X,
                                                            const blueprint_linear_combination_vector<FieldType> &Y,
                                                            const blueprint_linear_combination_vector<FieldType> &Z,
                                                            const variable<FieldType> &result) :
                    component<FieldType>(pb),
                    X(X), Y(Y), Z(Z), result(result) {
                    result_bits.allocate(pb, 32);
                    pack_result.reset(new packing_component<FieldType>(pb, result_bits, result));
                }

                template<typename FieldType>
                void majority_component<FieldType>::generate_r1cs_constraints() {
                    for (std::size_t i = 0; i < 32; ++i) {
                        /*
                          2*result + aux = x + y + z
                          x, y, z, aux -- bits
                          aux = x + y + z - 2*result
                        */
                        generate_boolean_r1cs_constraint<FieldType>(this->pb, result_bits[i]);
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            X[i] + Y[i] + Z[i] - 2 * result_bits[i], 1 - (X[i] + Y[i] + Z[i] - 2 * result_bits[i]), 0));
                    }
                    pack_result->generate_r1cs_constraints(false);
                }

                template<typename FieldType>
                void majority_component<FieldType>::generate_r1cs_witness() {
                    for (std::size_t i = 0; i < 32; ++i) {
                        const long v =
                            (this->pb.lc_val(X[i]) + this->pb.lc_val(Y[i]) + this->pb.lc_val(Z[i])).as_ulong();
                        this->pb.val(result_bits[i]) = typename FieldType::value_type(v / 2);
                    }

                    pack_result->generate_r1cs_witness_from_bits();
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SHA256_AUX_HPP
