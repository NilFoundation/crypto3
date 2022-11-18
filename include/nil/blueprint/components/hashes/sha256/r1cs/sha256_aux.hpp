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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_SHA256_AUX_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_SHA256_AUX_HPP

#include <nil/blueprint/components/packing.hpp>
#include <nil/crypto3/zk/blueprint/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                template<typename FieldType>
                class lastbits_component : public component<FieldType> {
                public:
                    blueprint_variable<FieldType> X;
                    std::size_t X_bits;
                    blueprint_variable<FieldType> result;
                    blueprint_linear_combination_vector<FieldType> result_bits;

                    blueprint_linear_combination_vector<FieldType> full_bits;
                    std::shared_ptr<packing<FieldType>> unpack_bits;
                    std::shared_ptr<packing<FieldType>> pack_result;

                    lastbits_component(blueprint<FieldType> &bp,
                                       const blueprint_variable<FieldType> &X,
                                       std::size_t X_bits,
                                       const blueprint_variable<FieldType> &result,
                                       const blueprint_linear_combination_vector<FieldType> &result_bits) :
                        component<FieldType>(bp),
                        X(X), X_bits(X_bits), result(result), result_bits(result_bits) {

                        full_bits = result_bits;
                        for (std::size_t i = result_bits.size(); i < X_bits; ++i) {
                            blueprint_variable<FieldType> full_bits_overflow;
                            full_bits_overflow.allocate(bp);
                            full_bits.emplace_back(full_bits_overflow);
                        }

                        unpack_bits.reset(new packing<FieldType>(bp, full_bits, X));
                        pack_result.reset(new packing<FieldType>(bp, result_bits, result));
                    }

                    void generate_gates() {
                        unpack_bits->generate_gates(true);
                        pack_result->generate_gates(false);
                    }

                    void generate_assignments() {
                        unpack_bits->generate_assignments_from_packed();
                        pack_result->generate_assignments_from_bits();
                    }
                };

                template<typename FieldType>
                class XOR3_component : public component<FieldType> {
                private:
                    blueprint_variable<FieldType> tmp;

                public:
                    blueprint_linear_combination<FieldType> A;
                    blueprint_linear_combination<FieldType> B;
                    blueprint_linear_combination<FieldType> C;
                    bool assume_C_is_zero;
                    blueprint_linear_combination<FieldType> out;

                    XOR3_component(blueprint<FieldType> &bp,
                                   const blueprint_linear_combination<FieldType> &A,
                                   const blueprint_linear_combination<FieldType> &B,
                                   const blueprint_linear_combination<FieldType> &C,
                                   bool assume_C_is_zero,
                                   const blueprint_linear_combination<FieldType> &out) :
                        component<FieldType>(bp),
                        A(A), B(B), C(C), assume_C_is_zero(assume_C_is_zero), out(out) {
                        if (!assume_C_is_zero) {
                            tmp.allocate(bp);
                        }
                    }

                    void generate_gates() {
                        /*
                          tmp = A + B - 2AB i.e. tmp = A xor B
                          out = tmp + C - 2tmp C i.e. out = tmp xor C
                        */
                        if (assume_C_is_zero) {
                            this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(2 * A, B, A + B - out));
                        } else {
                            this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(2 * A, B, A + B - tmp));
                            this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(2 * tmp, C, tmp + C - out));
                        }
                    }

                    void generate_assignments() {
                        if (assume_C_is_zero) {
                            this->bp.lc_val(out) =
                                this->bp.lc_val(A) + this->bp.lc_val(B) -
                                typename FieldType::value_type(0x02) * this->bp.lc_val(A) * this->bp.lc_val(B);
                        } else {
                            this->bp.val(tmp) =
                                this->bp.lc_val(A) + this->bp.lc_val(B) -
                                typename FieldType::value_type(0x02) * this->bp.lc_val(A) * this->bp.lc_val(B);
                            this->bp.lc_val(out) =
                                this->bp.val(tmp) + this->bp.lc_val(C) -
                                typename FieldType::value_type(0x02) * this->bp.val(tmp) * this->bp.lc_val(C);
                        }
                    }
                };

#define SHA256_COMPONENT_ROTR(A, i, k) A[((i) + (k)) % 32]

                /* Page 10 of http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf */
                template<typename FieldType>
                class small_sigma_component : public component<FieldType> {
                private:
                    blueprint_variable_vector<FieldType> W;
                    blueprint_variable<FieldType> result;

                public:
                    blueprint_variable_vector<FieldType> result_bits;
                    std::vector<std::shared_ptr<XOR3_component<FieldType>>> compute_bits;
                    std::shared_ptr<packing<FieldType>> pack_result;

                    small_sigma_component(blueprint<FieldType> &bp,
                                          const blueprint_variable_vector<FieldType> &W,
                                          const blueprint_variable<FieldType> &result,
                                          std::size_t rot1,
                                          std::size_t rot2,
                                          std::size_t shift) :
                        component<FieldType>(bp),
                        W(W), result(result) {

                        result_bits.allocate(bp, 32);
                        compute_bits.resize(32);
                        for (std::size_t i = 0; i < 32; ++i) {
                            compute_bits[i].reset(new XOR3_component<FieldType>(
                                bp, SHA256_COMPONENT_ROTR(W, i, rot1), SHA256_COMPONENT_ROTR(W, i, rot2),
                                (i + shift < 32 ? W[i + shift] : blueprint_variable<FieldType>(0)), (i + shift >= 32),
                                result_bits[i]));
                        }
                        pack_result.reset(new packing<FieldType>(bp, result_bits, result));
                    }

                    void generate_gates() {
                        for (std::size_t i = 0; i < 32; ++i) {
                            compute_bits[i]->generate_gates();
                        }

                        pack_result->generate_gates(false);
                    }

                    void generate_assignments() {
                        for (std::size_t i = 0; i < 32; ++i) {
                            compute_bits[i]->generate_assignments();
                        }

                        pack_result->generate_assignments_from_bits();
                    }
                };

                /* Page 10 of http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf */
                template<typename FieldType>
                class big_sigma_component : public component<FieldType> {
                private:
                    blueprint_linear_combination_vector<FieldType> W;
                    blueprint_variable<FieldType> result;

                public:
                    blueprint_variable_vector<FieldType> result_bits;
                    std::vector<std::shared_ptr<XOR3_component<FieldType>>> compute_bits;
                    std::shared_ptr<packing<FieldType>> pack_result;

                    big_sigma_component(blueprint<FieldType> &bp,
                                        const blueprint_linear_combination_vector<FieldType> &W,
                                        const blueprint_variable<FieldType> &result,
                                        std::size_t rot1,
                                        std::size_t rot2,
                                        std::size_t rot3) :
                        component<FieldType>(bp),
                        W(W), result(result) {

                        result_bits.allocate(bp, 32);
                        compute_bits.resize(32);
                        for (std::size_t i = 0; i < 32; ++i) {
                            compute_bits[i].reset(new XOR3_component<FieldType>(
                                bp, SHA256_COMPONENT_ROTR(W, i, rot1), SHA256_COMPONENT_ROTR(W, i, rot2),
                                SHA256_COMPONENT_ROTR(W, i, rot3), false, result_bits[i]));
                        }

                        pack_result.reset(new packing<FieldType>(bp, result_bits, result));
                    }

                    void generate_gates() {
                        for (std::size_t i = 0; i < 32; ++i) {
                            compute_bits[i]->generate_gates();
                        }

                        pack_result->generate_gates(false);
                    }

                    void generate_assignments() {
                        for (std::size_t i = 0; i < 32; ++i) {
                            compute_bits[i]->generate_assignments();
                        }

                        pack_result->generate_assignments_from_bits();
                    }
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
                    blueprint_variable<FieldType> result;
                    std::shared_ptr<packing<FieldType>> pack_result;

                    choice_component(blueprint<FieldType> &bp,
                                     const blueprint_linear_combination_vector<FieldType> &X,
                                     const blueprint_linear_combination_vector<FieldType> &Y,
                                     const blueprint_linear_combination_vector<FieldType> &Z,
                                     const blueprint_variable<FieldType> &result) :
                        component<FieldType>(bp),
                        X(X), Y(Y), Z(Z), result(result) {

                        result_bits.allocate(bp, 32);
                        pack_result.reset(new packing<FieldType>(bp, result_bits, result));
                    }

                    void generate_gates() {
                        for (std::size_t i = 0; i < 32; ++i) {
                            /*
                              result = x * y + (1-x) * z
                              result - z = x * (y - z)
                            */
                            this->bp.add_r1cs_constraint(
                                snark::r1cs_constraint<FieldType>(X[i], Y[i] - Z[i], result_bits[i] - Z[i]));
                        }
                        pack_result->generate_gates(false);
                    }

                    void generate_assignments() {
                        for (std::size_t i = 0; i < 32; ++i) {
                            this->bp.val(result_bits[i]) =
                                this->bp.lc_val(X[i]) * this->bp.lc_val(Y[i]) +
                                (FieldType::value_type::one() - this->bp.lc_val(X[i])) * this->bp.lc_val(Z[i]);
                        }
                        pack_result->generate_assignments_from_bits();
                    }
                };

                /* Page 10 of http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf */
                template<typename FieldType>
                class majority_component : public component<FieldType> {
                private:
                    blueprint_variable_vector<FieldType> result_bits;
                    std::shared_ptr<packing<FieldType>> pack_result;

                public:
                    blueprint_linear_combination_vector<FieldType> X;
                    blueprint_linear_combination_vector<FieldType> Y;
                    blueprint_linear_combination_vector<FieldType> Z;
                    blueprint_variable<FieldType> result;

                    majority_component(blueprint<FieldType> &bp,
                                       const blueprint_linear_combination_vector<FieldType> &X,
                                       const blueprint_linear_combination_vector<FieldType> &Y,
                                       const blueprint_linear_combination_vector<FieldType> &Z,
                                       const blueprint_variable<FieldType> &result) :
                        component<FieldType>(bp),
                        X(X), Y(Y), Z(Z), result(result) {
                        result_bits.allocate(bp, 32);
                        pack_result.reset(new packing<FieldType>(bp, result_bits, result));
                    }

                    void generate_gates() {
                        for (std::size_t i = 0; i < 32; ++i) {
                            /*
                              2*result + aux = x + y + z
                              x, y, z, aux -- bits
                              aux = x + y + z - 2*result
                            */
                            generate_boolean_r1cs_constraint<FieldType>(this->bp, result_bits[i]);
                            this->bp.add_r1cs_constraint(
                                snark::r1cs_constraint<FieldType>(X[i] + Y[i] + Z[i] - 2 * result_bits[i],
                                                                  1 - (X[i] + Y[i] + Z[i] - 2 * result_bits[i]), 0));
                        }
                        pack_result->generate_gates(false);
                    }

                    void generate_assignments() {

                        // temporary added until fixed-precision modular adaptor is ready:
                        typedef nil::crypto3::multiprecision::number<
                            nil::crypto3::multiprecision::backends::cpp_int_backend<>>
                            non_fixed_precision_integral_type;

                        using integral_type = typename FieldType::integral_type;

                        for (std::size_t i = 0; i < 32; ++i) {
                            const non_fixed_precision_integral_type v = non_fixed_precision_integral_type(
                                (this->bp.lc_val(X[i]) + this->bp.lc_val(Y[i]) + this->bp.lc_val(Z[i])).data);
                            this->bp.val(result_bits[i]) = typename FieldType::value_type(integral_type(v / 2));
                        }

                        pack_result->generate_assignments_from_bits();
                    }
                };

            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_SHA256_AUX_HPP
