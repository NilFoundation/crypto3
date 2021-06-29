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
// @file Declaration of interfaces for the knapsack component.
//
// The component checks the correct execution of a knapsack (modular subset-sum) over
// the field specified in the template parameter. With suitable choices of parameters
// such knapsacks are collision-resistant hashes (CRHs). See \[Ajt96] and \[GGH96].
//
// Given two positive integers m (the input length) and d (the dimension),
// and a matrix M over the field F and of dimension dxm, the hash H_M maps {0,1}^m
// to F^d by sending x to M*x. Security of the function (very roughly) depends on
// d*log(|F|).
//
// Below, we give two different components:
// - knapsack_crh_with_field_out_component, which verifies H_M
// - knapsack_crh_with_bit_out_component, which verifies H_M when its output is "expanded" to bits.
// In both cases, a method ("sample_randomness") allows to sample M.
//
// The parameter d (the dimension) is fixed at compile time in the struct
// knapsack_dimension below. The parameter m (the input length) can be chosen
// at run time (in either component).
//
//
// References:
//
// \[Ajt96]:
// "Generating hard instances of lattice problems",
// Miklos Ajtai,
// STOC 1996
//
// \[GGH96]:
// "Collision-free hashing from lattice problems",
// Oded Goldreich, Shafi Goldwasser, Shai Halevi,
// ECCC TR95-042
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_KNAPSACK_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_KNAPSACK_COMPONENT_HPP

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/random/hash.hpp>

#include <nil/crypto3/zk/merkle_tree.hpp>

#include <nil/crypto3/zk/components/packing.hpp>
#include <nil/crypto3/zk/components/hashes/hash_io.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                /************************** Choice of dimension ******************************/

                template<typename FieldType>
                struct knapsack_dimension {
                    // the size of typename FieldType::value_type should be (approximately) at least 200 bits
                    static const std::size_t dimension = 1;
                };

                /*********************** Knapsack with field output **************************/

                template<typename FieldType>
                class knapsack_crh_with_field_out_component : public component<FieldType> {
                private:
                    static std::vector<typename FieldType::value_type> knapsack_coefficients;
                    static std::size_t num_cached_coefficients;

                public:
                    typedef std::vector<typename FieldType::value_type> hash_value_type;
                    typedef blueprint_linear_combination_vector<FieldType> hash_variable_type;
                    std::size_t input_len;
                    std::size_t dimension;

                    block_variable<FieldType> input_block;
                    blueprint_linear_combination_vector<FieldType> output;

                    knapsack_crh_with_field_out_component(
                        blueprint<FieldType> &bp,
                        std::size_t input_len,
                        const block_variable<FieldType> &input_block,
                        const blueprint_linear_combination_vector<FieldType> &output) :
                        component<FieldType>(bp),
                        input_len(input_len), dimension(knapsack_dimension<FieldType>::dimension),
                        input_block(input_block), output(output) {
                        BOOST_ASSERT(input_block.bits.size() == input_len);
                        if (num_cached_coefficients < dimension * input_len) {
                            sample_randomness(input_len);
                        }
                        BOOST_ASSERT(output.size() == this->get_digest_len());
                    }
                    void generate_r1cs_constraints() {
                        for (std::size_t i = 0; i < dimension; ++i) {
                            this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                                1,
                                blueprint_coeff_sum<FieldType>(
                                    input_block.bits,
                                    std::vector<typename FieldType::value_type>(
                                        knapsack_coefficients.begin() + input_len * i,
                                        knapsack_coefficients.begin() + input_len * (i + 1))),
                                output[i]));
                        }
                    }
                    void generate_r1cs_witness() {
                        const std::vector<bool> input = input_block.get_block();

                        for (std::size_t i = 0; i < dimension; ++i) {
                            typename FieldType::value_type sum = FieldType::value_type::zero();
                            for (std::size_t k = 0; k < input_len; ++k) {
                                if (input[k]) {
                                    sum += knapsack_coefficients[input_len * i + k];
                                }
                            }

                            this->bp.lc_val(output[i]) = sum;
                        }
                    }

                    static std::size_t get_digest_len() {
                        return knapsack_dimension<FieldType>::dimension;
                    }

                    /* return 0 as block length, as the hash function is variable-input */
                    static std::size_t get_block_len() {
                        return 0;
                    }

                    static std::vector<typename FieldType::value_type> get_hash(const std::vector<bool> &input) {
                        const std::size_t dimension = knapsack_dimension<FieldType>::dimension;
                        if (num_cached_coefficients < dimension * input.size()) {
                            sample_randomness(input.size());
                        }

                        std::vector<typename FieldType::value_type> result(dimension, FieldType::value_type::zero());

                        for (std::size_t i = 0; i < dimension; ++i) {
                            for (std::size_t k = 0; k < input.size(); ++k) {
                                if (input[k]) {
                                    result[i] += knapsack_coefficients[input.size() * i + k];
                                }
                            }
                        }

                        return result;
                    }

                    static void sample_randomness(std::size_t input_len) {
                        const std::size_t num_coefficients = knapsack_dimension<FieldType>::dimension * input_len;
                        random::hash<hashes::sha2<512>, typename FieldType::value_type> rng;

                        if (num_coefficients > num_cached_coefficients) {
                            knapsack_coefficients.resize(num_coefficients);
                            for (std::size_t i = num_cached_coefficients; i < num_coefficients; ++i) {
                                rng.seed(i);
                                knapsack_coefficients[i] = rng();
                            }
                            num_cached_coefficients = num_coefficients;
                        }
                    }

                    /* for debugging */
                    static std::size_t expected_constraints() {
                        return knapsack_dimension<FieldType>::dimension;
                    }
                };

                /********************** Knapsack with binary output **************************/

                template<typename FieldType>
                class knapsack_crh_with_bit_out_component : public component<FieldType> {
                public:
                    typedef std::vector<bool> hash_value_type;
                    typedef digest_variable<FieldType> hash_variable_type;
                    typedef snark::merkle_authentication_path merkle_authentication_path_type;

                    std::size_t input_len;
                    std::size_t dimension;

                    blueprint_linear_combination_vector<FieldType> output;

                    std::shared_ptr<knapsack_crh_with_field_out_component<FieldType>> hasher;

                    block_variable<FieldType> input_block;
                    digest_variable<FieldType> output_digest;

                    knapsack_crh_with_bit_out_component(blueprint<FieldType> &bp,
                                                        std::size_t input_len,
                                                        const block_variable<FieldType> &input_block,
                                                        const digest_variable<FieldType> &output_digest) :
                        component<FieldType>(bp),
                        input_len(input_len), dimension(knapsack_dimension<FieldType>::dimension),
                        input_block(input_block), output_digest(output_digest) {
                        BOOST_ASSERT(output_digest.bits.size() == this->get_digest_len());

                        output.resize(dimension);

                        for (std::size_t i = 0; i < dimension; ++i) {
                            output[i].assign(bp,
                                             blueprint_packing_sum<FieldType>(blueprint_variable_vector<FieldType>(
                                                 output_digest.bits.begin() + i * FieldType::value_bits,
                                                 output_digest.bits.begin() + (i + 1) * FieldType::value_bits)));
                        }

                        hasher.reset(
                            new knapsack_crh_with_field_out_component<FieldType>(bp, input_len, input_block, output));
                    }

                    void generate_r1cs_constraints(bool enforce_bitness = true) {
                        hasher->generate_r1cs_constraints();

                        if (enforce_bitness) {
                            for (std::size_t k = 0; k < output_digest.bits.size(); ++k) {
                                generate_boolean_r1cs_constraint<FieldType>(this->bp, output_digest.bits[k]);
                            }
                        }
                    }

                    void generate_r1cs_witness() {
                        hasher->generate_r1cs_witness();

                        /* do unpacking in place */
                        const std::vector<bool> input = input_block.bits.get_bits(this->bp);
                        for (std::size_t i = 0; i < dimension; ++i) {
                            blueprint_variable_vector<FieldType> va(
                                output_digest.bits.begin() + i * FieldType::value_bits,
                                output_digest.bits.begin() + (i + 1) * FieldType::value_bits);
                            va.fill_with_bits_of_field_element(this->bp, this->bp.lc_val(output[i]));
                        }
                    }

                    static std::size_t get_digest_len() {
                        return knapsack_dimension<FieldType>::dimension * FieldType::value_bits;
                    }

                    /* return 0 as block length, as the hash function is variable-input */
                    static std::size_t get_block_len() {
                        return 0;
                    }
                    static hash_value_type get_hash(const std::vector<bool> &input) {
                        const std::vector<typename FieldType::value_type> hash_elems =
                            knapsack_crh_with_field_out_component<FieldType>::get_hash(input);
                        hash_value_type result;

                        typedef nil::crypto3::multiprecision::number<
                            nil::crypto3::multiprecision::backends::cpp_int_backend<>>
                            modulus_type;

                        for (const typename FieldType::value_type &elt : hash_elems) {
                            // std::vector<std::uint8_t> elt_bytes;
                            std::vector<bool> elt_bits(FieldType::modulus_bits);

                            std::vector<bool>::iterator write_iter = elt_bits.begin();
                            // little-endian, to preserve compatibility with blueprint_packing_sum.
                            auto end = ::nil::crypto3::multiprecision::export_bits(
                                modulus_type(elt.data), write_iter, 1, false);

                            result.insert(result.end(), elt_bits.begin(), elt_bits.end());
                        }

                        return result;
                    }

                    static void sample_randomness(std::size_t input_len) {
                        knapsack_crh_with_field_out_component<FieldType>::sample_randomness(input_len);
                    }

                    /* for debugging */
                    static std::size_t expected_constraints(bool enforce_bitness = true) {
                        const std::size_t hasher_constraints =
                            knapsack_crh_with_field_out_component<FieldType>::expected_constraints();
                        const std::size_t bitness_constraints = (enforce_bitness ? get_digest_len() : 0);
                        return hasher_constraints + bitness_constraints;
                    }
                };

                template<typename FieldType>
                std::vector<typename FieldType::value_type>
                    knapsack_crh_with_field_out_component<FieldType>::knapsack_coefficients;
                template<typename FieldType>
                std::size_t knapsack_crh_with_field_out_component<FieldType>::num_cached_coefficients;
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_KNAPSACK_COMPONENT_HPP
