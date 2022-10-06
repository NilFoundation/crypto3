//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_BATCHED_PICKLES_DETAIL_HPP
#define CRYPTO3_ZK_PLONK_BATCHED_PICKLES_DETAIL_HPP

#include <nil/crypto3/zk/commitments/polynomial/kimchi_pedersen.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/permutation.hpp>
#include <nil/crypto3/math/domains/basic_radix2_domain.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <map>
#include <array>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /// The collection of constants required to evaluate an `Expr`.
                template<typename FieldType>
                struct Constants {
                    /// The challenge alpha from the PLONK IOP.
                    typename FieldType::value_type alpha;
                    /// The challenge beta from the PLONK IOP.
                    typename FieldType::value_type beta;
                    /// The challenge gamma from the PLONK IOP.
                    typename FieldType::value_type gamma;
                    /// The challenge joint_combiner which is used to combine
                    /// joint lookup tables.
                    typename FieldType::value_type joint_combiner;
                    /// The endomorphism coefficient
                    typename FieldType::value_type endo_coefficient;
                    /// The MDS matrix
                    std::array<std::array<typename FieldType::value_type, 3>, 3> mds;
                };

                enum gate_type {
                    /// Zero gate
                    Zero = 0,
                    /// Generic arithmetic gate
                    Generic = 1,
                    /// Poseidon permutation gate
                    Poseidon = 2,
                    /// Complete EC addition in Affine form
                    CompleteAdd = 3,
                    /// EC variable base scalar multiplication
                    VarBaseMul = 4,
                    /// EC variable base scalar multiplication with group endomorphim optimization
                    EndoMul = 5,
                    /// Gate for computing the scalar corresponding to an endoscaling
                    EndoMulScalar = 6,
                    /// ChaCha
                    ChaCha0 = 7,
                    ChaCha1 = 8,
                    ChaCha2 = 9,
                    ChaChaFinal = 10,
                    /// Lookup
                    Lookup = 11,
                    /// Cairo
                    CairoClaim = 12,
                    CairoInstruction = 13,
                    CairoFlags = 14,
                    CairoTransition = 15,
                    // Range check (16-24)
                    RangeCheck0 = 16,
                    RangeCheck1 = 17,
                };

                enum argument_type {
                    /// Gates in the PLONK constraint system.
                    /// As gates are mutually exclusive (a single gate is set per row),
                    /// we can reuse the same powers of alpha across gates.
                    GateType,
                    /// The permutation argument
                    Permutation,
                    /// The lookup argument
                    LookupArgument
                };

                template<typename FieldType>
                struct evaluation_domain {
                    std::size_t log_size_of_group;
                    FieldType group_gen;
                };

                template<typename FieldType>
                struct arithmetic_sponge_params {
                    std::vector<std::vector<FieldType>> round_constants;
                    std::array<std::array<FieldType,3>,3> mds;
                };

                struct Column;

                template<typename ContainerType>
                struct Linearization {
                    ContainerType constant_term;
                    std::vector<std::tuple<Column, ContainerType>> index_term;
                };

                template<typename CurveType>
                struct lookup_verifier_index {
                    typedef typename commitments::kimchi_pedersen<CurveType> commitment_scheme;
                    typedef typename commitment_scheme::commitment_type commitment_type;
                    typedef typename CurveType::scalar_field_type scalar_field_type;

                    enum lookups_used { Single, Joint } lookup_used;
                    std::vector<commitment_type> lookup_table;
                    std::vector<commitment_type> lookup_selectors;

                    commitment_type table_ids;

                    std::size_t max_joint_size;
                    
                    commitment_type runtime_tables_selector;
                    bool runtime_tables_selector_is_used;
                    
                    static commitment_type combine_table(std::vector<commitment_type>& columns,
                                            typename scalar_field_type::value_type column_combiner,
                                            typename scalar_field_type::value_type table_id_combiner,
                                            commitment_type& table_id_vector, 
                                            commitment_type& runtime_vector){
                        typename scalar_field_type::value_type j = scalar_field_type::value_type::one();
                        std::vector<typename scalar_field_type::value_type> scalars;
                        std::vector<commitment_type> commitments;

                        for(auto &comm : columns){
                            scalars.push_back(j);
                            commitments.push_back(comm);
                            j *= column_combiner;
                        }

                        if(table_id_vector.unshifted.size() != 0){
                            scalars.push_back(table_id_combiner);
                            commitments.push_back(table_id_vector);
                        }

                        if(runtime_vector.unshifted.size() != 0){
                            scalars.push_back(column_combiner);
                            commitments.push_back(runtime_vector);
                        }

                        return commitment_scheme::commitment_type::multi_scalar_mul(commitments, scalars);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_BATCHED_PICKLES_DETAIL_HPP
