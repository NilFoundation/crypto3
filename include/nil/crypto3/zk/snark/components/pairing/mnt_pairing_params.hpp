//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of specializations of pairing_selector<CurveType> to
// - pairing_selector<curves::mnt4>, and
// - pairing_selector<curves::mnt6>.
//
// See pairing_params.hpp .
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_MNT_PAIRING_PARAMS_HPP
#define CRYPTO3_ZK_MNT_PAIRING_PARAMS_HPP

#include <nil/crypto3/zk/snark/components/fields/fp2_components.hpp>
#include <nil/crypto3/zk/snark/components/fields/fp3_components.hpp>
#include <nil/crypto3/zk/snark/components/fields/fp4_components.hpp>
#include <nil/crypto3/zk/snark/components/fields/fp6_components.hpp>
#include <nil/crypto3/zk/snark/components/pairing/pairing_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename CurveType>
                class mnt_e_over_e_miller_loop_component;

                template<typename CurveType>
                class mnt_e_times_e_over_e_miller_loop_component;

                template<typename CurveType>
                class mnt4_final_exp_component;

                template<typename CurveType>
                class mnt6_final_exp_component;

                /**
                 * Specialization for MNT4.
                 */
                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                class pairing_selector<curves::mnt4<ModulusBits, GeneratorBits>> {
                    using curve_type = typename curves::mnt4<ModulusBits, GeneratorBits>;
                public:
                    
                    using other_curve_type = typename curve_type::pairing_policy::other_curve;  // mnt6

                    using field_type = typename curve_type::pairing_policy::Fp_type;
                    using fqe_type = typename other_curve::pairing_policy::Fqe_type;
                    using fqk_type = typename other_curve::pairing_policy::Fqk_type;

                    typedef Fp3_variable<fqe_type> Fqe_variable_type;
                    typedef Fp3_mul_component<fqe_type> Fqe_mul_component_type;
                    typedef Fp3_mul_by_lc_component<fqe_type> Fqe_mul_by_lc_component_type;
                    typedef Fp3_sqr_component<fqe_type> Fqe_sqr_component_type;

                    typedef Fp6_variable<fqk_type> Fqk_variable_type;
                    typedef Fp6_mul_component<fqk_type> Fqk_mul_component_type;
                    typedef Fp6_mul_by_2345_component<fqk_type> Fqk_special_mul_component_type;
                    typedef Fp6_sqr_component<fqk_type> Fqk_sqr_component_type;

                    typedef mnt_e_over_e_miller_loop_component<curve_type> e_over_e_miller_loop_component_type;
                    typedef mnt_e_times_e_over_e_miller_loop_component<curve_type>
                        e_times_e_over_e_miller_loop_component_type;
                    typedef mnt4_final_exp_component<curve_type> final_exp_component_type;

                    constexpr static const typename curve_type::pairing_policy::number_type &pairing_loop_count = 
                        curve_type::pairing_policy::pairing_loop_count;
                };

                /**
                 * Specialization for MNT6.
                 */
                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                class pairing_selector<curves::mnt6<ModulusBits, GeneratorBits>> {
                    using curve_type = typename curves::mnt6<ModulusBits, GeneratorBits>;
                public:

                    using other_curve_type = typename curve_type::pairing_policy::other_curve;  // mnt4

                    using field_type = typename curve_type::pairing_policy::Fp_type;
                    using fqe_type = typename other_curve::pairing_policy::Fqe_type;
                    using fqk_type = typename other_curve::pairing_policy::Fqk_type;

                    typedef Fp2_variable<fqe_type> Fqe_variable_type;
                    typedef Fp2_mul_component<fqe_type> Fqe_mul_component_type;
                    typedef Fp2_mul_by_lc_component<fqe_type> Fqe_mul_by_lc_component_type;
                    typedef Fp2_sqr_component<fqe_type> Fqe_sqr_component_type;

                    typedef Fp4_variable<fqk_type> Fqk_variable_type;
                    typedef Fp4_mul_component<fqk_type> Fqk_mul_component_type;
                    typedef Fp4_mul_component<fqk_type> Fqk_special_mul_component_type;
                    typedef Fp4_sqr_component<fqk_type> Fqk_sqr_component_type;

                    typedef mnt_e_over_e_miller_loop_component<curve_type> e_over_e_miller_loop_component_type;
                    typedef mnt_e_times_e_over_e_miller_loop_component<curve_type>
                        e_times_e_over_e_miller_loop_component_type;
                    typedef mnt6_final_exp_component<curve_type> final_exp_component_type;

                    constexpr static const typename curve_type::pairing_policy::number_type &pairing_loop_count = 
                        curve_type::pairing_policy::pairing_loop_count;
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MNT_PAIRING_PARAMS_HPP
