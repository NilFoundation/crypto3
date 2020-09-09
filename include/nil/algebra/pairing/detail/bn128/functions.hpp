//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_BN128_FUNCTIONS_HPP
#define ALGEBRA_PAIRING_BN128_FUNCTIONS_HPP

#include <sstream>

#include <nil/algebra/pairing/detail/bn128/ate.hpp>
#include <nil/algebra/pairing/detail/bn128/basic_functions.hpp>
#include <nil/algebra/pairing/detail/bn128/basic_policy.hpp>

#include <nil/algebra/curves/bn128.hpp>

#include <nil/algebra/fields/fp6_3over2.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {
            namespace detail {

                using nil::algebra;

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                using bn128_Fq6 = fields::fp6_3over2<bn128_fq<<ModulusBits, GeneratorBits>>>::value_type;

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                struct bn128_ate_g1_precomp {
                    typename curves::bn128_g1<ModulusBits, GeneratorBits>::underlying_field_type_value p[3];

                    bool operator==(const bn128_ate_g1_precomp &other) const {
                        return (p[0] == other.p[0] && p[1] == other.p[1] && p[2] == other.p[2]);
                    }
                };

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                typedef bn128_Fq6<ModulusBits, GeneratorBits> bn128_ate_ell_coeffs;

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                struct bn128_ate_g2_precomp {
                    typename curves::bn128_g2<ModulusBits, GeneratorBits>::underlying_field_type_value q[3];

                    std::vector<bn128_ate_ell_coeffs<ModulusBits, GeneratorBits>> coeffs;

                    bool operator==(const bn128_ate_g2_precomp &other) const {
                        if (!(q[0] == other.q[0] && q[1] == other.q[1] && q[2] == other.q[2] &&
                              coeffs.size() == other.coeffs.size())) {
                            return false;
                        }

                        /* work around for upstream serialization bug */
                        for (size_t i = 0; i < coeffs.size(); ++i) {
                            std::stringstream this_ss, other_ss;
                            this_ss << coeffs[i];
                            other_ss << other.coeffs[i];
                            if (this_ss.str() != other_ss.str()) {
                                return false;
                            }
                        }

                        return true;
                    }
                };

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                bn128_ate_g1_precomp<ModulusBits, GeneratorBits>
                    bn128_ate_precompute_g1(const curves::bn128_g1<ModulusBits, GeneratorBits> &P) {

                    bn128_ate_g1_precomp<ModulusBits, GeneratorBits> result;
                    detail::NormalizeJac(result.P, P.p);

                    return result;
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                bn128_ate_g2_precomp<ModulusBits, GeneratorBits>
                    bn128_ate_precompute_g2(const curves::bn128_g2<ModulusBits, GeneratorBits> &Q) {

                    bn128_ate_g2_precomp<ModulusBits, GeneratorBits> result;
                    detail::precomputeg2(result.coeffs, result.Q, Q.coord);

                    return result;
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                curves::bn128_gt<ModulusBits, GeneratorBits>
                    bn128_double_ate_miller_loop(const bn128_ate_g1_precomp<ModulusBits, GeneratorBits> &prec_P1,
                                                 const bn128_ate_g2_precomp<ModulusBits, GeneratorBits> &prec_Q1,
                                                 const bn128_ate_g1_precomp<ModulusBits, GeneratorBits> &prec_P2,
                                                 const bn128_ate_g2_precomp<ModulusBits, GeneratorBits> &prec_Q2) {
                    curves::bn128_gt<ModulusBits, GeneratorBits> f;

                    millerLoop2(f.elem, prec_Q1.coeffs, prec_P1.P, prec_Q2.coeffs, prec_P2.P);
                    return f;
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                curves::bn128_gt<ModulusBits, GeneratorBits>
                    bn128_ate_miller_loop(const bn128_ate_g1_precomp<ModulusBits, GeneratorBits> &prec_P,
                                          const bn128_ate_g2_precomp<ModulusBits, GeneratorBits> &prec_Q) {
                    curves::bn128_gt<ModulusBits, GeneratorBits> f;
                    millerLoop(f.elem, prec_Q.coeffs, prec_P.P);
                    return f;
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                curves::bn128_gt<ModulusBits, GeneratorBits>
                    bn128_final_exponentiation(const curves::bn128_gt<ModulusBits, GeneratorBits> &elt) {
                    curves::bn128_gt<ModulusBits, GeneratorBits> eltcopy = elt;
                    eltcopy.elem.final_exp();
                    return eltcopy;
                }

                /*template <std::size_t ModulusBits, std::size_t GeneratorBits>
                static curves::bn128_gt<ModulusBits, GeneratorBits> bn128_final_exponentiation (const
                curves::bn128_gt<ModulusBits, GeneratorBits> &elt) { return bn128_final_exponentiation(elt);
                }

                template <std::size_t ModulusBits, std::size_t GeneratorBits>
                static curves::bn128_gt<ModulusBits, GeneratorBits> bn128_miller_loop (const
                bn128_ate_g1_precomp<ModulusBits, GeneratorBits> &prec_P, const bn128_ate_g2_precomp<ModulusBits,
                GeneratorBits> &prec_Q) {

                    curves::bn128_gt<ModulusBits, GeneratorBits> result = bn128_ate_miller_loop(prec_P, prec_Q);

                    return result;
                }

                template <std::size_t ModulusBits, std::size_t GeneratorBits>
                static curves::bn128_gt<ModulusBits, GeneratorBits> bn128_double_miller_loop (const
                bn128_ate_g1_precomp<ModulusBits, GeneratorBits> &prec_P1, const bn128_ate_g2_precomp<ModulusBits,
                GeneratorBits> &prec_Q1, const bn128_ate_g1_precomp<ModulusBits, GeneratorBits> &prec_P2, const
                bn128_ate_g2_precomp<ModulusBits, GeneratorBits> &prec_Q2) {

                    curves::bn128_gt<ModulusBits, GeneratorBits> result = bn128_double_ate_miller_loop(prec_P1, prec_Q1,
                prec_P2, prec_Q2);

                    return result;
                }*/

            }    // namespace detail
        }        // namespace pairing
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_PAIRING_BN128_FUNCTIONS_HPP
