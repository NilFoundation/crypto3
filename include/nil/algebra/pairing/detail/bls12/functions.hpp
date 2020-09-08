//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_BLS12_FUNCTIONS_HPP
#define ALGEBRA_PAIRING_BLS12_FUNCTIONS_HPP

#include <sstream>

#include <nil/algebra/pairing/detail/bls12/basic_policy.hpp>

#include <nil/algebra/curves/bls12.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {
            namespace detail {

                using namespace nil::algebra;

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                using bls12_Fq = curves::bls12_g1<ModulusBits, GeneratorBits>::underlying_field_type_value;

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                using bls12_Fq2 = curves::bls12_g2<ModulusBits, GeneratorBits>::underlying_field_type_value;

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                struct bls12_Fq_conic_coefficients {

                    bls12_Fq<ModulusBits, GeneratorBits> c_ZZ;
                    bls12_Fq<ModulusBits, GeneratorBits> c_XY;
                    bls12_Fq<ModulusBits, GeneratorBits> c_XZ;

                    bool operator==(const bls12_Fq_conic_coefficients &other) const {
                        return (this->c_ZZ == other.c_ZZ && this->c_XY == other.c_XY && this->c_XZ == other.c_XZ);
                    }
                };

                template<typename ppT>
                struct MillerTriple {
                    typename ppT::Fqe_type a;
                    typename ppT::Fqe_type b;
                    typename ppT::Fqe_type c;
                };


                template<typename ppT, typename Fqk_type>
                static inline Fqk_type exp_by_x(const Fqk_type &a) {
                    auto res = Fqk_type::one();
                    bool found_one = false;
                    for( int i = 63; i >= 0; i-- ) {
                        if( found_one ) {
                            res = res.squared();
                        }

                        if( ppT::X & (1ul<<i) ) {
                            found_one = true;
                            res = res * a;
                        }
                    }

                    if constexpr(ppT::X_IS_NEG) {
                        return res.unitary_inverse();
                    }

                    return res;
                }

                template<typename ppT, typename Fqk_type>
                static Fqk_type bls12_final_exponentiation(const Fqk_type &f) {
                    Fqk_type r = f.Frobenius_map(6) * f.inverse();
                    r = r.Frobenius_map(2) * r;
                    // Hard part of the final exponentation is below:
                    // From https://eprint.iacr.org/2016/130.pdf, Table 1
                    auto y0 = r.cyclotomic_squared().unitary_inverse();

                    const auto y5 = exp_by_x<ppT>(r);
                    const auto y3 = y0 * y5;
                    y0 = exp_by_x<ppT>(y3);

                    const auto y2 = exp_by_x<ppT>(y0);
                    const auto y4 = exp_by_x<ppT>(y2) * y5.cyclotomic_squared();
                    return (  (y0 * r).Frobenius_map(3)
                            * (y5 * y2).Frobenius_map(2)
                            * (y4 * r.unitary_inverse()).Frobenius_map(1)
                            * exp_by_x<ppT>(y4)
                            * y3.unitary_inverse()
                            * r);
                }

                template<typename ppT>
                static void doubling_step_for_miller_loop(MillerTriple<ppT> &result, typename ppT::G2_type &r, 
                        const typename ppT::Fq_type &two_inv) {
                    // Formula for line function when working with homogeneous projective coordinates.
                    const auto b = r.Y.squared();
                    const auto c = r.Z.squared();
                    const auto e = ppT::TWIST_COEFF_B * c.multiply3();
                    const auto f = e.multiply3();
                    const auto h = (r.Y + r.Z).squared() - (b + c);

                    if constexpr( ppT::TWIST_TYPE == TwistType::M ) {
                        result.a = e - b;
                        result.b = r.X.squared().multiply3();
                        result.c = -h;
                    }
                    else {
                        result.a = -h;
                        result.b = r.X.squared().multiply3();
                        result.c = e - b;
                    }

                    r.X = ((two_inv * r.X) * r.Y) * (b - f);
                    r.Y = (two_inv * (b + f)).squared() - e.squared().multiply3();
                    r.Z = b * h;
                }

                template<typename ppT>
                static void addition_step_for_miller_loop(MillerTriple<ppT> &result, typename ppT::G2_type &r, 
                        const typename ppT::G2_type &q) {
                    // Formula for line function when working with homogeneous projective coordinates.
                    const auto theta = r.Y - (q.Y * r.Z);
                    const auto lambda = r.X - (q.X * r.Z);
                    const auto d = lambda.squared();
                    const auto e = lambda * d;
                    const auto g = r.X * d;
                    const auto h = e + (r.Z * theta.squared()) - g.multiply2();
                    const auto j = (theta * q.X) - (lambda * q.Y);

                    r.X = lambda * h;
                    r.Y = theta * (g - h) - (e * r.Y);
                    r.Z = r.Z * e;

                    if constexpr( ppT::TWIST_TYPE == TwistType::M ) {
                        result.a = j;
                        result.b = -theta;
                        result.c = lambda;
                    }
                    else {
                        result.a = lambda;
                        result.b = -theta;
                        result.c = j;
                    }
                }


                /* NOTE: This structure is approximately 20 KiB in size, so use with caution. */
                template<typename ppT>
                struct G2Prepared {
                    static constexpr unsigned int num_coeffs = ppT::X_HIGHEST_BIT + ppT::X_NUM_ONES - 1;
                    using G2_type = typename ppT::G2_type;

                    std::array<MillerTriple<ppT>, num_coeffs> coeffs;
                    const bool infinity;

                    bool is_zero() const {
                        return this->infinity;
                    }

                    G2Prepared( const G2_type &g2 )
                    :
                        infinity(g2.is_zero()) {
                        if( ! infinity ) {
                            _prepare(g2);
                        }
                    }

                    void _prepare(const G2_type &input_point) {
                        G2_type q = input_point;
                        q.to_affine_coordinates();

                        G2_type r = q;
                        int coeff_idx = 0;

                        // TODO: pre-compute two_inv... rather than every time it's prepared
                        const auto two_inv = ppT::Fq_type::one().multiply2().inverse();

                        // Skip the 1st bit
                        for (int i = 62; i >= 0; i--) {
                            doubling_step_for_miller_loop(this->coeffs[coeff_idx++], r, two_inv);

                            if ( ppT::X & (1ul<<i) ) {
                                addition_step_for_miller_loop(this->coeffs[coeff_idx++], r, q);
                            }
                        }
                    }
                };


                template<typename ppT>
                struct PreparedPair {
                    typename ppT::G1_type g1;
                    const G2Prepared<ppT> g2;

                    PreparedPair( const decltype(g1) &a, const decltype(g2) &b )
                    :
                        g1(a), g2(b) {
                        g1.to_affine_coordinates();
                    }
                };


                // Twisting isomorphism from E to E'
                template<typename ppT>
                static inline void ell(typename ppT::Fqk_type &f, const MillerTriple<ppT> &coeffs, const typename ppT::G1_type &g1) {
                    if constexpr( ppT::TWIST_TYPE == TwistType::M ) {
                        f.multiply_by_c014(f, coeffs.a, g1.X * coeffs.b, g1.Y * coeffs.c);       
                    }
                    else {
                        f.multiply_by_c034(f, g1.Y * coeffs.a, g1.X * coeffs.b, coeffs.c);       
                    }
                }


                template<typename ppT>
                static typename ppT::Fqk_type bls12_miller_loop( const typename ppT::G1_type &P, const typename ppT::G2_type &Q ) {
                    const PreparedPair<ppT> pair(P, Q);
                    int coeff_idx = 0;
                    auto f = ppT::Fqk_type::one();

                    for( int i = 62; i >= 0; i-- ) {
                        f.square(f);

                        ell<ppT>(f, pair.g2.coeffs[coeff_idx++], pair.g1);

                        if ( ppT::X & (1ul<<i) ) {
                            ell<ppT>(f, pair.g2.coeffs[coeff_idx++], pair.g1);
                        }
                    }

                    if constexpr( ppT::X_IS_NEG ) {
                        f.conjugate(f);
                    }

                    return f;
                }


            }    // namespace detail
        }        // namespace pairing
    }            // namespace algebra
}                // namespace nil
#endif                   // ALGEBRA_PAIRING_BLS12_FUNCTIONS_HPP
