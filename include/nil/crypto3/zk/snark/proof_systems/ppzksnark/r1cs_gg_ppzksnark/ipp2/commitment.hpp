//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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
// @file This module implements two binding commitment schemes used in the Groth16
// aggregation.
// The first one is a commitment scheme that commits to a single vector $a$ of
// length n in the second base group $G_1$ (for example):
// * it requires a structured SRS $v_1$ of the form $(h,h^u,h^{u^2}, ...
// ,g^{h^{n-1}})$ with $h \in G_2$ being a random generator of $G_2$ and $u$ a
// random scalar (coming from a power of tau ceremony for example)
// * it requires a second structured SRS $v_2$ of the form $(h,h^v,h^{v^2},
// ...$ with $v$ being a random scalar different than u (coming from another
// power of tau ceremony for example)
// The Commitment is a tuple $(\prod_{i=0}^{n-1} e(a_i,v_{1,i}),
// \prod_{i=0}^{n-1} e(a_i,v_{2,i}))$
//
// The second one takes two vectors $a \in G_1^n$ and $b \in G_2^n$ and commits
// to them using a similar approach as above. It requires an additional SRS
// though:
// * $v_1$ and $v_2$ stay the same
// * An additional tuple $w_1 = (g^{u^n},g^{u^{n+1}},...g^{u^{2n-1}})$ and $w_2 =
// (g^{v^n},g^{v^{n+1},...,g^{v^{2n-1}})$ where $g$ is a random generator of
// $G_1$
// The commitment scheme returns a tuple:
// * $\prod_{i=0}^{n-1} e(a_i,v_{1,i})e(w_{1,i},b_i)$
// * $\prod_{i=0}^{n-1} e(a_i,v_{2,i})e(w_{2,i},b_i)$
//
// The second commitment scheme enables to save some KZG verification in the
// verifier of the Groth16 verification protocol since we pack two vectors in
// one commitment.

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_COMMITMENT_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_COMMITMENT_HPP

#include <tuple>
#include <vector>

#include <boost/assert.hpp>

#include <nil/crypto3/detail/type_traits.hpp>

#include <nil/crypto3/algebra/algorithms/pair.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /// Both commitment outputs a pair of $F_q^k$ element.
                template<typename CurveType>
                using r1cs_gg_ppzksnark_ipp2_commitment_output =
                    std::pair<typename CurveType::scalar_field_type::value_type,
                              typename CurveType::scalar_field_type::value_type>;

                /// Key is a generic commitment key that is instanciated with g and h as basis,
                /// and a and b as powers.
                template<typename FieldType>
                struct r1cs_gg_ppzksnark_ipp2_commitment_key {
                    typedef FieldType field_type;
                    typedef typename field_type::value_type value_type;

                    typedef typename std::vector<value_type>::const_iterator const_iterator;
                    typedef typename std::vector<value_type>::iterator iterator;

                    /// Exponent is a
                    std::vector<value_type> a;
                    /// Exponent is b
                    std::vector<value_type> b;

                    /// Returns true if commitment keys have the exact required length.
                    /// It is necessary for the IPP scheme to work that commitment
                    /// key have the exact same number of arguments as the number of proofs to
                    /// aggregate.
                    inline bool valid(std::size_t n) {
                        return a.size() == n && n == b.size();
                    }

                    /// Returns both vectors scaled by the given vector entrywise.
                    /// In other words, it returns $\{v_i^{s_i}\}$
                    template<typename InputIterator>
                    r1cs_gg_ppzksnark_ipp2_commitment_key<FieldType> scale(InputIterator sfirst, InputIterator slast) {
                        BOOST_ASSERT(std::distance(sfirst, slast) == a.size() &&
                                     std::distance(sfirst, slast) == b.size());
                        r1cs_gg_ppzksnark_ipp2_commitment_key<FieldType> result;
                        const_iterator afirst = a.begin(), bfirst = b.begin();

                        while (sfirst != slast && afirst != a.end() && bfirst != b.end()) {
                            result.a.emplace_back(afirst->to_projective() * sfirst->to_affine());
                            result.b.emplace_back(bfirst->to_projective() * sfirst->to_affine());
                        }

                        return result;
                    }

                    /// Takes a left and right commitment key and returns a commitment
                    /// key $left \circ right^{scale} = (left_i*right_i^{scale} ...)$. This is
                    /// required step during GIPA recursion.
                    r1cs_gg_ppzksnark_ipp2_commitment_key<FieldType>
                        compress(const r1cs_gg_ppzksnark_ipp2_commitment_key<FieldType> &other,
                                 const typename FieldType::number_type &scale) {
                        BOOST_ASSERT(a.size() == other.a.size() && other.valid());

                        r1cs_gg_ppzksnark_ipp2_commitment_key<FieldType> result;
                        const_iterator afirst = a.begin(), bfirst = b.begin();
                        const_iterator oafirst = other.a.begin(), obfirst = other.b.begin();

                        while (afirst != a.end() && bfirst != b.end() && oafirst != other.a.begin() &&
                               obfirst != other.b.begin()) {
                            auto ra = oafirst->to_projective() * scale;
                            auto rb = obfirst->to_projective() * scale;

                            ra.add_assign_mixed(*afirst);
                            rb.add_assign_mixed(*bfirst);

                            result.a.emplace_back(ra.to_affine());
                            result.b.emplace_back(rb.to_affine());

                            ++afirst;
                            ++bfirst;
                            ++oafirst;
                            ++obfirst;
                        }

                        return result;
                    }
                };

                /*!
                 * Returns both vectors scaled by the given vector entrywise.
                 * In other words, it returns $\{v_i^{s_i}\}$
                 */
                template<typename FieldType, typename InputIterator>
                r1cs_gg_ppzksnark_ipp2_commitment_key<FieldType>
                    scale(const r1cs_gg_ppzksnark_ipp2_commitment_key<FieldType> &key,
                          InputIterator first,
                          InputIterator last) {
                    BOOST_ASSERT(std::distance(first, last) == key.a.size() &&
                                 std::distance(first, last) == key.b.size());
                    r1cs_gg_ppzksnark_ipp2_commitment_key<FieldType> result;

                    typename r1cs_gg_ppzksnark_ipp2_commitment_key<FieldType>::const_iterator afirst = key.a.begin(),
                                                                                              bfirst = key.b.begin();

                    while (first != last && afirst != key.a.end() && bfirst != key.b.end()) {
                        result.a.emplace_back(afirst->to_projective() * first->to_affine());
                        result.b.emplace_back(bfirst->to_projective() * first->to_affine());

                        ++first;
                        ++afirst;
                        ++bfirst;
                    }

                    return result;
                }

                /// Takes a left and right commitment key and returns a commitment
                /// key $left \circ right^{scale} = (left_i*right_i^{scale} ...)$. This is
                /// required step during GIPA recursion.
                template<typename FieldType>
                r1cs_gg_ppzksnark_ipp2_commitment_key<FieldType>
                    compress(const r1cs_gg_ppzksnark_ipp2_commitment_key<FieldType> &left,
                             const r1cs_gg_ppzksnark_ipp2_commitment_key<FieldType> &right,
                             const typename FieldType::number_type &scale) {
                    BOOST_ASSERT(left.a.size() == right.a.size());

                    r1cs_gg_ppzksnark_ipp2_commitment_key<FieldType> result;
                    typename r1cs_gg_ppzksnark_ipp2_commitment_key<FieldType>::const_iterator lafirst = left.a.begin(),
                                                                                              lbfirst = left.b.begin();
                    typename r1cs_gg_ppzksnark_ipp2_commitment_key<FieldType>::const_iterator rafirst = right.a.begin(),
                                                                                              rbfirst = right.b.begin();

                    while (lafirst != left.a.end() && lbfirst != left.b.end() && rafirst != right.a.begin() &&
                           rbfirst != right.b.begin()) {
                        auto ra = rafirst->to_projective() * scale;
                        auto rb = rbfirst->to_projective() * scale;

                        ra.add_assign_mixed(*lafirst);
                        rb.add_assign_mixed(*lbfirst);

                        result.a.emplace_back(ra.to_affine());
                        result.b.emplace_back(rb.to_affine());

                        ++lafirst;
                        ++lbfirst;
                        ++rafirst;
                        ++rbfirst;
                    }

                    return result;
                }

                /// Commitment key used by the "single" commitment on G1 values as
                /// well as in the "pair" commtitment.
                /// It contains $\{h^a^i\}_{i=1}^n$ and $\{h^b^i\}_{i=1}^n$
                template<typename CurveType>
                using r1cs_gg_ppzksnark_ipp2_vkey = r1cs_gg_ppzksnark_ipp2_commitment_key<typename CurveType::g2_type>;

                /// Commitment key used by the "pair" commitment. Note the sequence of
                /// powers starts at $n$ already.
                /// It contains $\{g^{a^{n+i}}\}_{i=1}^n$ and $\{g^{b^{n+i}}\}_{i=1}^n$
                template<typename CurveType>
                using r1cs_gg_ppzksnark_ipp2_wkey = r1cs_gg_ppzksnark_ipp2_commitment_key<typename CurveType::g1_type>;

                template<typename CurveType>
                struct r1cs_gg_ppzksnark_ipp2_commitment {
                    typedef CurveType curve_type;

                    typedef r1cs_gg_ppzksnark_ipp2_wkey<CurveType> wkey_type;
                    typedef r1cs_gg_ppzksnark_ipp2_vkey<CurveType> vkey_type;

                    typedef r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType> output_type;

                    /// Commits to a tuple of G1 vector and G2 vector in the following way:
                    /// $T = \prod_{i=0}^n e(A_i, v_{1,i})e(B_i,w_{1,i})$
                    /// $U = \prod_{i=0}^n e(A_i, v_{2,i})e(B_i,w_{2,i})$
                    /// Output is $(T,U)$
                    template<typename InputG1Iterator, typename InputG2Iterator>
                    static output_type pair(const vkey_type &vkey, const wkey_type &wkey, InputG1Iterator afirst,
                                            InputG1Iterator alast, InputG2Iterator bfirst, InputG2Iterator blast) {
                        // (A * v)
                        auto t1 = algebra::pair(afirst, alast, vkey.a);
                        auto t2 = algebra::pair(wkey.a, bfirst, blast);

                        // (B * v)
                        auto u1 = algebra::pair(afirst, alast, vkey.b);
                        auto u2 = algebra::pair(wkey.b, bfirst, blast);

                        // (A * v)(w * B)
                        t1.mul_assign(&t2);
                        u1.mul_assign(&u2);
                        return {t1.mul_assign(t2), u1.mul_assign(u2)};
                    }
                };

                template<typename ProofSchemeCommitmentType, typename InputG1Iterator, typename InputG2Iterator>
                typename ProofSchemeCommitmentType::output_type
                    pair(const typename ProofSchemeCommitmentType::vkey_type &vkey,
                         const typename ProofSchemeCommitmentType::wkey_type &wkey, InputG1Iterator afirst,
                         InputG1Iterator alast, InputG2Iterator bfirst, InputG2Iterator blast) {
                    // (A * v)
                    auto t1 = algebra::pair(afirst, alast, vkey.a);
                    auto t2 = algebra::pair(wkey.a, bfirst, blast);

                    // (B * v)
                    auto u1 = algebra::pair(afirst, alast, vkey.b);
                    auto u2 = algebra::pair(wkey.b, bfirst, blast);

                    // (A * v)(w * B)
                    t1.mul_assign(&t2);
                    u1.mul_assign(&u2);
                    return {t1.mul_assign(t2), u1.mul_assign(u2)};
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP
