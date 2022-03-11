//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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
// @file This module implements two binding commitment systems used in the Groth16
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

#ifndef CRYPTO3_ZK_COMMITMENTS_KZG_COMMITMENT_HPP
#define CRYPTO3_ZK_COMMITMENTS_KZG_COMMITMENT_HPP

#include <tuple>
#include <vector>
#include <type_traits>

#include <boost/assert.hpp>
#include <boost/iterator/zip_iterator.hpp>
#include <boost/accumulators/accumulators.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                template<typename GroupType>
                struct kzg_commitment_key {
                    typedef GroupType group_type;
                    typedef typename group_type::curve_type curve_type;
                    typedef typename curve_type::scalar_field_type field_type;

                    typedef typename group_type::value_type group_value_type;
                    typedef typename field_type::value_type field_value_type;

                    /// Exponent is a
                    std::vector<group_value_type> a;
                    /// Exponent is b
                    std::vector<group_value_type> b;

                    /// Returns true if commitment keys have the exact required length.
                    /// It is necessary for the IPP scheme to work that commitment
                    /// key have the exact same number of arguments as the number of proofs to
                    /// aggregate.
                    inline bool has_correct_len(std::size_t n) const {
                        return a.size() == n && n == b.size();
                    }

                    /// Returns both vectors scaled by the given vector entrywise.
                    /// In other words, it returns $\{v_i^{s_i}\}$
                    template<
                        typename InputIterator,
                        typename ValueType = typename std::iterator_traits<InputIterator>::value_type,
                        typename std::enable_if<std::is_same<field_value_type, ValueType>::value, bool>::type = true>
                    kzg_commitment_key<group_type> scale(InputIterator s_first, InputIterator s_last) const {
                        BOOST_ASSERT(has_correct_len(std::distance(s_first, s_last)));

                        kzg_commitment_key<group_type> result;
                        std::for_each(boost::make_zip_iterator(boost::make_tuple(s_first, a.begin(), b.begin())),
                                      boost::make_zip_iterator(boost::make_tuple(s_last, a.end(), b.end())),
                                      [&](const boost::tuple<const field_value_type &,
                                                             const group_value_type &,
                                                             const group_value_type &> &t) {
                                          result.a.emplace_back(t.template get<1>() * t.template get<0>());
                                          result.b.emplace_back(t.template get<2>() * t.template get<0>());
                                      });

                        return result;
                    }

                    /// Returns the left and right commitment key part. It makes copy.
                    std::pair<kzg_commitment_key<group_type>, kzg_commitment_key<group_type>>
                        split(std::size_t at) const {
                        BOOST_ASSERT(a.size() == b.size());
                        BOOST_ASSERT(at > 0 && at < a.size());

                        kzg_commitment_key<group_type> result_l;
                        kzg_commitment_key<group_type> result_r;

                        auto a_it = a.begin();
                        auto b_it = b.begin();
                        while (a_it != a.begin() + at && b_it != b.begin() + at) {
                            result_l.a.emplace_back(*a_it);
                            result_l.b.emplace_back(*b_it);
                            ++a_it;
                            ++b_it;
                        }
                        while (a_it != a.end() && b_it != b.end()) {
                            result_r.a.emplace_back(*a_it);
                            result_r.b.emplace_back(*b_it);
                            ++a_it;
                            ++b_it;
                        }

                        return std::make_pair(result_l, result_r);
                    }

                    /// Takes a left and right commitment key and returns a commitment
                    /// key $left \circ right^{scale} = (left_i*right_i^{scale} ...)$. This is
                    /// required step during GIPA recursion.
                    kzg_commitment_key<group_type> compress(const kzg_commitment_key<group_type> &right,
                                                            const field_value_type &scale) const {
                        BOOST_ASSERT(a.size() == right.a.size());
                        BOOST_ASSERT(b.size() == right.b.size());
                        BOOST_ASSERT(a.size() == b.size());

                        kzg_commitment_key<group_type> result;

                        std::for_each(
                            boost::make_zip_iterator(
                                boost::make_tuple(a.begin(), b.begin(), right.a.begin(), right.b.begin())),
                            boost::make_zip_iterator(boost::make_tuple(a.end(), b.end(), right.a.end(), right.b.end())),
                            [&](const boost::tuple<const group_value_type &,
                                                   const group_value_type &,
                                                   const group_value_type &,
                                                   const group_value_type &> &t) {
                                result.a.emplace_back(t.template get<0>() + t.template get<2>() * scale);
                                result.b.emplace_back(t.template get<1>() + t.template get<3>() * scale);
                            });

                        return result;
                    }

                    /// Returns the first values in the vector of v1 and v2 (respectively
                    /// w1 and w2). When commitment key is of size one, it's a proxy to get the
                    /// final values.
                    std::pair<group_value_type, group_value_type> first() const {
                        return std::make_pair(a.front(), b.front());
                    }
                };

                template<typename CurveType>
                struct kzg_commitment {
                    typedef CurveType curve_type;
                    typedef algebra::pairing::pairing_policy<curve_type> pairing;

                    /// Key is a generic commitment key that is instantiated with g and h as basis,
                    /// and a and b as powers.
                    using commitment_key_type = std::vector<typename CurveType::template g1_type<>::value_type>;
                    using verification_key_type = typename CurveType::template g1_type<>::value_type;

                    using commitment_type = typename CurveType::template g1_type<>::value_type;
                    using proof_type = commitment_type;

                    struct params_type { };

                    /// Returns both vectors scaled by the given vector entrywise.
                    /// In other words, it returns $\{v_i^{s_i}\}$
                    static std::pair<commitment_key_type, verification_key_type> setup(const std::size_t n) {

                        kzg_commitment_key<group_type> result;
                        std::for_each(boost::make_zip_iterator(boost::make_tuple(s_first, a.begin())),
                                      boost::make_zip_iterator(boost::make_tuple(s_last, a.end())),
                                      [&](const boost::tuple<const field_value_type &,
                                                             const group_value_type &,
                                                             const group_value_type &> &t) {
                                          result.a.emplace_back(t.template get<1>() * t.template get<0>());
                                      });

                        return result;
                    }

                    /// Commits to a single vector of G1 elements in the following way:
                    /// $C = \prod_{i=0}^n (g^{a^i})^{f_i}$
                    /// Output is $C$
                    static commitment_type commit(const commitment_key_type &ckey,
                                                  const math::polynomial<typename FieldType::value_type> &f,
                                                  params_type params) {
                        BOOST_ASSERT(ckey.has_correct_len(std::distance(f_first, f_last)));

                        g1_value_type c = g1_value_type::one();
                        std::for_each_n(boost::make_zip_iterator(boost::make_tuple(f_first, ckey.a.begin())),
                                        std::distance(f_first, f_last),
                                        [&](const boost::tuple<const g1_value_type &, const g1_value_type &> &t) {
                                            for (size_t i = 0; i < (t.template get<0>()); i++) {
                                                c = c * t.template get<1>();
                                            }
                                        });
                    }

                    static proof_type proof_eval(commitment_key_type commitment_key,
                                                 commitment_type C_f,
                                                 typename CurveType::base_field_type::value_type x,
                                                 typename CurveType::base_field_type::value_type y,
                                                 const math::polynomial<typename FieldType::value_type> &f,
                                                 params_type params) {

                        const math::polynomial<typename FieldType::value_type> denominator_polynom = {1, -x};

                        const math::polynomial<typename FieldType::value_type> q = (f - {y}) / denominator_polynom;
                    }

                    static bool verify_eval(verification_key_type verification_key,
                                            commitment_type C_f,
                                            typename CurveType::base_field_type::value_type x,
                                            typename CurveType::base_field_type::value_type y,
                                            proof_type p,
                                            params_type params) {
                    }
                };
            };    // namespace commitments
        }         // namespace zk
    }             // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_KZG_COMMITMENT_HPP