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

#ifndef KZG_COMMITMENT_HPP
#define KZG_COMMITMENT_HPP

#include <tuple>
#include <vector>
#include <type_traits>

#include <boost/assert.hpp>
#include <boost/iterator/zip_iterator.hpp>
#include <boost/accumulators/accumulators.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/algebra/algorithms/pair.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /// KZGOpening represents the KZG opening of a commitment key (which is a tuple
                /// given commitment keys are a tuple).
                template<typename GroupType>
                using kzg_opening = typename GroupType::value_type;

                /// Both commitment outputs a pair of $F_q^k$ element.
                template<typename CurveType>
                using kzg_commitment_output = typename CurveType::g1_type::value_type;

                /// Key is a generic commitment key that is instantiated with g and h as basis,
                /// and a and b as powers.
                template<typename GroupType>
                struct kzg_commitment_key {
                    typedef GroupType group_type;
                    typedef typename group_type::curve_type curve_type;
                    typedef typename curve_type::scalar_field_type field_type;

                    typedef typename group_type::value_type group_value_type;
                    typedef typename field_type::value_type field_value_type;

                    /// Exponent is a
                    std::vector<group_value_type> a;

                    /// Returns true if commitment keys have the exact required length.
                 
                    inline bool has_correct_len(std::size_t n) const {
                        return a.size() == n ;
                    }

                    /// Returns both vectors scaled by the given vector entrywise.
                    /// In other words, it returns $\{v_i^{s_i}\}$
                    template<
                        typename InputIterator,
                        typename ValueType = typename std::iterator_traits<InputIterator>::value_type,
                        typename std::enable_if<std::is_same<field_value_type, ValueType>::value, bool>::type = true>
                    kzg_commitment_key<group_type> setup(InputIterator s_first,
                                                                            InputIterator s_last) const {
                        BOOST_ASSERT(has_correct_len(std::distance(s_first, s_last)));

                        kzg_commitment_key<group_type> result;
                        std::for_each(boost::make_zip_iterator(boost::make_tuple(s_first, a.begin())),
                                      boost::make_zip_iterator(boost::make_tuple(s_last, a.end())),
                                      [&](const boost::tuple<const field_value_type &, const group_value_type &,
                                                             const group_value_type &> &t) {
                                          result.a.emplace_back(t.template get<1>() * t.template get<0>());
                                        
                                      });

                        return result;
                    }
                };

                template<typename CurveType>
                using kzg_ckey = kzg_commitment_key<typename CurveType::template g1_type<>>;


                template<typename CurveType>
                struct kzg_commitment {
                    typedef CurveType curve_type;
                    typedef algebra::pairing::pairing_policy<curve_type> pairing;

                    typedef kzg_ckey<curve_type>ckey_type;
                    typedef kzg_vkey<curve_type> vkey_type;

                    typedef typename ckey_type::group_value_type g1_value_type;
                    typedef typename vkey_type::group_value_type g2_value_type;
                    typedef typename curve_type::gt_type::value_type gt_value_type;

                    typedef kzg_commitment_output<curve_type> output_type;

                   

                    /// Commits to a single vector of G1 elements in the following way:
                    /// $C = \prod_{i=0}^n (g^{a^i})^{f_i}$
                    /// Output is $C$
                    template<typename InputG1Iterator,
                             typename ValueType1 = typename std::iterator_traits<InputG1Iterator>::value_type,
                             typename std::enable_if<std::is_same<g1_value_type, ValueType1>::value, bool>::type = true>
                    static output_type commit(const ckey_type &ckey, InputG1Iterator f_first, InputG1Iterator f_last) {
                        BOOST_ASSERT(ckey.has_correct_len(std::distance(f_first, f_last)));

                        g1_value_type c = g1_value_type::one();
                        std::for_each_n(boost::make_zip_iterator(boost::make_tuple(f_first, ckey.a.begin())),
                        std::distance(f_first, f_last),
                        [&](const boost::tuple<const g1_value_type &, const g1_value_type &> &t) {
                            for(size_t i = 0; i < (t.template get<0>()); i++){
                                c = c * t.template get<1>();
                            }
                                      });
                
                    }
                };
            } ;   // namespace snark 
        }        // namespace zk
    }          // namespace crypto3
}    // namespace nil

#endif   