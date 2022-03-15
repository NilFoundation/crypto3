//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#ifndef CRYPTO3_ZK_COMMITMENTS_KZG_COMMITMENT_HPP
#define CRYPTO3_ZK_COMMITMENTS_KZG_COMMITMENT_HPP

#include <tuple>
#include <vector>
#include <type_traits>

#include <boost/assert.hpp>
#include <boost/iterator/zip_iterator.hpp>
#include <boost/accumulators/accumulators.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/pairing/pairing_policy.hpp>

using namespace nil::crypto3::math;

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                
                template<typename CurveType>
                struct kzg_commitment {

                    typedef CurveType curve_type;
                    typedef algebra::pairing::pairing_policy<curve_type> pairing;
                    typedef typename curve_type::gt_type::value_type gt_value_type;

                    using base_field_value_type = typename curve_type::base_field_type::value_type;
                    using commitment_key_type = std::vector<typename curve_type::template g1_type<>::value_type>;
                    using verification_key_type = typename curve_type::template g2_type<>::value_type;
                    using commitment_type = typename curve_type::template g1_type<>::value_type;
                    using proof_type = commitment_type;

                    struct params_type {
                        std::size_t a;
                    };

                    static std::pair<commitment_key_type, verification_key_type> setup(const std::size_t n,
                                                                                       params_type params) {

                        size_t a_scaled = params.a;
                        commitment_key_type commitment_key = {curve_type::template g1_type<>::value_type::one()};
                        verification_key_type verification_key =
                            curve_type::template g2_type<>::value_type::one() * params.a;

                        for (std::size_t i = 0; i < n; i++) {
                            commitment_key.emplace_back(a_scaled * (curve_type::template g1_type<>::value_type::one()));
                            a_scaled = a_scaled * params.a;
                        }

                        return std::make_pair(commitment_key, verification_key);
                    }

                    static commitment_type commit(const commitment_key_type &commitment_key,
                                                  const polynomial<base_field_value_type> &f) {

                        commitment_type commitment = f[0] * commitment_key[0];

                        for (std::size_t i = 0; i < f.size(); i++) {
                            commitment = commitment + commitment_key[i] * f[i];
                        }

                        return commitment;
                    }

                    static proof_type proof_eval(commitment_key_type commitment_key,
                                                 typename curve_type::base_field_type::value_type x,
                                                 typename curve_type::base_field_type::value_type y,
                                                 const polynomial<base_field_value_type> &f) {

                        const polynomial<base_field_value_type> denominator_polynom = {-x, 1};

                        const polynomial<base_field_value_type> q =
                            (f + polynomial<base_field_value_type> {-y}) / denominator_polynom;

                        proof_type p = kzg_commitment::commit(commitment_key, q);
                        return p;
                    }

                    static bool verify_eval(verification_key_type verification_key,
                                            commitment_type C_f,
                                            base_field_value_type x,
                                            base_field_value_type y,
                                            proof_type p) {

                        typename curve_type::gt_type::value_type gt1 =
                            algebra::pair<curve_type>(C_f - curve_type::template g1_type<>::value_type::one() * y,
                                                      curve_type::template g2_type<>::value_type::one());

                        typename curve_type::gt_type::value_type gt2 = algebra::pair<curve_type>(
                            p, verification_key - curve_type::template g2_type<>::value_type::one() * x);

                        return gt1 == gt2;
                    }
                };
            };    // namespace snark
        }         // namespace zk
    }             // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_KZG_COMMITMENT_HPP