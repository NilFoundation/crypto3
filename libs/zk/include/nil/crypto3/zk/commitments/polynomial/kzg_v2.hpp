//-----------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#ifndef CRYPTO3_ZK_COMMITMENTS_KZG_V2_HPP
#define CRYPTO3_ZK_COMMITMENTS_KZG_V2_HPP

#include <tuple>
#include <vector>
#include <set>
#include <type_traits>

#include <boost/assert.hpp>
#include <boost/iterator/zip_iterator.hpp>
#include <boost/accumulators/accumulators.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>
#include <nil/crypto3/algebra/curves/detail/marshalling.hpp>
#include <nil/crypto3/algebra/marshalling.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/zk/commitments/batched_commitment.hpp>
#include <nil/crypto3/zk/detail/field_element_consumer.hpp>

using namespace nil::crypto3::math;

using namespace nil::crypto3;

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                // Placeholder-friendly class, KZGv2
                /**
                 * References:
                 * "Efficient polynomial commitment schemes for multiple points and polynomials",
                 * Dan Boneh, Justin Drake, Ben Fisch,
                 * <https://eprint.iacr.org/2020/081.pdf>
                 */
                template<typename CommitmentSchemeType>
                class kzg_commitment_scheme_v2 :
                        public polys_evaluator<
                                typename CommitmentSchemeType::params_type,
                                typename CommitmentSchemeType::commitment_type,
                                typename CommitmentSchemeType::polynomial_type> {
                public:
                    static constexpr bool is_kzg() { return true; }

                    using curve_type = typename CommitmentSchemeType::curve_type;
                    using field_type = typename CommitmentSchemeType::field_type;
                    using params_type = typename CommitmentSchemeType::params_type;

                    // This should be marshallable and transcriptable type
                    using commitment_type = typename CommitmentSchemeType::commitment_type;
                    using verification_key_type = typename curve_type::template g2_type<>::value_type;
                    using transcript_type = typename CommitmentSchemeType::transcript_type;
                    using transcript_hash_type = typename CommitmentSchemeType::transcript_hash_type;
                    using polynomial_type = typename CommitmentSchemeType::polynomial_type;

                    using eval_storage_type = eval_storage<field_type>;
                    using single_commitment_type = typename CommitmentSchemeType::single_commitment_type;

                    struct proof_type {
                        eval_storage_type z;
                        single_commitment_type pi_1, pi_2;

                        bool operator==(proof_type const &other) const {
                            return (z == other.z) && (pi_1 == other.pi_1) && (pi_2 == other.pi_2);
                        }

                        bool operator!=(proof_type const &other) const {
                            return !(*this == other);
                        }
                    };

                    using endianness = nil::marshalling::option::big_endian;
                    using field_element_type = nil::crypto3::marshalling::types::field_element<
                            nil::marshalling::field_type<endianness>,
                            commitment_type
                    >;
                private:
                    params_type _params;
                    std::map<std::size_t, commitment_type> _commitments;
                    std::map<std::size_t, std::vector<typename CommitmentSchemeType::single_commitment_type>> _ind_commitments;
                    std::vector<typename CommitmentSchemeType::scalar_value_type> _merged_points;
                protected:

                    // Differs from static one by input parameters
                    void merge_eval_points() {
                        std::set<typename CommitmentSchemeType::scalar_value_type> set;
                        for (auto const &it: this->_points) {
                            auto k = it.first;
                            for (std::size_t i = 0; i < this->_points[k].size(); ++i) {
                                set.insert(this->_points[k][i].begin(), this->_points[k][i].end());
                            }
                        }
                        _merged_points = std::vector<typename CommitmentSchemeType::scalar_value_type>(set.begin(),
                                                                                                       set.end());
                    }

                    typename math::polynomial<typename CommitmentSchemeType::scalar_value_type>
                    set_difference_polynom(
                            std::vector<typename CommitmentSchemeType::scalar_value_type> merged_points,
                            std::vector<typename CommitmentSchemeType::scalar_value_type> points) {
                        std::sort(merged_points.begin(), merged_points.end());
                        std::sort(points.begin(), points.end());
                        std::vector<typename CommitmentSchemeType::scalar_value_type> result;
                        std::set_difference(merged_points.begin(), merged_points.end(), points.begin(), points.end(),
                                            std::back_inserter(result));
                        if (result.size() == 0) {
                            return typename math::polynomial<typename CommitmentSchemeType::scalar_value_type>(
                                    {{CommitmentSchemeType::scalar_value_type::one()}});
                        }
                        BOOST_ASSERT(this->get_V(result) * this->get_V(points) == this->get_V(merged_points));
                        return this->get_V(result);
                    }

                    void update_transcript(std::size_t batch_ind,
                                           typename CommitmentSchemeType::transcript_type &transcript) {
                        /* The procedure of updating the transcript is subject to review and change
                         * #295 */

                        // Push commitments to transcript
                        transcript(_commitments[batch_ind]);

                        // Push evaluation points to transcript
                        for (std::size_t i = 0; i < this->_z.get_batch_size(batch_ind); i++) {
                            for (std::size_t j = 0; j < this->_z.get_poly_points_number(batch_ind, i); j++) {
                                transcript(this->_z.get(batch_ind, i, j));
                            }
                        }

                        // Push U polynomials to transcript
                        for (std::size_t i = 0; i < this->_points[batch_ind].size(); i++) {
                            auto poly = this->get_U(batch_ind, i);
                            for (std::size_t j = 0; j < poly.size(); ++j) {
                                transcript(poly[j]);
                            }
                        }
                    }

                public:
                    // Interface function. Isn't useful here.
                    void mark_batch_as_fixed(std::size_t index) {
                    }

                    static params_type
                    create_params(std::size_t d, typename CommitmentSchemeType::scalar_value_type alpha) {
                        return params_type(d, 1, alpha);
                    }

                    kzg_commitment_scheme_v2(params_type kzg_params) : _params(kzg_params) {
                        BOOST_ASSERT(kzg_params.verification_key.size() == 2);
                    }

                    // Differs from static, because we pack the result into byte blob.
                    commitment_type commit(std::size_t index) {
                        this->_ind_commitments[index] = {};
                        this->_ind_commitments[index].resize(this->_polys[index].size());
                        this->state_commited(index);

                        std::vector<std::uint8_t> result = {};
                        for (std::size_t i = 0; i < this->_polys[index].size(); ++i) {
                            BOOST_ASSERT(this->_polys[index][i].degree() <= _params.commitment_key.size());
                            auto single_commitment = nil::crypto3::zk::algorithms::commit_one<CommitmentSchemeType>(
                                    _params,
                                    this->_polys[index][i]);
                            this->_ind_commitments[index].push_back(single_commitment);
                            nil::marshalling::status_type status;
                            std::vector<uint8_t> single_commitment_bytes =
                                    nil::marshalling::pack<endianness>(single_commitment, status);
                            BOOST_ASSERT(status == nil::marshalling::status_type::success);
                            result.insert(result.end(), single_commitment_bytes.begin(), single_commitment_bytes.end());
                        }
                        _commitments[index] = result;
                        return result;
                    }

                    using preprocessed_data_type = bool;

                    preprocessed_data_type preprocess(transcript_type &transcript) const {
                        return true;
                    }

                    void setup(transcript_type &transcript, preprocessed_data_type b = true) {
                        // Nothing to be done here.
                    }

                    proof_type proof_eval(transcript_type &transcript) {
                        this->eval_polys();
                        this->merge_eval_points();

                        for (auto const &it: this->_commitments) {
                            auto k = it.first;
                            update_transcript(k, transcript);
                        }

                        auto theta = transcript.template challenge<typename CommitmentSchemeType::curve_type::scalar_field_type>();
                        auto theta_i = CommitmentSchemeType::scalar_value_type::one();
                        auto f = math::polynomial<typename CommitmentSchemeType::scalar_value_type>::zero();

                        for (auto const &it: this->_polys) {
                            auto k = it.first;
                            for (std::size_t i = 0; i < this->_z.get_batch_size(k); ++i) {
                                auto diffpoly = set_difference_polynom(_merged_points, this->_points.at(k)[i]);
                                auto f_i = math::polynomial<typename CommitmentSchemeType::scalar_value_type>(
                                        this->_polys[k][i].coefficients());
                                f += theta_i * (f_i - this->get_U(k, i)) * diffpoly;
                                theta_i *= theta;
                            }
                        }

                        BOOST_ASSERT(f % this->get_V(_merged_points) ==
                                     math::polynomial<typename CommitmentSchemeType::scalar_value_type>::zero());
                        f /= this->get_V(_merged_points);

                        typename CommitmentSchemeType::single_commitment_type pi_1 = nil::crypto3::zk::algorithms::commit_one<CommitmentSchemeType>(
                                _params, f);

                        transcript(pi_1);

                        auto theta_2 = transcript.template challenge<typename curve_type::scalar_field_type>();
                        math::polynomial<typename CommitmentSchemeType::scalar_value_type> theta_2_vanish = {
                                {-theta_2, CommitmentSchemeType::scalar_value_type::one()}};

                        theta_i = CommitmentSchemeType::scalar_value_type::one();

                        auto L = math::polynomial<typename CommitmentSchemeType::scalar_value_type>::zero();

                        for (auto const &it: this->_polys) {
                            auto k = it.first;
                            for (std::size_t i = 0; i < this->_z.get_batch_size(k); ++i) {
                                auto diffpoly = set_difference_polynom(_merged_points, this->_points.at(k)[i]);
                                auto Z_T_S_i = diffpoly.evaluate(theta_2);
                                auto f_i = math::polynomial<typename CommitmentSchemeType::scalar_value_type>(
                                        this->_polys[k][i].coefficients());
                                L += theta_i * Z_T_S_i * (f_i - this->get_U(k, i).evaluate(theta_2));
                                theta_i *= theta;
                            }
                        }

                        L -= this->get_V(_merged_points).evaluate(theta_2) * f;
                        BOOST_ASSERT(L.evaluate(theta_2) == CommitmentSchemeType::scalar_value_type::zero());
                        L /= theta_2_vanish;

                        typename CommitmentSchemeType::single_commitment_type pi_2 = nil::crypto3::zk::algorithms::commit_one<CommitmentSchemeType>(
                                _params, L);

                        /* TODO: Review the necessity of sending pi_2 to transcript */
                        transcript(pi_2);

                        return {this->_z, pi_1, pi_2};
                    }

                    bool verify_eval(const proof_type &proof,
                                     const std::map<std::size_t, commitment_type> &commitments,
                                     transcript_type &transcript) {
                        this->merge_eval_points();
                        this->_commitments = commitments;
                        this->_z = proof.z;

                        for (auto const &it: this->_commitments) {
                            auto k = it.first;
                            update_transcript(k, transcript);
                        }

                        auto theta = transcript.template challenge<typename CommitmentSchemeType::curve_type::scalar_field_type>();

                        transcript(proof.pi_1);

                        auto theta_2 = transcript.template challenge<typename CommitmentSchemeType::curve_type::scalar_field_type>();
                        auto theta_i = CommitmentSchemeType::scalar_value_type::one();

                        auto F = CommitmentSchemeType::single_commitment_type::zero();
                        auto rsum = CommitmentSchemeType::scalar_value_type::zero();

                        nil::marshalling::status_type status;

                        for (const auto &it: this->_commitments) {
                            auto k = it.first;
                            std::size_t blob_size = this->_commitments[k].size() / this->_points.at(k).size();
                            std::vector<std::uint8_t> byteblob(blob_size);

                            for (std::size_t i = 0; i < this->_points[k].size(); ++i) {
                                for (std::size_t j = 0; j < blob_size; j++) {
                                    byteblob[j] = this->_commitments[k][i * blob_size + j];
                                }
                                typename curve_type::template g1_type<>::value_type
                                        cm_i = nil::marshalling::pack(byteblob, status);
                                BOOST_ASSERT(status == nil::marshalling::status_type::success);
                                auto Z_T_S_i = set_difference_polynom(_merged_points, this->_points.at(k)[i]).evaluate(
                                        theta_2);
                                F += theta_i * Z_T_S_i * cm_i;
                                rsum += theta_i * Z_T_S_i * this->get_U(k, i).evaluate(theta_2);

                                theta_i *= theta;
                            }
                        }

                        F -= rsum * CommitmentSchemeType::single_commitment_type::one();
                        F -= this->get_V(_merged_points).evaluate(theta_2) * proof.pi_1;

                        auto left_side_pairing = nil::crypto3::algebra::pair_reduced<typename CommitmentSchemeType::curve_type>
                                (F + theta_2 * proof.pi_2, verification_key_type::one());

                        auto right_side_pairing = nil::crypto3::algebra::pair_reduced<typename CommitmentSchemeType::curve_type>
                                (proof.pi_2, _params.verification_key[1]);

                        return left_side_pairing == right_side_pairing;
                    }

                    const params_type &get_commitment_params() const {
                        return _params;
                    }
                };
            }     // namespace commitments
        }         // namespace zk
    }             // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_KZG_HPP
