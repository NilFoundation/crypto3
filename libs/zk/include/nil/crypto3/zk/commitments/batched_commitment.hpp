//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef CRYPTO3_ZK_STUB_PLACEHOLDER_COMMITMENT_SCHEME_HPP
#define CRYPTO3_ZK_STUB_PLACEHOLDER_COMMITMENT_SCHEME_HPP

#include <unordered_set>
#include <set>
#include <vector>
#include <utility>
#include <map>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/eval_storage.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {

                template<typename FieldType, typename CommitmentType>
                struct commitment_scheme_params_type{
                    using commitment_type = CommitmentType;
                    using field_type = FieldType;
                };

                // Placeholder commitment scheme works with polynomial_dfs
                template<typename ParamsType, typename TranscriptType,
                         typename PolynomialType = typename math::polynomial_dfs<typename ParamsType::field_type::value_type>>
                class polys_evaluator {
                public:
                    using params_type = ParamsType;
                    using commitment_type = typename ParamsType::commitment_type;
                    using field_type = typename ParamsType::field_type;
                    using transcript_type = TranscriptType;
                    using polynomial_type = PolynomialType;
                    using value_type = typename field_type::value_type;
                    using eval_storage_type = eval_storage<field_type>;

                    polys_evaluator() = default;

                    // These fields are accessed from marshalling.
                    eval_storage_type _z;

                    std::map<std::size_t, std::vector<polynomial_type>> _polys;

                    // _locked[batch] is true after it is commited
                    std::map<std::size_t, bool> _locked; 

                    std::map<std::size_t, std::vector<std::vector<value_type>>> _points;

                    bool operator==(const polys_evaluator& other) const {
                        return _z == other._z && _polys == other._polys &&
                            _locked == other._locked && _points == other._points;
                    }

                    // We frequently search over the this->_points structure, and it's better to keep a hashmap that maps point to
                    // it's index in vector for faster search. We need to duplicate this data for now, because the order of points matters.
                    std::map<std::size_t, std::vector<std::unordered_map<typename field_type::value_type, std::size_t>>> _points_map;

                    // Creates '_points_map'. We need to think about re-designing this class later. Currently this is used from LPC.
                    void build_points_map() {
                        for (const auto& [i, V]: this->_points) {
                            _points_map[i].resize(V.size());
                            for (std::size_t j = 0; j < V.size(); ++j) {
                                const auto& batch = V[j];
                                for (std::size_t k = 0; k < batch.size(); ++k) {
                                    // We need to store the index of the first occurance of each point.
                                    if (_points_map[i][j].find(batch[k]) == _points_map[i][j].end())
                                        _points_map[i][j][batch[k]] = k;
                                }
                            }
                        }
                    }

                    // This function is called from verifier directly, without actually committing to the
                    // polynomials.
                    void state_commited(std::size_t index) {
                        _locked[index] = true;
                        _points[index].resize(_polys[index].size());
                    }

                protected:
                    math::polynomial<typename field_type::value_type> get_V(
                        const std::vector<typename field_type::value_type> &points) const {

                        math::polynomial<typename field_type::value_type> V = {{field_type::value_type::one()}};
                        for( std::size_t xi_index = 0; xi_index < points.size(); xi_index++ ){
                            V *= math::polynomial<typename field_type::value_type>({-points[xi_index], field_type::value_type::one()});
                        }
                        return V;
                    }

                    std::vector<math::polynomial<typename field_type::value_type>> get_V_multipliers(
                        const std::vector<typename field_type::value_type> &points) const {

                        std::vector<math::polynomial<typename field_type::value_type>> V_multipliers;
                        for( std::size_t xi_index = 0; xi_index < points.size(); xi_index++ ){
                            V_multipliers.push_back(math::polynomial<typename field_type::value_type>(
                                {-points[xi_index], 1}));
                        }
                        return V_multipliers;
                    }

                    math::polynomial<typename field_type::value_type> get_U(std::size_t b_ind, std::size_t poly_ind) const {
                        const auto &points = _points.at(b_ind)[poly_ind];
                        BOOST_ASSERT(points.size() == this->_z.get_poly_points_number(b_ind, poly_ind));
                        std::vector<std::pair<typename field_type::value_type,typename field_type::value_type>> U_interpolation_points;

                        U_interpolation_points.resize(points.size());
                        for(std::size_t k = 0; k < points.size(); k++){
                            U_interpolation_points[k] = std::make_pair( points[k], this->_z.get(b_ind, poly_ind, k) );
                        }

                        return math::lagrange_interpolation(U_interpolation_points);
                    }

                    // We call them singles in recursive verifier
                    // We keep the order of points, not sure if that was required.
                    std::vector<typename field_type::value_type> get_unique_points() const {

                        std::vector<typename field_type::value_type> result;
                        std::unordered_set<typename field_type::value_type> result_set;

                        for( auto const &[k, point_batch]: _points ){
                            for( auto const &point_set: point_batch ){
                                for( auto const &point: point_set ){
                                    if (result_set.find(point) == result_set.end()) {
                                        result.push_back(point);
                                        result_set.insert(point);
                                    }
                                }
                            }
                        }

                        return result;
                    }

                    std::vector<std::vector<typename field_type::value_type>> get_unique_point_sets_list() const{
                        std::vector<std::vector<typename field_type::value_type>> unique_points;

                        for (auto const &[k, point]:_points) {
                            for (std::size_t i = 0; i < point.size(); i++) {
                                bool found = false;
                                for (std::size_t j = 0; j < unique_points.size(); j++) {
                                    if( unique_points[j] == point[i] ){
                                        found = true;
                                        break;
                                    }
                                }
                                if (!found) {
                                    unique_points.push_back(point[i]);
                                }
                            }
                        }
                        return unique_points;
                    }

                    std::map<std::size_t, std::vector<std::size_t>> get_eval_map(
                            const std::vector<std::vector<typename field_type::value_type>>& unique_points) const {
                        std::map<std::size_t, std::vector<std::size_t>> eval_map;

                        for(auto const &[k, point] : _points) {
                            eval_map[k] = {};
                            for (std::size_t i = 0; i < point.size(); i++) {
                                bool found = false;
                                for (std::size_t j = 0; j < unique_points.size(); j++) {
                                    if (unique_points[j] == point[i]) {
                                        eval_map[k].push_back(j);
                                        found = true;
                                        break;
                                    }
                                }
                                BOOST_ASSERT(found);
                            }
                        }
                        return eval_map;
                    }

                    void eval_polys() {
                        for(auto const &[k, poly] : _polys) {
                            _z.set_batch_size(k, poly.size());
                            auto const &point = _points.at(k);

                            BOOST_ASSERT(poly.size() == point.size() || point.size() == 1);

                            for (std::size_t i = 0; i < poly.size(); ++i) {
                                _z.set_poly_points_number(k, i, point[i].size());
                                for (std::size_t j = 0; j < point[i].size(); j++) {
                                    _z.set(k, i, j, poly[i].evaluate(point[i][j]));
                                }
                            }
                        }
                    }

                public:
                    boost::property_tree::ptree get_params() const{
                        boost::property_tree::ptree root;
                        return root;
                    }

                    void append_to_batch(std::size_t index, const polynomial_type& poly){
                        if (_locked.find(index) == _locked.end())
                            _locked[index] = false;

                        // We cannot modify batch after commitment
                        BOOST_ASSERT(!_locked[index]);

                        _polys[index].push_back(poly);
                    }

                    template<typename container_type>
                    void append_to_batch(std::size_t index, const container_type& polys){
                        if (_locked.find(index) == _locked.end())
                            _locked[index] = false;

                        BOOST_ASSERT(!_locked[index]); // We cannot modify batch after commitment
                        _polys[index].insert(std::end(_polys[index]), std::begin(polys), std::end(polys));
                    }

                    void append_eval_point(std::size_t batch_id, typename field_type::value_type point) {
                        // We can add points only after polynomails are commited.
                        BOOST_ASSERT(_locked[batch_id]);

                        for (std::size_t i = 0; i < _points[batch_id].size(); i++) {
                            _points[batch_id][i].push_back(point);
                        }
                    }

                    void append_eval_point(
                            std::size_t batch_id, std::size_t poly_id,
                            const typename field_type::value_type& point) {
                        // We can add points only after polynomails are commited.
                        BOOST_ASSERT(_locked[batch_id]); 

                        _points[batch_id][poly_id].push_back(point);
                    }

                    // This function don't check evaluation points repeats
                    void append_eval_points(std::size_t batch_id, std::set<typename field_type::value_type> points){
                        BOOST_ASSERT(_locked[batch_id]); // We can add points only after polynomails are commited.
                        for(std::size_t i = 0; i < _points[batch_id].size(); i++){
                            _points[batch_id][i].insert(_points[batch_id][i].end(), points.begin(), points.end());
                        }
                    }

                    // This function don't check evaluation points repeats
                    void append_eval_points(std::size_t batch_id, std::size_t poly_id,
                            std::set<typename field_type::value_type> points) {
                        // We can add points only after polynomails are commited.
                        BOOST_ASSERT(_locked[batch_id]); 

                        _points[batch_id][poly_id].insert(_points[batch_id][poly_id].end(), points.begin(), points.end());
                    }

                    void set_batch_size(std::size_t batch_id, std::size_t batch_size) {
                        if (_points.find(batch_id) == _points.end()) {
                            _points[batch_id] = {};
                        }
                        _points[batch_id].resize(batch_size);
                        _locked[batch_id] = true;
                    }
                };

                namespace algorithms{
                    // TODO check, that SchemeType has commitment_type and commit functions
                    // Is called from preprocessor
                    template<typename FieldType, typename SchemeType>
                    static typename SchemeType::preprocessed_data_type preprocess(
                        SchemeType &scheme, typename SchemeType::transcript_type &transcript
                    ){
                        return scheme.preprocess(transcript);
                    }

                    // Is called from prover and verifier. Checks, that transcript is well-initialized
                    template<typename FieldType, typename SchemeType>
                    static void setup(
                        SchemeType &scheme,
                        typename SchemeType::transcript_type &transcript,
                        const typename SchemeType::preprocessed_data_type preprocessed_data
                        ) {
                        return scheme.setup(transcript, preprocessed_data);
                    }

                    // TODO check, that SchemeType has commitment_type and commit functions
                    template<typename FieldType, typename SchemeType>
                    static typename SchemeType::commitment_type commit(
                        SchemeType &scheme,
                        const std::vector<math::polynomial_dfs<typename FieldType::value_type>> &polynomials,
                        std::size_t index
                    ){
                        return scheme.commit(polynomials, index);
                    }

                    // TODO check, that SchemeType has proof_type and proof_eval functions
                    template<typename FieldType, typename SchemeType>
                    static typename SchemeType::proof_type proof_eval(
                        SchemeType &scheme,
                        const std::vector<std::vector<std::vector<FieldType>>> &evaluation_points,
                        typename SchemeType::transcript_type &transcript
                    ){
                        return scheme.proof_eval(evaluation_points);
                    }

                    // TODO check, that SchemeType has proof_type and verify_eval functions
                    template<typename FieldType, typename SchemeType>
                    static bool verify_eval(
                        SchemeType &scheme,
                        const typename SchemeType::proof_type &proof,
                        const std::map<std::size_t, std::vector<std::vector<FieldType>>> &evaluation_points,
                        const std::map<std::size_t, typename SchemeType::commitment_type> &commitments,
                        typename SchemeType::transcript_type &transcript
                    ){
                        return scheme.verify_eval(proof, evaluation_points, commitments);
                    }

                }
            }
        }
    }
}

#endif // CRYPTO3_ZK_STUB_PLACEHOLDER_COMMITMENT_SCHEME_HPP
