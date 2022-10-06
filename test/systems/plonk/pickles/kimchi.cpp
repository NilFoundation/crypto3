//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE pickles_struct_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/json.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <boost/foreach.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/verifier_index.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/verifier.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk::snark;

BOOST_AUTO_TEST_SUITE(kimchi_proof_struct_test_suite)

using curve_type = nil::crypto3::algebra::curves::vesta;
using vesta_verifier_index_type = zk::snark::verifier_index<
    curve_type,
    nil::crypto3::zk::snark::arithmetic_sponge_params<curve_type::scalar_field_type::value_type>,
    nil::crypto3::zk::snark::arithmetic_sponge_params<curve_type::base_field_type::value_type>,
    nil::crypto3::zk::snark::kimchi_constant::COLUMNS, 
    nil::crypto3::zk::snark::kimchi_constant::PERMUTES
>;

template<typename Iterator>
nil::crypto3::multiprecision::cpp_int get_cppui256(Iterator it) {
    BOOST_ASSERT(it->second.template get_value<std::string>() != "");
    return nil::crypto3::multiprecision::cpp_int(it->second.template get_value<std::string>());
}

// make_proof function name is similar to crypto3/marshalling naming style

zk::snark::proof_type<curve_type> make_proof(boost::property_tree::ptree root) {
    typename zk::snark::proof_type<curve_type> proof;
    size_t i = 0;
    std::string base_path = "protocolStateProof.json.proof.";

    auto best_chain = *root.get_child("data.bestChain").begin();
    i = 0;
    for (auto &row : best_chain.second.get_child(base_path + "messages.w_comm")) {
        auto it = row.second.get_child("").begin()->second.get_child("").begin();
        proof.commitments.w_comm[i].unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
        ++i;
    }
    auto it = best_chain.second.get_child(base_path + "messages.z_comm").begin()->second.get_child("").begin();
    proof.commitments.z_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));

    it = best_chain.second.get_child(base_path + "messages.t_comm").begin()->second.get_child("").begin();
    proof.commitments.t_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
    //    proof.commitments.lookup;    // TODO: where it is?

    i = 0;
    for (auto &row : best_chain.second.get_child(base_path + "openings.proof.lr")) {
        auto it0 = row.second.begin()->second.get_child("").begin();
        auto it1 = row.second.begin();
        it1++;
        it1 = it1->second.begin();
        proof.proof.lr.push_back({{get_cppui256(it0++), get_cppui256(it0)}, {get_cppui256(it1++), get_cppui256(it1)}});
        ++i;
    }
    it = best_chain.second.get_child(base_path + "openings.proof.delta").begin();
    proof.proof.delta = {get_cppui256(it++), get_cppui256(it)};
    it = best_chain.second.get_child(base_path + "openings.proof.sg").begin();
    proof.proof.sg = {get_cppui256(it++), get_cppui256(it)};

    proof.proof.z1 = multiprecision::cpp_int(best_chain.second.get<std::string>(base_path + "openings.proof.z_1"));
    proof.proof.z2 = multiprecision::cpp_int(best_chain.second.get<std::string>(base_path + "openings.proof.z_2"));

    std::size_t ev_i = 0;
    for (auto &evals_it : best_chain.second.get_child(base_path + "openings.evals")) {

        i = 0;
        for (auto &row : evals_it.second.get_child("w")) {
            for (auto &cell : row.second) {
                proof.evals[ev_i].w[i].push_back(get_cppui256(&cell));
            }
            i++;
        }

        //proof.evals[ev_i].z.size();= get_cppui256(evals_it.second.get_child("z").begin());
        for( auto z_it : evals_it.second.get_child("z") ){
            proof.evals[ev_i].z.push_back(get_cppui256(&z_it));
        }
       
        i = 0;
        for (auto &row : evals_it.second.get_child("s")) {
            for (auto &cell : row.second) {
                proof.evals[ev_i].s[i].push_back(get_cppui256(&cell));
            }
            i++;
        }

//        proof.evals[ev_i].generic_selector = get_cppui256(evals_it.second.get_child("generic_selector").begin());
        for( auto s_it : evals_it.second.get_child("generic_selector") ){
            proof.evals[ev_i].generic_selector.push_back(get_cppui256(&s_it));
        }

//        proof.evals[ev_i].poseidon_selector = get_cppui256(evals_it.second.get_child("poseidon_selector").begin());
        for( auto p_it : evals_it.second.get_child("poseidon_selector") ){
            proof.evals[ev_i].poseidon_selector.push_back(get_cppui256(&p_it));
        }
        ev_i++;
    }

    proof.ft_eval1 = multiprecision::cpp_int(best_chain.second.get<std::string>(base_path + "openings.ft_eval1"));
    //            // public
    //            std::vector<typename CurveType::scalar_field_type::value_type> public_p; // TODO: where it is?
    //
    //            // Previous challenges
    //            std::vector<
    //                std::tuple<std::vector<typename CurveType::scalar_field_type::value_type>, commitment_scheme>>
    //                prev_challenges; // TODO: where it is?
    return proof;
}

vesta_verifier_index_type make_verify_index(boost::property_tree::ptree root, boost::property_tree::ptree const_root) {
    using curve_type = typename nil::crypto3::algebra::curves::vesta;

    vesta_verifier_index_type ver_index;
    size_t i = 0;

    // TODO Is it right? Is it a good way to set domain generator?
    // We need to assert, need to check that the input is indeed the root of unity

    auto d_gen = multiprecision::cpp_int(const_root.get<std::string>("verify_index.domain.group_gen"));
    auto d_size = const_root.get<std::size_t>("verify_index.domain.log_size_of_group");
    // std::cout << d_gen << " " << d_size << std::endl;
    ver_index.domain = nil::crypto3::math::basic_radix2_domain<typename curve_type::scalar_field_type>(d_size+1);
    // std::cout << ver_index.domain.omega.data << std::endl;
    ver_index.domain.omega = d_gen;


    ver_index.max_poly_size = root.get<std::size_t>("data.blockchainVerificationKey.index.max_poly_size");
    ver_index.max_quot_size = root.get<std::size_t>("data.blockchainVerificationKey.index.max_quot_size");
    //    ver_index.srs = root.get<std::string>("data.blockchainVerificationKey.index.srs");    // TODO: null
    i = 0;
    for (auto &row : root.get_child("data.blockchainVerificationKey.commitments.sigma_comm")) {
        auto it = row.second.begin();
        ver_index.sigma_comm[i].unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
        ++i;
    }

    i = 0;
    for (auto &row : root.get_child("data.blockchainVerificationKey.commitments.coefficients_comm")) {
        auto it = row.second.begin();
        ver_index.coefficients_comm[i].unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
        ++i;
    }
    auto it = root.get_child("data.blockchainVerificationKey.commitments.generic_comm").begin();
    ver_index.generic_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));

    it = root.get_child("data.blockchainVerificationKey.commitments.psm_comm").begin();
    ver_index.psm_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
    it = root.get_child("data.blockchainVerificationKey.commitments.complete_add_comm").begin();
    ver_index.complete_add_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
    it = root.get_child("data.blockchainVerificationKey.commitments.mul_comm").begin();
    ver_index.mul_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
    it = root.get_child("data.blockchainVerificationKey.commitments.emul_comm").begin();
    ver_index.emul_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
    it = root.get_child("data.blockchainVerificationKey.commitments.endomul_scalar_comm").begin();
    ver_index.endomul_scalar_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));

    // TODO: null in example
    //    i = 0;
    //    for (auto &row : root.get_child("data.blockchainVerificationKey.commitments.chacha_comm")) {
    //        auto it = row.second.begin();
    //        ver_index.chacha_comm[i].unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
    //        ++i;
    //    }
    //i = 0; 
    // No member shifts
    //for (auto &row : root.get_child("data.blockchainVerificationKey.index.shifts")) {
    //    ver_index.shifts[i] = multiprecision::cpp_int(row.second.get_value<std::string>());
    //    ++i;
    //}

    // Polynomial in coefficients form
    // Const
    ver_index.zkpm = {0x2C46205451F6C3BBEA4BABACBEE609ECF1039A903C42BFF639EDC5BA33356332_cppui256,
                      0x1764D9CB4C64EBA9A150920807637D458919CB6948821F4D15EB1994EADF9CE3_cppui256,
                      0x0140117C8BBC4CE4644A58F7007148577782213065BB9699BF5C391FBE1B3E6D_cppui256,
                      0x0000000000000000000000000000000000000000000000000000000000000001_cppui256};
    ver_index.w = multiprecision::cpp_int(const_root.get<std::string>("verify_index.w"));
    ver_index.endo = multiprecision::cpp_int(const_root.get<std::string>("verify_index.endo"));

    //ver_index.lookup_index = root.get_child("data.blockchainVerificationKey.index.lookup_index"); // TODO: null
    //ver_index.linearization;       // TODO: where it is?
    ver_index.powers_of_alpha.next_power = 24;

    i = 0;
    ver_index.fr_sponge_params.round_constants.resize(const_root.get_child("verify_index.fr_sponge_params.round_constants").size());
    for (auto &row : const_root.get_child("verify_index.fr_sponge_params.round_constants")) {
        size_t j = 0;
        for (auto cell : row.second){
            ver_index.fr_sponge_params.round_constants[i].push_back(get_cppui256(&cell));
            j++;
        }
        i++;
    }

    i = 0;
    for (auto &row : const_root.get_child("verify_index.fr_sponge_params.mds")) {
        size_t j = 0;
        for (auto cell : row.second){
            ver_index.fr_sponge_params.mds[i][j] = get_cppui256(&cell);
            j++;
        }
        i++;
    }

    i = 0;
    ver_index.fq_sponge_params.round_constants.resize(const_root.get_child("verify_index.fq_sponge_params.round_constants").size());
    for (auto &row : const_root.get_child("verify_index.fq_sponge_params.round_constants")) {
        size_t j = 0;
        for (auto cell : row.second){
            ver_index.fq_sponge_params.round_constants[i].push_back(get_cppui256(&cell));
            j++;
        }
        i++;
    }

    i = 0;
    for (auto &row : const_root.get_child("verify_index.fq_sponge_params.mds")) {
        size_t j = 0;
        for (auto cell : row.second){
            ver_index.fr_sponge_params.mds[i][j] = get_cppui256(&cell);
            j++;
        }
        i++;
    }

    // TODO: Add assertions about right size of 
    //      fr_sponge_params.mds, 
    //      fr_sponge_params.round_constants,

    return ver_index;
}

BOOST_AUTO_TEST_CASE(pickles_proof_struct_test_suite) {
    boost::property_tree::ptree root;
    boost::property_tree::ptree const_root;
    // Load the json file in this ptree
    std::string test_data = TEST_DATA;
    boost::property_tree::read_json(test_data + ".json", root);
    boost::property_tree::read_json(test_data + "_const.json", const_root);

    zk::snark::proof_type<nil::crypto3::algebra::curves::vesta> proof = make_proof(root);
    vesta_verifier_index_type ver_index = make_verify_index(root, const_root);
    
    //group_map<curve_type> g_map;
    //BOOST_CHECK(true);
    // TODO :: verifier should work correctly
    //verifier<curve_type, vesta_verifier_index_type>::verify(g_map, ver_index, proof);
}
BOOST_AUTO_TEST_SUITE_END()