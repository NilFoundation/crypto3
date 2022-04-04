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
#include <nil/crypto3/algebra/curves/pallas.hpp>

#include <boost/foreach.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/pickles/verifier_index.hpp>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(pickles_proof_struct_test_suite)

const char *test_data = TEST_DATA;

boost::property_tree::ptree string_data(const char *child_name) {
    boost::property_tree::ptree root_data;
    boost::property_tree::read_json(test_data, root_data);
    boost::property_tree::ptree string_data = root_data.get_child(child_name);

    return string_data;
}

template <typename Iterator>
std::string get_cppui256(Iterator it) {
    return it->second.template get_value<std::string>() + "_cppui256";
}

zk::snark::pickles_proof<nil::crypto3::algebra::curves::vesta> fill_proof(boost::property_tree::ptree root) {
    size_t i = 0;
    std::string base_path = "protocolStateProof.json.proof.";

    auto best_chain = root.get_child("data.bestChain")) {
        i = 0;
        for (auto &row :best_chain.second.get_child(base_path + "messages.w_comm")) {
            auto it = row.second.get_child("").begin()->second.get_child("").begin();
            proof.commitments.w_comm[i] = {get_cppui256(it++), get_cppui256(it), 0x1};
            ++i;
        }
        it = best_chain.second.get_child(base_path + "messages.z_comm").begin()->second.get_child("").begin();
        proof.commitments.z_comm = {get_cppui256(it++), get_cppui256(it), 0x1};
        it = best_chain.second.get_child(base_path + "messages.t_comm").begin()->second.get_child("").begin();
        proof.commitments.t_comm = {get_cppui256(it++), get_cppui256(it), 0x1};
        proof.commitments.lookup;    // TODO: where it is?

        i = 0;
        for (pt::ptree::value_type &row :best_chain.second.get_child(base_path + "openings.proof.lr")) {
            auto it = row.second.begin()->second.get_child("").begin();
            proof.proof.lr.push_back({get_cppui256(it++), get_cppui256(it), 0x1});
            ++i;
        }
        it = best_chain.second.get_child(base_path + "openings.proof.delta").begin();
        proof.proof.delta = {get_cppui256(it++), get_cppui256(it), 0x1};
        it = best_chain.second.get_child("openings.proof.sg").begin();
        proof.proof.sg = {get_cppui256(it++), get_cppui256(it), 0x1};

        proof.proof.z1 = get_cppui256(best_chain.second.get_child(base_path + "openings.proof.z1").begin());
        proof.proof.z2 = get_cppui256(best_chain.second.get_child(base_path + "openings.proof.z2").begin());

        std::size_t ev_i = 0;
        for (auto &evals_it : best_chain.second.get_child(base_path + "openings.evals")) {

            i = 0;
            for (auto &row : evals_it.second.get_child("w")) {
                proof.evals[ev_i].w[i] = get_cppui256(row.second.begin()));
            }

            proof.evals[ev_i].z = get_cppui256(evals_it.second.get_child("z").begin()));

            i = 0;
            for (auto &row : evals_it.second.get_child("s")) {
                proof.evals[ev_i].s[i] = get_cppui256(row.second.begin()));
            }
            proof.evals[ev_i].generic_selector = get_cppui256(evals_it.second.get_child("generic_selector").begin()));
            proof.evals[ev_i].poseidon_selector = get_cppui256(evals_it.second.get_child("poseidon_selector").begin()));

            ev_i++;
        }

        ft_eval1 proof.ft_eval1 = new_root.second.get<std::string>(base_path + "openings.ft_eval1") + "_cppui256";
    }
    //            // public
    //            std::vector<typename CurveType::scalar_field_type::value_type> public_p; // TODO: implement it
    //
    //            // Previous challenges
    //            std::vector<
    //                std::tuple<std::vector<typename CurveType::scalar_field_type::value_type>, commitment_scheme>>
    //                prev_challenges; // TODO: implement it
}

zk::snark::verifier_index<nil::crypto3::algebra::curves::vesta> fill_verify_index(boost::property_tree::ptree root) {
    size_t i = 0;
    //    ver_index.domain;    // "log_size_of_group":15, "group_gen" : "0x130D1D6482B9C33536E280AE674431F85F4A103EF6AF12C7AC4CDF0AD3EDB265";
    ver_index.max_poly_size = root.get<std::size_t>("data.blockchainVerificationKey.index.max_poly_size");
    ver_index.max_quot_size = root.get<std::size_t>("data.blockchainVerificationKey.index.max_quot_size");
    ver_index.srs = root.get<std::string>("data.blockchainVerificationKey.index.srs");    // TODO: null
    i = 0;
    for (pt::ptree::value_type & row : root.get_child("data.blockchainVerificationKey.commitments.sigma_comm")) {
        auto it = row.second.begin();
        ver_index.sigma_comm[i] = {get_cppui256(it++), get_cppui256(it), 0x1};
        ++i;
    }

    i = 0;
    for (pt::ptree::value_type &row : root.get_child("data.blockchainVerificationKey.commitments.coefficients_comm")) {
        auto it = row.second.begin();
        ver_index.coefficients_comm[i] = {get_cppui256(it++), get_cppui256(it), 0x1};
        ++i;
    }
    auto it = root.get_child("data.blockchainVerificationKey.commitments.generic_comm").begin();
    generic_comm.coefficients_comm = {get_cppui256(it++), get_cppui256(it), 0x1};

    it = root.get_child("data.blockchainVerificationKey.commitments.psm_comm").begin();
    ver_index.psm_comm.coefficients_comm = {get_cppui256(it++), get_cppui256(it), 0x1};
    it = root.get_child("data.blockchainVerificationKey.commitments.complete_add_comm").begin();
    ver_index.complete_add_comm.coefficients_comm[i] = {get_cppui256(it++), get_cppui256(it), 0x1};
    it = root.get_child("data.blockchainVerificationKey.commitments.mul_comm").begin();
    ver_index.mul_comm.coefficients_comm = {get_cppui256(it++), get_cppui256(it), 0x1};
    it = root.get_child("data.blockchainVerificationKey.commitments.emul_comm").begin();
    ver_index.emul_comm.coefficients_comm = {get_cppui256(it++), get_cppui256(it), 0x1};
    it = root.get_child("data.blockchainVerificationKey.commitments.endomul_scalar_comm").begin();
    ver_index.endomul_scalar_comm.coefficients_comm = {get_cppui256(it++), get_cppui256(it), 0x1};

    i = 0;
    for (pt::ptree::value_type &row : root.get_child("data.blockchainVerificationKey.commitments.chacha_comm")) {
        auto it = row.second.begin();
        ver_index.chacha_comm[i] = {get_cppui256(it++), get_cppui256(it), 0x1};
        ++i;
    }
    i = 0;
    for (pt::ptree::value_type &row : root.get_child("data.blockchainVerificationKey.index.shifts")) {
        auto it = row.second.begin();
        ver_index.shifts[i] = {get_cppui256(it++), get_cppui256(it), 0x1};
        ++i;
    }

    // Polynomial in coefficients form
    //    ver_index.zkpm;    // TODO: where it is?
    //    ver_index.w;       // TODO: where it is?
    //    ver_index.endo;    // TODO: where it is?
    //    ver_index.lookup_index = root.get_child("data.blockchainVerificationKey.index.lookup_index");    // TODO: null
    //    ver_index.linearization;       // TODO: where it is?
    //    ver_index.powers_of_alpha;     // TODO: where it is?
    //    ver_index.fr_sponge_params;    // TODO: where it is?
    //    ver_index.fq_sponge_params;    // TODO: where it is?
}

BOOST_AUTO_TEST_CASE(pickles_proof_struct_test_suite) {
    boost::property_tree::ptree root;
    // Load the json file in this ptree
    boost::property_tree::read_json(TEST_DATA, root);

    zk::snark::pickles_proof<nil::crypto3::algebra::curves::vesta> proof = fill_proof(root);
    zk::snark::verifier_index<nil::crypto3::algebra::curves::vesta> ver_index = fill_verify_index(root);

}
BOOST_AUTO_TEST_SUITE_END()