//=======================================================================
// Copyright 2002 Indiana University.
// Authors: Andrew Lumsdaine, Lie-Quan Lee, Jeremy G. Siek
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//=======================================================================

#include <boost/graph/graph_as_tree.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/cstdlib.hpp>
#include <iostream>

#include <nil/merkle/merkle.hpp>
#include <nil/merkle/proof.hpp>

#include <iostream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/adaptor/hashed.hpp>

#include <nil/crypto3/hash/blake2b.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/adaptor/hashed.hpp>

#include <nil/crypto3/hash/blake2b.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

//using namespace boost;
//using namespace std;
using namespace nil::crypto3::merkletree;
using namespace nil::crypto3;

int main()
{
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    std::array<char, 14> b = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x21', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    std::vector<std::array<char, 14>> v;
    for (size_t i = 0; i < 8; ++i) {
        v.push_back(a);
    }
    MerkleTree<hashes::blake2b<224>, 2> x(v);
    MerkleProof<hashes::blake2b<224>, 2> proof(x, 0);
    std::cout << proof.validate(a) << std::endl;
    std::cout << proof.validate(b) << std::endl;
    return boost::exit_success;
}
