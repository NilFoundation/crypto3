//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef FILECOIN_STORAGE_PROOFS_CORE__PROCESSING_NAIVE_MERKLE_TREE_HPP
#define FILECOIN_STORAGE_PROOFS_CORE__PROCESSING_NAIVE_MERKLE_TREE_HPP

#include <algorithm>
#include <vector>

#include <boost/assert.hpp>
#include <boost/variant.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/filecoin/storage/proofs/core/proof/proof.hpp>
#include <nil/filecoin/storage/proofs/core/crypto/feistel.hpp>
#include <nil/filecoin/storage/proofs/core/path_element.hpp>

#include <nil/filecoin/storage/proofs/core/merkle/tree.hpp>
#include <nil/filecoin/storage/proofs/core/merkle/proof.hpp>

namespace nil {
    namespace filecoin {
        namespace merkletree {
            namespace processing {
                namespace naive {


                    template<typename Hash>
                    MerkleProof<MerkleTree<typename Hash>::Hasher, 
                                MerkleTree<typename Hash>::Arity, 
                                MerkleTree<typename Hash>::SubTreeArity, 
                                MerkleTree<typename Hash>::TopTreeArity> MerkleTree_gen_proof(MerkleTree<typename Hash> &merkle_tree, std::usize i) {
                        
                        MerkleProof<MerkleTree<typename Hash>::Hasher, 
                                    MerkleTree<typename Hash>::Arity, 
                                    MerkleTree<typename Hash>::SubTreeArity, 
                                    MerkleTree<typename Hash>::TopTreeArity> proof 
                                    = merkle_tree.inner.gen_proof(i);

                        BOOST_ASSERT(proof.validate::<Hash>());

                        MerkleProof::try_from_proof(proof)
                    }

                    template<typename Hash>
                    MerkleProof<MerkleTree<typename Hash>::Hasher, 
                                MerkleTree<typename Hash>::Arity, 
                                MerkleTree<typename Hash>::SubTreeArity, 
                                MerkleTree<typename Hash>::TopTreeArity> proof MerkleTree_gen_cached_proof(MerkleTree<typename Hash> &merkle_tree, std::usize i, Option<usize> rows_to_discard) {
                        if (rows_to_discard.is_some() && rows_to_discard == 0) {
                            return gen_proof(merkle_tree, i);
                        }

                        MerkleProof<MerkleTree<typename Hash>::Hasher, 
                                    MerkleTree<typename Hash>::Arity, 
                                    MerkleTree<typename Hash>::SubTreeArity, 
                                    MerkleTree<typename Hash>::TopTreeArity> proof 
                                    = merkle_tree.inner.gen_cached_proof(i, rows_to_discard)?;

                        BOOST_ASSERT(proof.validate::<Hash>());

                        MerkleProof::try_from_proof(proof)
                    }
                }    // namespace naive
            }    // namespace processing
        }    // namespace merkletree
    }    // namespace filecoin
}    // namespace nil

#endif // FILECOIN_STORAGE_PROOFS_CORE__PROCESSING_NAIVE_MERKLE_TREE_HPP
