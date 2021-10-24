//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
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

#ifndef FILECOIN_MERKLE_HPP
#define FILECOIN_MERKLE_HPP
namespace nil {
    namespace filecoin {
        namespace merkletree {

// Number of batched nodes processed and stored together when
// populating from the data leaves.
const size_t BUILD_DATA_BLOCK_SIZE = 64 * BUILD_CHUNK_NODES;

// Merkle Tree.
//
// All leafs and nodes are stored in a linear array (vec).
//
// A merkle tree is a tree in which every non-leaf node is the hash of its
// child nodes. A diagram depicting how it works://
// ```text
//         root = h1234 = h(h12 + h34)
//        /                           \
//  h12 = h(h1 + h2)            h34 = h(h3 + h4)
//   /            \              /            \
// h1 = h(tx1)  h2 = h(tx2)    h3 = h(tx3)  h4 = h(tx4)
// ```
//
// In memory layout:
//
// ```text
//     [h1 h2 h3 h4 h12 h34 root]
// ```
//
// Merkle root is always the last element in the array.
//
// The number of inputs must always be a power of two.
//
// This tree structure can consist of at most 3 layers of trees (of
// arity U, N and R, from bottom to top).
//
// This structure ties together multiple Merkle Trees and allows
// supported properties of the Merkle Trees across it.  The
// significance of this class is that it allows an arbitrary number
// of sub-trees to be constructed and proven against.
//
// To show an example, this structure can be used to create a single
// tree composed of 3 sub-trees, each that have branching factors /
// arity of 4.  Graphically, this may look like this:
//
// ```text
//                O
//       ________/|\_________
//      /         |          \
//     O          O           O
//  / / \ \    / / \ \     / / \ \
// O O  O  O  O O  O  O   O O  O  O
//
//
// At most, one more layer (top layer) can be constructed to group a
// number of the above sub-tree structures (not pictured).
//
// BaseTreeArity is the arity of the base layer trees [bottom].
// SubTreeArity is the arity of the sub-tree layer of trees [middle].
// TopTreeArity is the arity of the top layer of trees [top].
//
// With N and R defaulting to 0, the tree performs as a single base
// layer merkle tree without layers (i.e. a conventional merkle
// tree).


enum Data<E: Element, A: Algorithm<E>, S: Store<E>, BaseTreeArity: Unsigned, SubTreeArity: Unsigned>
{
    // A BaseTree contains a single Store.
    BaseTree(S),

    // A SubTree contains a list of BaseTrees.
    SubTree(Vec<MerkleTree<E, A, S, BaseTreeArity>>),

    // A TopTree contains a list of SubTrees.
    TopTree(Vec<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity>>),
}

template<typename E, typename A<E>, typename S<E>, typename BaseTreeArity, typename SubTreeArity>
class Data {
    // Read-only access to the BaseTree store.
    Store<Element> store() {
        match self {
            Data::BaseTree(s) => Some(s),
            _ => None,
        }
    }

    // Mutable access to the BaseTree store.
    Store<Element> store_mut(f) -> Option<&mut S> {
        match self {
            Data::BaseTree(s) => Some(s),
            _ => None,
        }
    }

    // Access to the list of SubTrees.
    std::vector<MerkleTree<E, A<E>, S<E>, BaseTreeArity, SubTreeArity>> sub_trees() {
        match self {
            Data::TopTree(s) => Some(s),
            _ => None,
        }
    }

    // Access to the list of BaseTrees.
    std::vector<MerkleTree<E, A<E>, S<E>, BaseTreeArity>> base_trees() {
        match self {
            Data::SubTree(s) => Some(s),
            _ => None,
        }
    }

};

template <typename E, typename A<E>, typename S<E>, typename BaseTreeArity, typename SubTreeArity, typename TopTreeArity>
struct MerkleTree {
    Data<E, A<E>, S<E>, BaseTreeArity, SubTreeArity> data;
    size_t leafs;
    size_t len;
    // Note: The former 'upstream' merkle_light project uses 'height'
    // (with regards to the tree property) incorrectly, so we've
    // renamed it since it's actually a 'row_count'.  For example, a
    // tree with 2 leaf nodes and a single root node has a height of
    // 1, but a row_count of 2.
    //
    // Internally, this code considers only the row_count.
    size_t row_count;
    // Cache with the `root` of the tree built from `data`. This allows to
    // not access the `Store` (e.g., access to disks in `DiskStore`).
    E root;
}

/// Element stored in the merkle tree.
class Element {
    /// Returns the length of an element when serialized as a byte slice.
    size_t byte_len();

    /// Creates the element from its byte form. Panics if the slice is not appropriately sized.
    Element(char *bytes);

    fn copy_to_slice(char* bytes);
};

//impl<
//        E: Element,
//        A: Algorithm<E>,
//        BaseTreeArity: Unsigned,
//        SubTreeArity: Unsigned,
//        TopTreeArity: Unsigned,
//    >
//    MerkleTree<E, A, LevelCacheStore<E, std::fs::File>, BaseTreeArity, SubTreeArity, TopTreeArity>
//{
//    /// Given a pathbuf, instantiate an ExternalReader and set it for the LevelCacheStore.
//    pub fn set_external_reader_path(&mut self, path: &PathBuf) -> Result<()> {
//        ensure!(self.data.store_mut().is_some(), "store data required");
//
//        self.data
//            .store_mut()
//            .unwrap()
//            .set_external_reader(ExternalReader::new_from_path(path)?)
//    }
//
//    /// Given a set of StoreConfig's (i.e on-disk references to
//    /// levelcache stores) and replica config info, instantiate each
//    /// tree and return a compound merkle tree with them.  The
//    /// ordering of the trees is significant, as trees are leaf
//    /// indexed / addressable in the same sequence that they are
//    /// provided here.
//    #[allow(clippy::type_complexity)]
//    pub fn from_store_configs_and_replica(
//        leafs: usize,
//        configs: &[StoreConfig],
//        replica_config: &ReplicaConfig,
//    ) -> Result<
//        MerkleTree<
//            E,
//            A,
//            LevelCacheStore<E, std::fs::File>,
//            BaseTreeArity,
//            SubTreeArity,
//            TopTreeArity,
//        >,
//    > {
//        let branches = BaseTreeArity::to_usize();
//        let mut trees = Vec::with_capacity(configs.len());
//        ensure!(
//            configs.len() == replica_config.offsets.len(),
//            "Config and Replica offset lists lengths are invalid"
//        );
//        for (i, config) in configs.iter().enumerate() {
//            let data = LevelCacheStore::new_from_disk_with_reader(
//                get_merkle_tree_len(leafs, branches)?,
//                branches,
//                config,
//                ExternalReader::new_from_config(replica_config, i)?,
//            )
//            .context("failed to instantiate levelcache store")?;
//            trees.push(
//                MerkleTree::<E, A, LevelCacheStore<_, _>, BaseTreeArity>::from_data_store(
//                    data, leafs,
//                )?,
//            );
//        }
//
//        Self::from_trees(trees)
//    }
//
//    /// Given a set of StoreConfig's (i.e on-disk references to
//    /// levelcache stores) and replica config info, instantiate each
//    /// sub tree and return a compound merkle tree with them.  The
//    /// ordering of the trees is significant, as trees are leaf
//    /// indexed / addressable in the same sequence that they are
//    /// provided here.
//    #[allow(clippy::type_complexity)]
//    pub fn from_sub_tree_store_configs_and_replica(
//        leafs: usize,
//        configs: &[StoreConfig],
//        replica_config: &ReplicaConfig,
//    ) -> Result<
//        MerkleTree<
//            E,
//            A,
//            LevelCacheStore<E, std::fs::File>,
//            BaseTreeArity,
//            SubTreeArity,
//            TopTreeArity,
//        >,
//    > {
//        ensure!(
//            configs.len() == replica_config.offsets.len(),
//            "Config and Replica offset lists lengths are invalid"
//        );
//
//        let sub_tree_count = TopTreeArity::to_usize();
//
//        let mut start = 0;
//        let mut end = configs.len() / sub_tree_count;
//        let mut trees = Vec::with_capacity(sub_tree_count);
//
//        for _ in 0..sub_tree_count {
//            let replica_sub_config = ReplicaConfig {
//                path: replica_config.path.clone(),
//                offsets: replica_config.offsets[start..end].to_vec(),
//            };
//            trees.push(MerkleTree::<
//                E,
//                A,
//                LevelCacheStore<_, _>,
//                BaseTreeArity,
//                SubTreeArity,
//            >::from_store_configs_and_replica(
//                leafs,
//                &configs[start..end],
//                &replica_sub_config,
//            )?);
//            start = end;
//            end += configs.len() / sub_tree_count;
//        }
//
//        Self::from_sub_trees(trees)
//    }
//}

impl<
        E: Element,
        A: Algorithm<E>,
        S: Store<E>,
        BaseTreeArity: Unsigned,
        SubTreeArity: Unsigned,
        TopTreeArity: Unsigned,
    > MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>
{
    /// Creates new merkle from a sequence of hashes.
    pub fn new<I: IntoIterator<Item = E>>(
        data: I,
    ) -> Result<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>> {
        Self::try_from_iter(data.into_iter().map(Ok))
    }

    /// Creates new merkle from a sequence of hashes.
    pub fn new_with_config<I: IntoIterator<Item = E>>(
        data: I,
        config: StoreConfig,
    ) -> Result<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>> {
        Self::try_from_iter_with_config(data.into_iter().map(Ok), config)
    }

    /// Creates new merkle tree from a list of hashable objects.
    pub fn from_data<O: Hashable<A>, I: IntoIterator<Item = O>>(
        data: I,
    ) -> Result<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>> {
        let mut a = A::default();
        Self::try_from_iter(data.into_iter().map(|x| {
            a.reset();
            x.hash(&mut a);
            Ok(a.hash())
        }))
    }

    /// Creates new merkle tree from a list of hashable objects.
    pub fn from_data_with_config<O: Hashable<A>, I: IntoIterator<Item = O>>(
        data: I,
        config: StoreConfig,
    ) -> Result<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>> {
        let mut a = A::default();
        Self::try_from_iter_with_config(
            data.into_iter().map(|x| {
                a.reset();
                x.hash(&mut a);
                Ok(a.hash())
            }),
            config,
        )
    }

    /// Creates new merkle tree from an already allocated 'Store'
    /// (used with 'Store::new_from_disk').  The specified 'size' is
    /// the number of base data leafs in the MT.
    pub fn from_data_store(data: S,
        leafs: usize,
    ) -> Result<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>> {
        ensure!(
            SubTreeArity::to_usize() == 0,
            "Data stores must not have sub-tree layers"
        );
        ensure!(
            TopTreeArity::to_usize() == 0,
            "Data stores must not have a top layer"
        );

        let branches = BaseTreeArity::to_usize();
        ensure!(next_pow2(leafs) == leafs, "leafs MUST be a power of 2");
        ensure!(
            next_pow2(branches) == branches,
            "branches MUST be a power of 2"
        );

        let tree_len = get_merkle_tree_len(leafs, branches)?;
        ensure!(tree_len == data.len(), "Inconsistent tree data");

        ensure!(
            is_merkle_tree_size_valid(leafs, branches),
            "MerkleTree size is invalid given the arity"
        );

        let row_count = get_merkle_tree_row_count(leafs, branches);
        let root = data.read_at(data.len() - 1)?;

        Ok(MerkleTree {
            data: Data::BaseTree(data),
            leafs,
            len: tree_len,
            row_count,
            root,
            _a: PhantomData,
            _e: PhantomData,
            _bta: PhantomData,
            _sta: PhantomData,
            _tta: PhantomData,
        })
    }

    /// Represent a fully constructed merkle tree from a provided slice.
    pub fn from_tree_slice(
        data: &[u8],
        leafs: usize,
    ) -> Result<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>> {
        ensure!(
            SubTreeArity::to_usize() == 0,
            "Data slice must not have sub-tree layers"
        );
        ensure!(
            TopTreeArity::to_usize() == 0,
            "Data slice must not have a top layer"
        );

        let branches = BaseTreeArity::to_usize();
        let row_count = get_merkle_tree_row_count(leafs, branches);
        let tree_len = get_merkle_tree_len(leafs, branches)?;
        ensure!(
            tree_len == data.len() / E::byte_len(),
            "Inconsistent tree data"
        );

        ensure!(
            is_merkle_tree_size_valid(leafs, branches),
            "MerkleTree size is invalid given the arity"
        );

        let store = S::new_from_slice(tree_len, &data).context("failed to create data store")?;
        let root = store.read_at(data.len() - 1)?;

        Ok(MerkleTree {
            data: Data::BaseTree(store),
            leafs,
            len: tree_len,
            row_count,
            root,
            _a: PhantomData,
            _e: PhantomData,
            _bta: PhantomData,
            _sta: PhantomData,
            _tta: PhantomData,
        })
    }

    /// Represent a fully constructed merkle tree from a provided slice.
    pub fn from_tree_slice_with_config(
        data: &[u8],
        leafs: usize,
        config: StoreConfig,
    ) -> Result<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>> {
        ensure!(
            SubTreeArity::to_usize() == 0,
            "Data slice must not have sub-tree layers"
        );
        ensure!(
            TopTreeArity::to_usize() == 0,
            "Data slice must not have a top layer"
        );

        let branches = BaseTreeArity::to_usize();
        let row_count = get_merkle_tree_row_count(leafs, branches);
        let tree_len = get_merkle_tree_len(leafs, branches)?;
        ensure!(
            tree_len == data.len() / E::byte_len(),
            "Inconsistent tree data"
        );

        ensure!(
            is_merkle_tree_size_valid(leafs, branches),
            "MerkleTree size is invalid given the arity"
        );

        let store = S::new_from_slice_with_config(tree_len, branches, &data, config)
            .context("failed to create data store")?;
        let root = store.read_at(data.len() - 1)?;

        Ok(MerkleTree {
            data: Data::BaseTree(store),
            leafs,
            len: tree_len,
            row_count,
            root,
            _a: PhantomData,
            _e: PhantomData,
            _bta: PhantomData,
            _sta: PhantomData,
            _tta: PhantomData,
        })
    }

    /// Creates new compound merkle tree from a vector of merkle
    /// trees.  The ordering of the trees is significant, as trees are
    /// leaf indexed / addressable in the same sequence that they are
    /// provided here.
    pub fn from_trees(
        trees: Vec<MerkleTree<E, A, S, BaseTreeArity>>,
    ) -> Result<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>> {
        ensure!(
            SubTreeArity::to_usize() > 0,
            "Cannot use from_trees if not constructing a structure with sub-trees"
        );
        ensure!(
            trees
                .iter()
                .all(|ref mt| mt.row_count() == trees[0].row_count()),
            "All passed in trees must have the same row_count"
        );
        ensure!(
            trees.iter().all(|ref mt| mt.len() == trees[0].len()),
            "All passed in trees must have the same length"
        );

        let sub_tree_layer_nodes = SubTreeArity::to_usize();
        ensure!(
            trees.len() == sub_tree_layer_nodes,
            "Length of trees MUST equal the number of sub tree layer nodes"
        );

        // If we are building a compound tree with no sub-trees,
        // all properties revert to the single tree properties.
        let (leafs, len, row_count, root) = if sub_tree_layer_nodes == 0 {
            (
                trees[0].leafs(),
                trees[0].len(),
                trees[0].row_count(),
                trees[0].root(),
            )
        } else {
            // Total number of leafs in the compound tree is the combined leafs total of all subtrees.
            let leafs = trees.iter().fold(0, |leafs, mt| leafs + mt.leafs());
            // Total length of the compound tree is the combined length of all subtrees plus the root.
            let len = trees.iter().fold(0, |len, mt| len + mt.len()) + 1;
            // Total row_count of the compound tree is the row_count of any of the sub-trees to top-layer plus root.
            let row_count = trees[0].row_count() + 1;
            // Calculate the compound root by hashing the top layer roots together.
            let roots: Vec<E> = trees.iter().map(|x| x.root()).collect();
            let root = A::default().multi_node(&roots, 1);

            (leafs, len, row_count, root)
        };

        Ok(MerkleTree {
            data: Data::SubTree(trees),
            leafs,
            len,
            row_count,
            root,
            _a: PhantomData,
            _e: PhantomData,
            _bta: PhantomData,
            _sta: PhantomData,
            _tta: PhantomData,
        })
    }

    /// Creates new top layer merkle tree from a vector of merkle
    /// trees with sub-trees.  The ordering of the trees is
    /// significant, as trees are leaf indexed / addressable in the
    /// same sequence that they are provided here.
    pub fn from_sub_trees(
        trees: Vec<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity>>,
    ) -> Result<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>> {
        ensure!(
            TopTreeArity::to_usize() > 0,
            "Cannot use from_sub_trees if not constructing a structure with sub-trees"
        );
        ensure!(
            trees
                .iter()
                .all(|ref mt| mt.row_count() == trees[0].row_count()),
            "All passed in trees must have the same row_count"
        );
        ensure!(
            trees.iter().all(|ref mt| mt.len() == trees[0].len()),
            "All passed in trees must have the same length"
        );

        let top_layer_nodes = TopTreeArity::to_usize();
        ensure!(
            trees.len() == top_layer_nodes,
            "Length of trees MUST equal the number of top layer nodes"
        );

        // If we are building a compound tree with no sub-trees,
        // all properties revert to the single tree properties.
        let (leafs, len, row_count, root) = {
            // Total number of leafs in the compound tree is the combined leafs total of all subtrees.
            let leafs = trees.iter().fold(0, |leafs, mt| leafs + mt.leafs());
            // Total length of the compound tree is the combined length of all subtrees plus the root.
            let len = trees.iter().fold(0, |len, mt| len + mt.len()) + 1;
            // Total row_count of the compound tree is the row_count of any of the sub-trees to top-layer plus root.
            let row_count = trees[0].row_count() + 1;
            // Calculate the compound root by hashing the top layer roots together.
            let roots: Vec<E> = trees.iter().map(|x| x.root()).collect();
            let root = A::default().multi_node(&roots, 1);

            (leafs, len, row_count, root)
        };

        Ok(MerkleTree {
            data: Data::TopTree(trees),
            leafs,
            len,
            row_count,
            root,
            _a: PhantomData,
            _e: PhantomData,
            _bta: PhantomData,
            _sta: PhantomData,
            _tta: PhantomData,
        })
    }

    /// Creates new top layer merkle tree from a vector of merkle
    /// trees by first constructing the appropriate sub-trees.  The
    /// ordering of the trees is significant, as trees are leaf
    /// indexed / addressable in the same sequence that they are
    /// provided here.
    pub fn from_sub_trees_as_trees(
        mut trees: Vec<MerkleTree<E, A, S, BaseTreeArity>>,
    ) -> Result<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>> {
        ensure!(
            TopTreeArity::to_usize() > 0,
            "Cannot use from_sub_trees if not constructing a structure with sub-trees"
        );
        ensure!(
            trees
                .iter()
                .all(|ref mt| mt.row_count() == trees[0].row_count()),
            "All passed in trees must have the same row_count"
        );
        ensure!(
            trees.iter().all(|ref mt| mt.len() == trees[0].len()),
            "All passed in trees must have the same length"
        );

        let sub_tree_count = TopTreeArity::to_usize();
        let top_layer_nodes = sub_tree_count * SubTreeArity::to_usize();
        ensure!(
            trees.len() == top_layer_nodes,
            "Length of trees MUST equal the number of top layer nodes"
        );

        // Group the trees appropriately into sub-tree ready vectors.
        let mut grouped_trees = Vec::with_capacity(sub_tree_count);
        for _ in (0..sub_tree_count).step_by(trees.len() / sub_tree_count) {
            grouped_trees.push(trees.split_off(trees.len() / sub_tree_count));
        }
        grouped_trees.insert(0, trees);

        let mut sub_trees: Vec<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity>> =
            Vec::with_capacity(sub_tree_count);
        for group in grouped_trees {
            sub_trees.push(MerkleTree::from_trees(group)?);
        }

        let (leafs, len, row_count, root) = {
            // Total number of leafs in the compound tree is the combined leafs total of all subtrees.
            let leafs = sub_trees.iter().fold(0, |leafs, mt| leafs + mt.leafs());
            // Total length of the compound tree is the combined length of all subtrees plus the root.
            let len = sub_trees.iter().fold(0, |len, mt| len + mt.len()) + 1;
            // Total row_count of the compound tree is the row_count of any of the sub-trees to top-layer plus root.
            let row_count = sub_trees[0].row_count() + 1;
            // Calculate the compound root by hashing the top layer roots together.
            let roots: Vec<E> = sub_trees.iter().map(|x| x.root()).collect();
            let root = A::default().multi_node(&roots, 1);

            (leafs, len, row_count, root)
        };

        Ok(MerkleTree {
            data: Data::TopTree(sub_trees),
            leafs,
            len,
            row_count,
            root,
            _a: PhantomData,
            _e: PhantomData,
            _bta: PhantomData,
            _sta: PhantomData,
            _tta: PhantomData,
        })
    }

    /// Create a compound merkle tree given already constructed merkle
    /// trees contained as a slices. The ordering of the trees is
    /// significant, as trees are leaf indexed / addressable in the
    /// same sequence that they are provided here.
    pub fn from_slices(
        tree_data: &[&[u8]],
        leafs: usize,
    ) -> Result<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity>> {
        let mut trees = Vec::with_capacity(tree_data.len());
        for data in tree_data {
            trees.push(MerkleTree::<E, A, S, BaseTreeArity>::from_tree_slice(
                data, leafs,
            )?);
        }

        MerkleTree::from_trees(trees)
    }

    /// Create a compound merkle tree given already constructed merkle
    /// trees contained as a slices, along with configs for
    /// persistence.  The ordering of the trees is significant, as
    /// trees are leaf indexed / addressable in the same sequence that
    /// they are provided here.
    pub fn from_slices_with_configs(
        tree_data: &[&[u8]],
        leafs: usize,
        configs: &[StoreConfig],
    ) -> Result<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>> {
        let mut trees = Vec::with_capacity(tree_data.len());
        for i in 0..tree_data.len() {
            trees.push(
                MerkleTree::<E, A, S, BaseTreeArity>::from_tree_slice_with_config(
                    tree_data[i],
                    leafs,
                    configs[i].clone(),
                )?,
            );
        }

        MerkleTree::from_trees(trees)
    }

    /// Given a set of Stores (i.e. backing to MTs), instantiate each
    /// tree and return a compound merkle tree with them.  The
    /// ordering of the stores is significant, as trees are leaf
    /// indexed / addressable in the same sequence that they are
    /// provided here.
    pub fn from_stores(
        leafs: usize,
        stores: Vec<S>,
    ) -> Result<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>> {
        let mut trees = Vec::with_capacity(stores.len());
        for store in stores {
            trees.push(MerkleTree::<E, A, S, BaseTreeArity>::from_data_store(
                store, leafs,
            )?);
        }

        MerkleTree::from_trees(trees)
    }

    /// Given a set of StoreConfig's (i.e on-disk references to disk
    /// stores), instantiate each tree and return a compound merkle
    /// tree with them.  The ordering of the trees is significant, as
    /// trees are leaf indexed / addressable in the same sequence that
    /// they are provided here.
    pub fn from_store_configs(
        leafs: usize,
        configs: &[StoreConfig],
    ) -> Result<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>> {
        let branches = BaseTreeArity::to_usize();
        let mut trees = Vec::with_capacity(configs.len());
        for config in configs {
            let data = S::new_with_config(
                get_merkle_tree_len(leafs, branches)?,
                branches,
                config.clone(),
            )
            .context("failed to create data store")?;
            trees.push(MerkleTree::<E, A, S, BaseTreeArity>::from_data_store(
                data, leafs,
            )?);
        }

        MerkleTree::from_trees(trees)
    }

    /// Given a set of StoreConfig's (i.e on-disk references to dis
    /// stores), instantiate each sub tree and return a compound
    /// merkle tree with them.  The ordering of the trees is
    /// significant, as trees are leaf indexed / addressable in the
    /// same sequence that they are provided here.
    #[allow(clippy::type_complexity)]
    pub fn from_sub_tree_store_configs(
        leafs: usize,
        configs: &[StoreConfig],
    ) -> Result<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>> {
        let tree_count = TopTreeArity::to_usize();

        let mut start = 0;
        let mut end = configs.len() / tree_count;

        let mut trees = Vec::with_capacity(tree_count);
        for _ in 0..tree_count {
            trees.push(
                MerkleTree::<E, A, S, BaseTreeArity, SubTreeArity>::from_store_configs(
                    leafs,
                    &configs[start..end],
                )?,
            );
            start = end;
            end += configs.len() / tree_count;
        }

        Self::from_sub_trees(trees)
    }

    #[inline]
    fn build_partial_tree(
        mut data: VecStore<E>,
        leafs: usize,
        row_count: usize,
    ) -> Result<MerkleTree<E, A, VecStore<E>, BaseTreeArity>> {
        let root = VecStore::build::<A, BaseTreeArity>(&mut data, leafs, row_count, None)?;
        let branches = BaseTreeArity::to_usize();

        let tree_len = get_merkle_tree_len(leafs, branches)?;
        ensure!(tree_len == Store::len(&data), "Inconsistent tree data");

        ensure!(
            is_merkle_tree_size_valid(leafs, branches),
            "MerkleTree size is invalid given the arity"
        );

        Ok(MerkleTree {
            data: Data::BaseTree(data),
            leafs,
            len: tree_len,
            row_count,
            root,
            _a: PhantomData,
            _e: PhantomData,
            _bta: PhantomData,
            _sta: PhantomData,
            _tta: PhantomData,
        })
    }

    /// Generate merkle sub tree inclusion proof for leaf `i` for
    /// either the top layer or the sub-tree layer, specified by the
    /// top_layer flag
    #[inline]
    fn gen_sub_tree_proof(
        &self,
        i: usize,
        top_layer: bool,
        arity: usize,
    ) -> Result<Proof<E, BaseTreeArity>> {
        ensure!(arity != 0, "Invalid sub-tree arity");

        // Locate the sub-tree the leaf is contained in.
        let tree_index = i / (self.leafs / arity);

        // Generate the sub tree proof at this tree level.
        let sub_tree_proof = if top_layer {
            ensure!(self.data.sub_trees().is_some(), "sub trees required");
            let sub_trees = self.data.sub_trees().unwrap();
            ensure!(arity == sub_trees.len(), "Top layer tree shape mis-match");

            let tree = &sub_trees[tree_index];
            let leaf_index = i % tree.leafs();

            tree.gen_proof(leaf_index)
        } else {
            ensure!(self.data.base_trees().is_some(), "base trees required");
            let base_trees = self.data.base_trees().unwrap();
            ensure!(arity == base_trees.len(), "Sub tree layer shape mis-match");

            let tree = &base_trees[tree_index];
            let leaf_index = i % tree.leafs();

            tree.gen_proof(leaf_index)
        }?;

        // Construct the top layer proof.  'lemma' length is
        // top_layer_nodes - 1 + root == top_layer_nodes
        let mut path: Vec<usize> = Vec::with_capacity(1); // path - 1
        let mut lemma: Vec<E> = Vec::with_capacity(arity);
        for i in 0..arity {
            if i != tree_index {
                lemma.push(if top_layer {
                    ensure!(self.data.sub_trees().is_some(), "sub trees required");
                    let sub_trees = self.data.sub_trees().unwrap();

                    sub_trees[i].root()
                } else {
                    ensure!(self.data.base_trees().is_some(), "base trees required");
                    let base_trees = self.data.base_trees().unwrap();

                    base_trees[i].root()
                });
            }
        }

        lemma.push(self.root());
        path.push(tree_index);

        Proof::new::<TopTreeArity, SubTreeArity>(Some(Box::new(sub_tree_proof)), lemma, path)
    }

    /// Generate merkle tree inclusion proof for leaf `i`
    #[inline]
    pub fn gen_proof(&self, i: usize) -> Result<Proof<E, BaseTreeArity>> {
        match &self.data {
            Data::TopTree(_) => self.gen_sub_tree_proof(i, true, TopTreeArity::to_usize()),
            Data::SubTree(_) => self.gen_sub_tree_proof(i, false, SubTreeArity::to_usize()),
            Data::BaseTree(_) => {
                ensure!(
                    i < self.leafs,
                    "{} is out of bounds (max: {})",
                    i,
                    self.leafs
                ); // i in [0 .. self.leafs)

                let mut base = 0;
                let mut j = i;

                // level 1 width
                let mut width = self.leafs;
                let branches = BaseTreeArity::to_usize();
                ensure!(width == next_pow2(width), "Must be a power of 2 tree");
                ensure!(
                    branches == next_pow2(branches),
                    "branches must be a power of 2"
                );
                let shift = log2_pow2(branches);

                let mut lemma: Vec<E> =
                    Vec::with_capacity(get_merkle_proof_lemma_len(self.row_count, branches));
                let mut path: Vec<usize> = Vec::with_capacity(self.row_count - 1); // path - 1

                // item is first
                ensure!(
                    SubTreeArity::to_usize() == 0,
                    "Data slice must not have sub-tree layers"
                );
                ensure!(
                    TopTreeArity::to_usize() == 0,
                    "Data slice must not have a top layer"
                );

                lemma.push(self.read_at(j)?);
                while base + 1 < self.len() {
                    let hash_index = (j / branches) * branches;
                    for k in hash_index..hash_index + branches {
                        if k != j {
                            lemma.push(self.read_at(base + k)?)
                        }
                    }

                    path.push(j % branches); // path_index

                    base += width;
                    width >>= shift; // width /= branches;
                    j >>= shift; // j /= branches;
                }

                // root is final
                lemma.push(self.root());

                // Sanity check: if the `MerkleTree` lost its integrity and `data` doesn't match the
                // expected values for `leafs` and `row_count` this can get ugly.
                ensure!(
                    lemma.len() == get_merkle_proof_lemma_len(self.row_count, branches),
                    "Invalid proof lemma length"
                );
                ensure!(
                    path.len() == self.row_count - 1,
                    "Invalid proof path length"
                );

                Proof::new::<U0, U0>(None, lemma, path)
            }
        }
    }

    /// Generate merkle sub-tree inclusion proof for leaf `i` using
    /// partial trees built from cached data if needed at that layer.
    fn gen_cached_top_tree_proof<Arity: Unsigned>(
        &self,
        i: usize,
        rows_to_discard: Option<usize>,
    ) -> Result<Proof<E, BaseTreeArity>> {
        ensure!(Arity::to_usize() != 0, "Invalid top-tree arity");
        ensure!(
            i < self.leafs,
            "{} is out of bounds (max: {})",
            i,
            self.leafs
        ); // i in [0 .. self.leafs)

        // Locate the sub-tree the leaf is contained in.
        ensure!(self.data.sub_trees().is_some(), "sub trees required");
        let trees = &self.data.sub_trees().unwrap();
        let tree_index = i / (self.leafs / Arity::to_usize());
        let tree = &trees[tree_index];
        let tree_leafs = tree.leafs();

        // Get the leaf index within the sub-tree.
        let leaf_index = i % tree_leafs;

        // Generate the proof that will validate to the provided
        // sub-tree root (note the branching factor of B).
        let sub_tree_proof = tree.gen_cached_proof(leaf_index, rows_to_discard)?;

        // Construct the top layer proof.  'lemma' length is
        // top_layer_nodes - 1 + root == top_layer_nodes
        let mut path: Vec<usize> = Vec::with_capacity(1); // path - 1
        let mut lemma: Vec<E> = Vec::with_capacity(Arity::to_usize());
        for i in 0..Arity::to_usize() {
            if i != tree_index {
                lemma.push(trees[i].root())
            }
        }

        lemma.push(self.root());
        path.push(tree_index);

        // Generate the final compound tree proof which is composed of
        // a sub-tree proof of branching factor B and a top-level
        // proof with a branching factor of SubTreeArity.
        Proof::new::<TopTreeArity, SubTreeArity>(Some(Box::new(sub_tree_proof)), lemma, path)
    }

    /// Generate merkle sub-tree inclusion proof for leaf `i` using
    /// partial trees built from cached data if needed at that layer.
    fn gen_cached_sub_tree_proof<Arity: Unsigned>(
        &self,
        i: usize,
        rows_to_discard: Option<usize>,
    ) -> Result<Proof<E, BaseTreeArity>> {
        ensure!(Arity::to_usize() != 0, "Invalid sub-tree arity");
        ensure!(
            i < self.leafs,
            "{} is out of bounds (max: {})",
            i,
            self.leafs
        ); // i in [0 .. self.leafs)

        // Locate the sub-tree the leaf is contained in.
        ensure!(self.data.base_trees().is_some(), "base trees required");
        let trees = &self.data.base_trees().unwrap();
        let tree_index = i / (self.leafs / Arity::to_usize());
        let tree = &trees[tree_index];
        let tree_leafs = tree.leafs();

        // Get the leaf index within the sub-tree.
        let leaf_index = i % tree_leafs;

        // Generate the proof that will validate to the provided
        // sub-tree root (note the branching factor of B).
        let sub_tree_proof = tree.gen_cached_proof(leaf_index, rows_to_discard)?;

        // Construct the top layer proof.  'lemma' length is
        // top_layer_nodes - 1 + root == top_layer_nodes
        let mut path: Vec<usize> = Vec::with_capacity(1); // path - 1
        let mut lemma: Vec<E> = Vec::with_capacity(Arity::to_usize());
        for i in 0..Arity::to_usize() {
            if i != tree_index {
                lemma.push(trees[i].root())
            }
        }

        lemma.push(self.root());
        path.push(tree_index);

        // Generate the final compound tree proof which is composed of
        // a sub-tree proof of branching factor B and a top-level
        // proof with a branching factor of SubTreeArity.
        Proof::new::<TopTreeArity, SubTreeArity>(Some(Box::new(sub_tree_proof)), lemma, path)
    }

    /// Generate merkle tree inclusion proof for leaf `i` by first
    /// building a partial tree (returned) along with the proof.
    /// 'rows_to_discard' is an option that will be used if set (even
    /// if it may cause an error), otherwise a reasonable default is
    /// chosen.
    ///
    /// Return value is a Result tuple of the proof and the partial
    /// tree that was constructed.
    #[allow(clippy::type_complexity)]
    pub fn gen_cached_proof(
        &self,
        i: usize,
        rows_to_discard: Option<usize>,
    ) -> Result<Proof<E, BaseTreeArity>> {
        match &self.data {
            Data::TopTree(_) => self.gen_cached_top_tree_proof::<TopTreeArity>(i, rows_to_discard),
            Data::SubTree(_) => self.gen_cached_sub_tree_proof::<SubTreeArity>(i, rows_to_discard),
            Data::BaseTree(_) => {
                ensure!(
                    i < self.leafs,
                    "{} is out of bounds (max: {})",
                    i,
                    self.leafs
                ); // i in [0 .. self.leafs]

                // For partial tree building, the data layer width must be a
                // power of 2.
                ensure!(
                    self.leafs == next_pow2(self.leafs),
                    "The size of the data layer must be a power of 2"
                );

                let branches = BaseTreeArity::to_usize();
                let total_size = get_merkle_tree_len(self.leafs, branches)?;
                // If rows to discard is specified and we *know* it's a value that will cause an error
                // (i.e. there are not enough rows to discard, we use a sane default instead).  This
                // primarily affects tests because it only affects 'small' trees, entirely outside the
                // scope of any 'production' tree width.
                let rows_to_discard = if let Some(rows) = rows_to_discard {
                    std::cmp::min(
                        rows,
                        StoreConfig::default_rows_to_discard(self.leafs, branches),
                    )
                } else {
                    StoreConfig::default_rows_to_discard(self.leafs, branches)
                };
                let cache_size = get_merkle_tree_cache_size(self.leafs, branches, rows_to_discard)?;
                ensure!(
                    cache_size < total_size,
                    "Generate a partial proof with all data available?"
                );

                let cached_leafs = get_merkle_tree_leafs(cache_size, branches)?;
                ensure!(
                    cached_leafs == next_pow2(cached_leafs),
                    "The size of the cached leafs must be a power of 2"
                );

                let cache_row_count = get_merkle_tree_row_count(cached_leafs, branches);
                let partial_row_count = self.row_count - cache_row_count + 1;

                // Calculate the subset of the base layer data width that we
                // need in order to build the partial tree required to build
                // the proof (termed 'segment_width'), given the data
                // configuration specified by 'rows_to_discard'.
                let segment_width = self.leafs / cached_leafs;
                let segment_start = (i / segment_width) * segment_width;
                let segment_end = segment_start + segment_width;

                debug!("leafs {}, branches {}, total size {}, total row_count {}, cache_size {}, rows_to_discard {}, \
                        partial_row_count {}, cached_leafs {}, segment_width {}, segment range {}-{} for {}",
                       self.leafs, branches, total_size, self.row_count, cache_size, rows_to_discard, partial_row_count,
                       cached_leafs, segment_width, segment_start, segment_end, i);

                // Copy the proper segment of the base data into memory and
                // initialize a VecStore to back a new, smaller MT.
                let mut data_copy = vec![0; segment_width * E::byte_len()];
                ensure!(self.data.store().is_some(), "store data required");

                self.data.store().unwrap().read_range_into(
                    segment_start,
                    segment_end,
                    &mut data_copy,
                )?;
                let partial_store = VecStore::new_from_slice(segment_width, &data_copy)?;
                ensure!(
                    Store::len(&partial_store) == segment_width,
                    "Inconsistent store length"
                );

                // Before building the tree, resize the store where the tree
                // will be built to allow space for the newly constructed layers.
                data_copy.resize(
                    get_merkle_tree_len(segment_width, branches)? * E::byte_len(),
                    0,
                );

                // Build the optimally small tree.
                let partial_tree: MerkleTree<E, A, VecStore<E>, BaseTreeArity> =
                    Self::build_partial_tree(partial_store, segment_width, partial_row_count)?;
                ensure!(
                    partial_row_count == partial_tree.row_count(),
                    "Inconsistent partial tree row_count"
                );

                // Generate entire proof with access to the base data, the
                // cached data, and the partial tree.
                let proof = self.gen_proof_with_partial_tree(i, rows_to_discard, &partial_tree)?;

                debug!(
                    "generated partial_tree of row_count {} and len {} with {} branches for proof at {}",
                    partial_tree.row_count,
                    partial_tree.len(),
                    branches,
                    i
                );

                Ok(proof)
            }
        }
    }

    /// Generate merkle tree inclusion proof for leaf `i` given a
    /// partial tree for lookups where data is otherwise unavailable.
    fn gen_proof_with_partial_tree(
        &self,
        i: usize,
        rows_to_discard: usize,
        partial_tree: &MerkleTree<E, A, VecStore<E>, BaseTreeArity>,
    ) -> Result<Proof<E, BaseTreeArity>> {
        ensure!(
            i < self.leafs,
            "{} is out of bounds (max: {})",
            i,
            self.leafs
        ); // i in [0 .. self.leafs)

        // For partial tree building, the data layer width must be a
        // power of 2.
        let mut width = self.leafs;
        let branches = BaseTreeArity::to_usize();
        ensure!(width == next_pow2(width), "Must be a power of 2 tree");
        ensure!(
            branches == next_pow2(branches),
            "branches must be a power of 2"
        );

        let data_width = width;
        let total_size = get_merkle_tree_len(data_width, branches)?;
        let cache_size = get_merkle_tree_cache_size(self.leafs, branches, rows_to_discard)?;
        let cache_index_start = total_size - cache_size;
        let cached_leafs = get_merkle_tree_leafs(cache_size, branches)?;
        ensure!(
            cached_leafs == next_pow2(cached_leafs),
            "Cached leafs size must be a power of 2"
        );

        // Calculate the subset of the data layer width that we need
        // in order to build the partial tree required to build the
        // proof (termed 'segment_width').
        let mut segment_width = width / cached_leafs;
        let segment_start = (i / segment_width) * segment_width;

        // shift is the amount that we need to decrease the width by
        // the number of branches at each level up the main merkle
        // tree.
        let shift = log2_pow2(branches);

        // segment_shift is the amount that we need to offset the
        // partial tree offsets to keep them within the space of the
        // partial tree as we move up it.
        //
        // segment_shift is conceptually (segment_start >>
        // (current_row_count * shift)), which tracks an offset in the
        // main merkle tree that we apply to the partial tree.
        let mut segment_shift = segment_start;

        // 'j' is used to track the challenged nodes required for the
        // proof up the tree.
        let mut j = i;

        // 'base' is used to track the data index of the layer that
        // we're currently processing in the main merkle tree that's
        // represented by the store.
        let mut base = 0;

        // 'partial_base' is used to track the data index of the layer
        // that we're currently processing in the partial tree.
        let mut partial_base = 0;

        let mut lemma: Vec<E> =
            Vec::with_capacity(get_merkle_proof_lemma_len(self.row_count, branches));
        let mut path: Vec<usize> = Vec::with_capacity(self.row_count - 1); // path - 1

        ensure!(
            SubTreeArity::to_usize() == 0,
            "Data slice must not have sub-tree layers"
        );
        ensure!(
            TopTreeArity::to_usize() == 0,
            "Data slice must not have a top layer"
        );

        lemma.push(self.read_at(j)?);
        while base + 1 < self.len() {
            let hash_index = (j / branches) * branches;
            for k in hash_index..hash_index + branches {
                if k != j {
                    let read_index = base + k;
                    lemma.push(
                        if read_index < data_width || read_index >= cache_index_start {
                            self.read_at(base + k)?
                        } else {
                            let read_index = partial_base + k - segment_shift;
                            partial_tree.read_at(read_index)?
                        },
                    );
                }
            }

            path.push(j % branches); // path_index

            base += width;
            width >>= shift; // width /= branches

            partial_base += segment_width;
            segment_width >>= shift; // segment_width /= branches

            segment_shift >>= shift; // segment_shift /= branches

            j >>= shift; // j /= branches;
        }

        // root is final
        lemma.push(self.root());

        // Sanity check: if the `MerkleTree` lost its integrity and `data` doesn't match the
        // expected values for `leafs` and `row_count` this can get ugly.
        ensure!(
            lemma.len() == get_merkle_proof_lemma_len(self.row_count, branches),
            "Invalid proof lemma length"
        );
        ensure!(
            path.len() == self.row_count - 1,
            "Invalid proof path length"
        );

        Proof::new::<U0, U0>(None, lemma, path)
    }

    /// Returns merkle root
    #[inline]
    pub fn root(&self) -> E {
        self.root.clone()
    }

    /// Returns number of elements in the tree.
    #[inline]
    pub fn len(&self) -> usize {
        match &self.data {
            Data::TopTree(_) => self.len,
            Data::SubTree(_) => self.len,
            Data::BaseTree(store) => store.len(),
        }
    }

    /// Truncates the data for later access via LevelCacheStore
    /// interface.
    #[inline]
    pub fn compact(&mut self, config: StoreConfig, store_version: u32) -> Result<bool> {
        let branches = BaseTreeArity::to_usize();
        ensure!(self.data.store_mut().is_some(), "store data required");

        self.data
            .store_mut()
            .unwrap()
            .compact(branches, config, store_version)
    }

    #[inline]
    pub fn reinit(&mut self) -> Result<()> {
        ensure!(self.data.store_mut().is_some(), "store data required");

        self.data.store_mut().unwrap().reinit()
    }

    /// Removes the backing store for this merkle tree.
    #[inline]
    pub fn delete(&self, config: StoreConfig) -> Result<()> {
        S::delete(config)
    }

    /// Returns `true` if the store contains no elements.
    #[inline]
    pub fn is_empty(&self) -> bool {
        match &self.data {
            Data::TopTree(_) => true,
            Data::SubTree(_) => true,
            Data::BaseTree(store) => store.is_empty(),
        }
    }

    /// Returns row_count of the tree
    #[inline]
    pub fn row_count(&self) -> usize {
        self.row_count
    }

    /// Returns original number of elements the tree was built upon.
    #[inline]
    pub fn leafs(&self) -> usize {
        self.leafs
    }

    /// Returns data reference
    #[inline]
    pub fn data(&self) -> Option<&S> {
        match &self.data {
            Data::TopTree(_) => None,
            Data::SubTree(_) => None,
            Data::BaseTree(store) => Some(store),
        }
    }

    /// Returns merkle leaf at index i
    #[inline]
    pub fn read_at(&self, i: usize) -> Result<E> {
        match &self.data {
            Data::TopTree(sub_trees) => {
                // Locate the top-layer tree the sub-tree leaf is contained in.
                ensure!(
                    TopTreeArity::to_usize() == sub_trees.len(),
                    "Top layer tree shape mis-match"
                );
                let tree_index = i / (self.leafs / TopTreeArity::to_usize());
                let tree = &sub_trees[tree_index];
                let tree_leafs = tree.leafs();

                // Get the leaf index within the sub-tree.
                let leaf_index = i % tree_leafs;

                tree.read_at(leaf_index)
            }
            Data::SubTree(base_trees) => {
                // Locate the sub-tree layer tree the base leaf is contained in.
                ensure!(
                    SubTreeArity::to_usize() == base_trees.len(),
                    "Sub-tree shape mis-match"
                );
                let tree_index = i / (self.leafs / SubTreeArity::to_usize());
                let tree = &base_trees[tree_index];
                let tree_leafs = tree.leafs();

                // Get the leaf index within the sub-tree.
                let leaf_index = i % tree_leafs;

                tree.read_at(leaf_index)
            }
            Data::BaseTree(data) => {
                // Read from the base layer tree data.
                data.read_at(i)
            }
        }
    }

    pub fn read_range(&self, start: usize, end: usize) -> Result<Vec<E>> {
        ensure!(start < end, "start must be less than end");
        ensure!(self.data.store().is_some(), "store data required");

        self.data.store().unwrap().read_range(start..end)
    }

    pub fn read_range_into(&self, start: usize, end: usize, buf: &mut [u8]) -> Result<()> {
        ensure!(start < end, "start must be less than end");
        ensure!(self.data.store().is_some(), "store data required");

        self.data.store().unwrap().read_range_into(start, end, buf)
    }

    /// Reads into a pre-allocated slice (for optimization purposes).
    pub fn read_into(&self, pos: usize, buf: &mut [u8]) -> Result<()> {
        ensure!(self.data.store().is_some(), "store data required");

        self.data.store().unwrap().read_into(pos, buf)
    }

    /// Build the tree given a slice of all leafs, in bytes form.
    pub fn from_byte_slice_with_config(leafs: &[u8], config: StoreConfig) -> Result<Self> {
        ensure!(
            leafs.len() % E::byte_len() == 0,
            "{} ist not a multiple of {}",
            leafs.len(),
            E::byte_len()
        );

        let leafs_count = leafs.len() / E::byte_len();
        let branches = BaseTreeArity::to_usize();
        ensure!(leafs_count > 1, "not enough leaves");
        ensure!(
            next_pow2(leafs_count) == leafs_count,
            "size MUST be a power of 2"
        );
        ensure!(
            next_pow2(branches) == branches,
            "branches MUST be a power of 2"
        );

        let size = get_merkle_tree_len(leafs_count, branches)?;
        let row_count = get_merkle_tree_row_count(leafs_count, branches);

        let mut data = S::new_from_slice_with_config(size, branches, leafs, config.clone())
            .context("failed to create data store")?;
        let root = S::build::<A, BaseTreeArity>(&mut data, leafs_count, row_count, Some(config))?;

        Ok(MerkleTree {
            data: Data::BaseTree(data),
            leafs: leafs_count,
            len: size,
            row_count,
            root,
            _a: PhantomData,
            _e: PhantomData,
            _bta: PhantomData,
            _sta: PhantomData,
            _tta: PhantomData,
        })
    }

    /// Build the tree given a slice of all leafs, in bytes form.
    pub fn from_byte_slice(leafs: &[u8]) -> Result<Self> {
        ensure!(
            leafs.len() % E::byte_len() == 0,
            "{} is not a multiple of {}",
            leafs.len(),
            E::byte_len()
        );

        let leafs_count = leafs.len() / E::byte_len();
        let branches = BaseTreeArity::to_usize();
        ensure!(leafs_count > 1, "not enough leaves");
        ensure!(
            next_pow2(leafs_count) == leafs_count,
            "size MUST be a power of 2"
        );
        ensure!(
            next_pow2(branches) == branches,
            "branches MUST be a power of 2"
        );

        let size = get_merkle_tree_len(leafs_count, branches)?;
        let row_count = get_merkle_tree_row_count(leafs_count, branches);

        let mut data = S::new_from_slice(size, leafs).context("failed to create data store")?;

        let root = S::build::<A, BaseTreeArity>(&mut data, leafs_count, row_count, None)?;

        Ok(MerkleTree {
            data: Data::BaseTree(data),
            leafs: leafs_count,
            len: size,
            row_count,
            root,
            _a: PhantomData,
            _e: PhantomData,
            _bta: PhantomData,
            _sta: PhantomData,
            _tta: PhantomData,
        })
    }
}

pub trait FromIndexedParallelIterator<E, BaseTreeArity>: Sized
where
    E: Send,
{
    fn from_par_iter<I>(par_iter: I) -> Result<Self>
    where
        BaseTreeArity: Unsigned,
        I: IntoParallelIterator<Item = E>,
        I::Iter: IndexedParallelIterator;

    fn from_par_iter_with_config<I>(par_iter: I, config: StoreConfig) -> Result<Self>
    where
        I: IntoParallelIterator<Item = E>,
        I::Iter: IndexedParallelIterator,
        BaseTreeArity: Unsigned;
}

impl<
        E: Element,
        A: Algorithm<E>,
        S: Store<E>,
        BaseTreeArity: Unsigned,
        SubTreeArity: Unsigned,
        TopTreeArity: Unsigned,
    > FromIndexedParallelIterator<E, BaseTreeArity>
    for MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>
{
    /// Creates new merkle tree from an iterator over hashable objects.
    fn from_par_iter<I>(into: I) -> Result<Self>
    where
        I: IntoParallelIterator<Item = E>,
        I::Iter: IndexedParallelIterator,
    {
        let iter = into.into_par_iter();

        let leafs = iter.opt_len().expect("must be sized");
        let branches = BaseTreeArity::to_usize();
        ensure!(leafs > 1, "not enough leaves");
        ensure!(next_pow2(leafs) == leafs, "size MUST be a power of 2");
        ensure!(
            next_pow2(branches) == branches,
            "branches MUST be a power of 2"
        );

        let size = get_merkle_tree_len(leafs, branches)?;
        let row_count = get_merkle_tree_row_count(leafs, branches);

        let mut data = S::new(size).expect("failed to create data store");

        populate_data_par::<E, A, S, BaseTreeArity, _>(&mut data, iter)?;
        let root = S::build::<A, BaseTreeArity>(&mut data, leafs, row_count, None)?;

        Ok(MerkleTree {
            data: Data::BaseTree(data),
            leafs,
            len: size,
            row_count,
            root,
            _a: PhantomData,
            _e: PhantomData,
            _bta: PhantomData,
            _sta: PhantomData,
            _tta: PhantomData,
        })
    }

    /// Creates new merkle tree from an iterator over hashable objects.
    fn from_par_iter_with_config<I>(into: I, config: StoreConfig) -> Result<Self>
    where
        BaseTreeArity: Unsigned,
        I: IntoParallelIterator<Item = E>,
        I::Iter: IndexedParallelIterator,
    {
        let iter = into.into_par_iter();

        let leafs = iter.opt_len().expect("must be sized");
        let branches = BaseTreeArity::to_usize();
        ensure!(leafs > 1, "not enough leaves");
        ensure!(next_pow2(leafs) == leafs, "size MUST be a power of 2");
        ensure!(
            next_pow2(branches) == branches,
            "branches MUST be a power of 2"
        );

        let size = get_merkle_tree_len(leafs, branches)?;
        let row_count = get_merkle_tree_row_count(leafs, branches);

        let mut data = S::new_with_config(size, branches, config.clone())
            .context("failed to create data store")?;

        // If the data store was loaded from disk, we know we have
        // access to the full merkle tree.
        if data.loaded_from_disk() {
            let root = data.last().context("failed to read root")?;

            return Ok(MerkleTree {
                data: Data::BaseTree(data),
                leafs,
                len: size,
                row_count,
                root,
                _a: PhantomData,
                _e: PhantomData,
                _bta: PhantomData,
                _sta: PhantomData,
                _tta: PhantomData,
            });
        }

        populate_data_par::<E, A, S, BaseTreeArity, _>(&mut data, iter)?;
        let root = S::build::<A, BaseTreeArity>(&mut data, leafs, row_count, Some(config))?;

        Ok(MerkleTree {
            data: Data::BaseTree(data),
            leafs,
            len: size,
            row_count,
            root,
            _a: PhantomData,
            _e: PhantomData,
            _bta: PhantomData,
            _sta: PhantomData,
            _tta: PhantomData,
        })
    }
}

impl<
        E: Element,
        A: Algorithm<E>,
        S: Store<E>,
        BaseTreeArity: Unsigned,
        SubTreeArity: Unsigned,
        TopTreeArity: Unsigned,
    > MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>
{
    /// Attempts to create a new merkle tree using hashable objects yielded by
    /// the provided iterator. This method returns the first error yielded by
    /// the iterator, if the iterator yielded an error.
    pub fn try_from_iter<I: IntoIterator<Item = Result<E>>>(into: I) -> Result<Self> {
        let iter = into.into_iter();

        let (_, n) = iter.size_hint();
        let leafs = n.ok_or_else(|| anyhow!("could not get size hint from iterator"))?;
        let branches = BaseTreeArity::to_usize();
        ensure!(leafs > 1, "not enough leaves");
        ensure!(next_pow2(leafs) == leafs, "size MUST be a power of 2");
        ensure!(
            next_pow2(branches) == branches,
            "branches MUST be a power of 2"
        );

        let size = get_merkle_tree_len(leafs, branches)?;
        let row_count = get_merkle_tree_row_count(leafs, branches);

        let mut data = S::new(size).context("failed to create data store")?;
        populate_data::<E, A, S, BaseTreeArity, I>(&mut data, iter)
            .context("failed to populate data")?;
        let root = S::build::<A, BaseTreeArity>(&mut data, leafs, row_count, None)?;

        Ok(MerkleTree {
            data: Data::BaseTree(data),
            leafs,
            len: size,
            row_count,
            root,
            _a: PhantomData,
            _e: PhantomData,
            _bta: PhantomData,
            _sta: PhantomData,
            _tta: PhantomData,
        })
    }

    /// Attempts to create a new merkle tree using hashable objects yielded by
    /// the provided iterator and store config. This method returns the first
    /// error yielded by the iterator, if the iterator yielded an error.
    pub fn try_from_iter_with_config<I: IntoIterator<Item = Result<E>>>(
        into: I,
        config: StoreConfig,
    ) -> Result<Self> {
        let iter = into.into_iter();

        let (_, n) = iter.size_hint();
        let leafs = n.ok_or_else(|| anyhow!("could not get size hint from iterator"))?;
        let branches = BaseTreeArity::to_usize();
        ensure!(leafs > 1, "not enough leaves");
        ensure!(next_pow2(leafs) == leafs, "size MUST be a power of 2");
        ensure!(
            next_pow2(branches) == branches,
            "branches MUST be a power of 2"
        );

        let size = get_merkle_tree_len(leafs, branches)?;
        let row_count = get_merkle_tree_row_count(leafs, branches);

        let mut data = S::new_with_config(size, branches, config.clone())
            .context("failed to create data store")?;

        // If the data store was loaded from disk, we know we have
        // access to the full merkle tree.
        if data.loaded_from_disk() {
            let root = data.last().context("failed to read root")?;

            return Ok(MerkleTree {
                data: Data::BaseTree(data),
                leafs,
                len: size,
                row_count,
                root,
                _a: PhantomData,
                _e: PhantomData,
                _bta: PhantomData,
                _sta: PhantomData,
                _tta: PhantomData,
            });
        }

        populate_data::<E, A, S, BaseTreeArity, I>(&mut data, iter)
            .expect("failed to populate data");
        let root = S::build::<A, BaseTreeArity>(&mut data, leafs, row_count, Some(config))?;

        Ok(MerkleTree {
            data: Data::BaseTree(data),
            leafs,
            len: size,
            row_count,
            root,
            _a: PhantomData,
            _e: PhantomData,
            _bta: PhantomData,
            _sta: PhantomData,
            _tta: PhantomData,
        })
    }
}

impl Element for [u8; 32] {
    fn byte_len() -> usize {
        32
    }

    fn from_slice(bytes: &[u8]) -> Self {
        if bytes.len() != 32 {
            panic!("invalid length {}, expected 32", bytes.len());
        }
        *array_ref!(bytes, 0, 32)
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(self);
    }
}

// Tree length calculation given the number of leafs in the tree and the branches.
size_t get_merkle_tree_len(size_t leafs, size_t branches) {
    assert(leafs >= branches, "leaf and branch mis-match");
    assert(branches == next_pow2(branches), "branches must be a power of 2");

    // Optimization
    if (branches == 2) {
        assert(leafs == next_pow2(leafs), "leafs must be a power of 2");
        return 2 * leafs - 1;
    }

    size_t len = leafs;
    size_t cur = leafs;
    size_t shift = log2_pow2(branches);
    if (shift == 0) {
        return len;
    }

    while (cur > 0) {
        cur >>= shift; // cur /= branches
        assert(cur < leafs, "invalid input provided");
        len += cur;
    }

    return len;
}

// Tree length calculation given the number of leafs in the tree, the
// rows_to_discard, and the branches.
size_t get_merkle_tree_cache_size(size_t leafs, size_t branches, size_t rows_to_discard) {
    size_t shift = log2_pow2(branches);
    size_t len = get_merkle_tree_len(leafs, branches)?;
    size_t row_count = get_merkle_tree_row_count(leafs, branches);

    assert(row_count - 1 > rows_to_discard,  "Cannot discard all rows except for the base");

    // 'row_count - 1' means that we start discarding rows above the base
    // layer, which is included in the current row_count.
    size_t cache_base = row_count - 1 - rows_to_discard;

    size_t cache_size = len;
    size_t cur_leafs = leafs;

    while (row_count > cache_base) {
        cache_size -= cur_leafs;
        cur_leafs >>= shift; // cur /= branches
        row_count -= 1;
    }

    return cache_size;
}

bool is_merkle_tree_size_valid(size_t leafs, size_t branches) {
    if (branches == 0 || leafs != next_pow2(leafs) || branches != next_pow2(branches)) {
        return false;
    }

    size_t mut cur = leafs;
    size_t shift = log2_pow2(branches);
    while (cur != 1) {
        cur >>= shift; // cur /= branches
        if (cur > leafs || cur == 0) {
            return false;
        }
    }

    return true;
}

// Row_Count calculation given the number of leafs in the tree and the branches.
size_t get_merkle_tree_row_count(size_t leafs, size_t branches) {
    // Optimization
    if (branches == 2) {
        retrun (leafs * branches).trailing_zeros();
    } else {
        return (branches as f64 * leafs as f64).log(branches as f64);
    }
}

// Given a tree of 'row_count' with the specified number of 'branches',
// calculate the length of hashes required for the proof.
size_t get_merkle_proof_lemma_len(size_t row_count, size_t branches) {
    return 2 + ((branches - 1) * (row_count - 1));
}

// This method returns the number of 'leafs' given a merkle tree
// length of 'len', where leafs must be a power of 2, respecting the
// number of branches.
size_t get_merkle_tree_leafs(size_t len, size_t branches) {
    assert(branches == next_pow2(branches), "branches must be a power of 2");
    size_t leafs = 0;
    // Optimization:
    if (branches == 2) {
        leafs = (len >> 1) + 1
    } else {
        size_t leafs = 1;
        size_t cur = len;
        size_t shift = log2_pow2(branches);
        while (cur != 1) {
            leafs <<= shift; // leafs *= branches
            assert(cur > leafs, "Invalid tree length provided for the specified arity");
            cur -= leafs;
            assert(cur < len, "Invalid tree length provided for the specified arity");
        }
    };

    assert(leafs == next_pow2(leafs), "Invalid tree length provided for the specified arity");
    return leafs;
}

/// returns next highest power of two from a given number if it is not
/// already a power of two.
size_t next_pow2(size_t n) {
    return pow(2, ceil(log(n)/log(2)));
}

/// find power of 2 of a number which is power of 2
size_t log2_pow2(size_t n) {
    return next_pow2(n);
}

pub fn populate_data<
    E: Element,
    A: Algorithm<E>,
    S: Store<E>,
    BaseTreeArity: Unsigned,
    I: IntoIterator<Item = Result<E>>,
>(
    data: &mut S,
    iter: <I as std::iter::IntoIterator>::IntoIter,
) -> Result<()> {
    if !data.is_empty() {
        return Ok(());
    }

    let mut buf = Vec::with_capacity(BUILD_DATA_BLOCK_SIZE * E::byte_len());

    let mut a = A::default();
    for item in iter {
        // short circuit the tree-populating routine if the iterator yields an
        // error
        let item = item?;

        a.reset();
        buf.extend(a.leaf(item).as_ref());
        if buf.len() >= BUILD_DATA_BLOCK_SIZE * E::byte_len() {
            let data_len = data.len();
            // FIXME: Integrate into `len()` call into `copy_from_slice`
            // once we update to `stable` 1.36.
            data.copy_from_slice(&buf, data_len)?;
            buf.clear();
        }
    }
    let data_len = data.len();
    data.copy_from_slice(&buf, data_len)?;
    data.sync()?;
}

void populate_data_par<E, A, S, BaseTreeArity, I>(data: &mut S, iter: I)
where
    E: Element,
    A: Algorithm<E>,
    S: Store<E>,
    BaseTreeArity: Unsigned,
    I: ParallelIterator<Item = E> + IndexedParallelIterator,
{
    if !data.is_empty() {
        return Ok(());
    }

    let store = Arc::new(RwLock::new(data));

    iter.chunks(BUILD_DATA_BLOCK_SIZE)
        .enumerate()
        .try_for_each(|(index, chunk)| {
            let mut a = A::default();
            let mut buf = Vec::with_capacity(BUILD_DATA_BLOCK_SIZE * E::byte_len());

            for item in chunk {
                a.reset();
                buf.extend(a.leaf(item).as_ref());
            }
            store
                .write()
                .unwrap()
                .copy_from_slice(&buf[..], BUILD_DATA_BLOCK_SIZE * index)
        })?;

    store.write().unwrap().sync()?;
    Ok(())
}
        }    // namespace merkletree
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_DISK_HPP
