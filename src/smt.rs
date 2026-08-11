//! Compact Sparse Merkle Tree over an opaque node store.
//!
//! This is the storage-side half of the tree that `pivx-name-prover` verifies
//! on-chain. Moving traversal here removes the socket round trips per domain
//! operation that a client-side implementation requires, and makes proof/root
//! consistency structural rather than a matter of client discipline.
//!
//! ## One definition of the hash rules
//!
//! Leaf hashing, node hashing, path derivation and the verification algorithm are
//! NOT defined here — they come from the `pins-core` crate, which the prover's guest
//! circuit uses too. That is what makes "the daemon and the prover agree" a
//! compile-time property instead of a claim maintained by hand. This module owns
//! only what is genuinely storage-side: node keys, the descent and the writes.
//!
//! ## Layout
//!
//! The tree is compact: a leaf sits at the shallowest depth at which it is the only
//! key in its subtree, so a proof carries ~log2(N) siblings rather than a fixed 128.
//! An empty subtree is the single constant [`EMPTY`] at every height — there is no
//! default-hash ladder. See `pivx-name-prover/docs/compact-smt.md`, which is the
//! specification this implements.
//!
//! A domain's path is the first 128 bits of `sha256(domain)`, most-significant-bit
//! first within each byte; path bit `0` selects the left child. That bit order looks
//! different from the circuit's, but consumes the path identically; the
//! `proof_verifies_under_the_provers_traversal` test pins it against `pins-core`
//! directly rather than against a transcription.
//!
//! ## Storage
//!
//! Two independent key spaces, distinguished by their first byte:
//!
//! * **Nodes** — `[depth: u8][ceil(depth/8) bytes of packed path bits]`,
//!   most-significant-bit first, trailing bits zero. The depth prefix keeps `"0"` and
//!   `"00"` distinct, which packing alone would not. Depth is `0..=128`, so the first
//!   byte never reaches [`RECORD_PREFIX`].
//! * **Records** — `[RECORD_PREFIX][domain]`, holding the raw record payload the
//!   client sent.
//!
//! Records are keyed by *domain*, not by node position, and that is deliberate: a
//! split moves a leaf deeper, so a position-keyed record would have to move with it.
//! Keyed by domain they are written once and never touched again by structural
//! changes.
//!
//! Records must be stored at all because a `Terminal::Blocked` proof carries the
//! blocking domain's **full preimage** — see spec §5.3, which explains why supplying
//! only its key is exploitable.

pub use pins_core::{EMPTY, MAX_DEPTH as DEPTH};

/// Leaf hash for a domain record. Re-exported from `pins-core`: clients send record
/// fields rather than a precomputed hash, so field order, endianness and the
/// domain-separation tag have exactly one definition, shared with the prover.
pub use pins_core::hash_leaf;

/// Internal node hash. Re-exported from `pins-core` — see [`hash_leaf`].
pub use pins_core::hash_node as hash_pair;

pub use pins_core::{Hash, LeafRecord, Proof, Terminal};

use pins_core::{first_divergence, key_bit, key_of};

/// Largest encoded node key: one depth byte plus the packed path.
pub const MAX_KEY_LEN: usize = 1 + DEPTH / 8;

/// First byte of a record key. Node keys begin with a depth in `0..=128`, so this
/// value can never collide with one.
pub const RECORD_PREFIX: u8 = 0xFF;

/// A domain's tree path, most-significant-bit first.
pub type PathBits = [bool; DEPTH];

/// Storage key for a domain's record.
pub fn record_key(domain: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + domain.len());
    key.push(RECORD_PREFIX);
    key.extend_from_slice(domain.as_bytes());
    key
}

/// What a stored node is.
///
/// The kind must be recorded, not inferred: in a compact tree a leaf and an internal
/// node can both sit at any depth, and the descent has to know which one it has
/// reached. A leaf also carries its domain, which is what lets a proof name the
/// blocking record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Internal(Hash),
    Leaf { hash: Hash, domain: String },
}

impl Node {
    pub fn hash(&self) -> Hash {
        match self {
            Node::Internal(h) => *h,
            Node::Leaf { hash, .. } => *hash,
        }
    }
}

/// An encoded node key.
///
/// Fixed-size and `Copy`, so building the keys an operation needs costs no heap
/// allocation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NodeKey {
    buf: [u8; MAX_KEY_LEN],
    len: usize,
}

impl NodeKey {
    /// Key of the node at `bits[..depth]`.
    pub fn at(bits: &PathBits, depth: usize) -> Self {
        Self::build(bits, depth, false)
    }

    /// Key of the root, which has no path.
    pub fn root() -> Self {
        Self::build(&[false; DEPTH], 0, false)
    }

    /// Key of the sibling of the node at `bits[..depth]` — the same prefix with
    /// the final bit flipped.
    pub fn sibling_at(bits: &PathBits, depth: usize) -> Self {
        debug_assert!(depth >= 1, "the root has no sibling");
        Self::build(bits, depth, true)
    }

    fn build(bits: &PathBits, depth: usize, flip_last: bool) -> Self {
        debug_assert!(depth <= DEPTH);
        let mut buf = [0u8; MAX_KEY_LEN];
        buf[0] = depth as u8;
        for (i, &bit) in bits.iter().take(depth).enumerate() {
            let bit = if flip_last && i + 1 == depth { !bit } else { bit };
            if bit {
                buf[1 + i / 8] |= 0x80 >> (i % 8);
            }
        }
        Self {
            buf,
            len: 1 + depth.div_ceil(8),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl AsRef<[u8]> for NodeKey {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl std::fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeKey({})", hex(self.as_slice()))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Storage backing the tree. Implemented over RocksDB in the daemon and over a
/// plain map in tests.
pub trait NodeStore {
    type Error;

    fn get_node(&self, key: &NodeKey) -> Result<Option<Node>, Self::Error>;

    /// Reads many node hashes in one operation, preserving order. Missing nodes are
    /// [`EMPTY`]. Used for siblings, which are only ever needed as hashes.
    fn get_hashes(&self, keys: &[NodeKey]) -> Result<Vec<Hash>, Self::Error>;

    fn put_node(&mut self, key: &NodeKey, node: &Node) -> Result<(), Self::Error>;

    fn delete_node(&mut self, key: &NodeKey) -> Result<(), Self::Error>;

    /// The raw record payload a client sent for `domain`.
    fn get_record(&self, domain: &str) -> Result<Option<Vec<u8>>, Self::Error>;

    fn put_record(&mut self, domain: &str, payload: &[u8]) -> Result<(), Self::Error>;
}

/// Where a key's path ends, and how deep.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Landing {
    /// Nothing stored here — the key is absent.
    Vacant,
    /// The key's own leaf.
    Occupied,
    /// A different domain's leaf.
    Blocked { domain: String, hash: Hash },
}

/// The compact Sparse Merkle Tree.
///
/// Stateless: unlike the dense tree this replaces, there are no precomputed default
/// hashes to hold, because an empty subtree is [`EMPTY`] at every height.
#[derive(Debug, Clone, Copy, Default)]
pub struct Smt;

impl Smt {
    pub fn new() -> Self {
        Self
    }

    /// Current root, or the empty-tree root if nothing has been written.
    pub fn root<S: NodeStore>(&self, store: &S) -> Result<Hash, S::Error> {
        Ok(store
            .get_node(&NodeKey::root())?
            .map(|n| n.hash())
            .unwrap_or(EMPTY))
    }

    /// The stored leaf for a domain, if it is present.
    pub fn leaf<S: NodeStore>(&self, store: &S, domain: &str) -> Result<Option<Hash>, S::Error> {
        let bits = path_bits(domain);
        let (depth, landing) = self.descend(store, &bits, domain)?;
        Ok(match landing {
            Landing::Occupied => store.get_node(&NodeKey::at(&bits, depth))?.map(|n| n.hash()),
            _ => None,
        })
    }

    /// Walks down `bits` until the path leaves the internal structure, returning the
    /// terminal depth and what is there.
    ///
    /// Only path nodes are read here — one lookup per level, and the depth is data
    /// dependent so it cannot be known in advance. Siblings are fetched separately in
    /// a single batched read once the depth is known.
    fn descend<S: NodeStore>(
        &self,
        store: &S,
        bits: &PathBits,
        domain: &str,
    ) -> Result<(usize, Landing), S::Error> {
        let mut depth = 0usize;
        loop {
            match store.get_node(&NodeKey::at(bits, depth))? {
                None => return Ok((depth, Landing::Vacant)),
                Some(Node::Leaf { hash, domain: found }) => {
                    return Ok((
                        depth,
                        if found == domain {
                            Landing::Occupied
                        } else {
                            Landing::Blocked {
                                domain: found,
                                hash,
                            }
                        },
                    ));
                }
                Some(Node::Internal(_)) => {
                    debug_assert!(depth < DEPTH, "an internal node cannot exist at maximum depth");
                    depth += 1;
                }
            }
        }
    }

    /// The sibling hashes for a terminal at `depth`, deepest first.
    fn siblings<S: NodeStore>(
        &self,
        store: &S,
        bits: &PathBits,
        depth: usize,
    ) -> Result<Vec<Hash>, S::Error> {
        // Sibling at path length `d` is proof index `depth - d`, so iterate from the
        // terminal upward. All of them are known once `depth` is, hence one batch.
        let keys: Vec<NodeKey> = (1..=depth)
            .rev()
            .map(|d| NodeKey::sibling_at(bits, d))
            .collect();
        store.get_hashes(&keys)
    }

    /// Writes `record`'s leaf at `domain`'s position, splitting if another domain
    /// holds the slot, and rehashes the spine to the root.
    ///
    /// Returns the new root.
    pub fn update<S: NodeStore>(
        &self,
        store: &mut S,
        domain: &str,
        record_payload: &[u8],
        leaf: Hash,
    ) -> Result<Hash, S::Error> {
        let bits = path_bits(domain);
        let (depth, landing) = self.descend(store, &bits, domain)?;
        let siblings = self.siblings(store, &bits, depth)?;

        // Keyed by domain, so this survives any later split untouched.
        store.put_record(domain, record_payload)?;

        let mut node = match landing {
            // The slot is ours or free: the leaf simply goes here.
            Landing::Occupied | Landing::Vacant => {
                store.put_node(
                    &NodeKey::at(&bits, depth),
                    &Node::Leaf {
                        hash: leaf,
                        domain: domain.to_string(),
                    },
                )?;
                leaf
            }

            // Another domain holds the slot. Both leaves move down to the bit where
            // the two keys diverge, with single-child internals bridging the gap.
            Landing::Blocked {
                domain: other_domain,
                hash: other_leaf,
            } => {
                let key = key_of(domain);
                let other_key = key_of(&other_domain);
                let j = first_divergence(&key, &other_key, depth)
                    .expect("two distinct domains cannot share all 128 key bits");
                debug_assert!(j < DEPTH);

                // The blocking leaf vacates this position.
                store.delete_node(&NodeKey::at(&bits, depth))?;

                let other_bits = path_bits(&other_domain);
                store.put_node(
                    &NodeKey::at(&bits, j + 1),
                    &Node::Leaf {
                        hash: leaf,
                        domain: domain.to_string(),
                    },
                )?;
                store.put_node(
                    &NodeKey::at(&other_bits, j + 1),
                    &Node::Leaf {
                        hash: other_leaf,
                        domain: other_domain.clone(),
                    },
                )?;

                let mut node = if bits[j] {
                    hash_pair(&other_leaf, &leaf)
                } else {
                    hash_pair(&leaf, &other_leaf)
                };
                store.put_node(&NodeKey::at(&bits, j), &Node::Internal(node))?;

                // Depths j-1 down to `depth`: the keys still agree, so the other
                // child of each is empty.
                for i in (depth..j).rev() {
                    node = if bits[i] {
                        hash_pair(&EMPTY, &node)
                    } else {
                        hash_pair(&node, &EMPTY)
                    };
                    store.put_node(&NodeKey::at(&bits, i), &Node::Internal(node))?;
                }
                node
            }
        };

        // Rehash the spine from `depth` up to and including the root.
        for (idx, sibling) in siblings.iter().enumerate() {
            let parent_depth = depth - 1 - idx;
            node = if bits[parent_depth] {
                hash_pair(sibling, &node)
            } else {
                hash_pair(&node, sibling)
            };
            store.put_node(&NodeKey::at(&bits, parent_depth), &Node::Internal(node))?;
        }

        Ok(node)
    }

    /// Merkle proof for `domain`, present or absent.
    pub fn proof<S: NodeStore>(&self, store: &S, domain: &str) -> Result<Proof, S::Error> {
        let bits = path_bits(domain);
        let (depth, landing) = self.descend(store, &bits, domain)?;
        let siblings = self.siblings(store, &bits, depth)?;

        let terminal = match landing {
            Landing::Vacant => Terminal::Vacant,
            Landing::Occupied => Terminal::Occupied,
            Landing::Blocked {
                domain: other_domain,
                ..
            } => {
                let payload = store
                    .get_record(&other_domain)?
                    .expect("a leaf in the tree must have a stored record");
                let parsed = crate::protocol::parse_record(&payload)
                    .expect("a stored record payload must parse");
                Terminal::Blocked {
                    record: LeafRecord {
                        domain: parsed.domain.to_string(),
                        pubkey: parsed.pubkey,
                        target_address: parsed.target_address.to_string(),
                        price: parsed.price,
                        nonce: parsed.nonce,
                    },
                }
            }
        };

        Ok(Proof {
            depth: depth as u8,
            siblings,
            terminal,
        })
    }
}

/// The 128-bit tree path for a domain: `sha256(domain)[..16]`, MSB first.
///
/// The key itself comes from [`pins_core::key_of`]; only the unpacking into per-level
/// bits is local, because the storage layer indexes by depth while the circuit
/// consumes the same bits in the opposite nesting order.
pub fn path_bits(domain: &str) -> PathBits {
    let key = key_of(domain);
    let mut bits = [false; DEPTH];
    for (i, slot) in bits.iter_mut().enumerate() {
        *slot = key_bit(&key, i);
    }
    bits
}

// =====================================================================
// TESTS
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    pub(crate) struct MemStore {
        pub(crate) nodes: HashMap<Vec<u8>, Node>,
        pub(crate) records: HashMap<String, Vec<u8>>,
    }

    impl NodeStore for MemStore {
        type Error = std::convert::Infallible;

        fn get_node(&self, key: &NodeKey) -> Result<Option<Node>, Self::Error> {
            Ok(self.nodes.get(key.as_slice()).cloned())
        }
        fn get_hashes(&self, keys: &[NodeKey]) -> Result<Vec<Hash>, Self::Error> {
            Ok(keys
                .iter()
                .map(|k| self.nodes.get(k.as_slice()).map(|n| n.hash()).unwrap_or(EMPTY))
                .collect())
        }
        fn put_node(&mut self, key: &NodeKey, node: &Node) -> Result<(), Self::Error> {
            self.nodes.insert(key.as_slice().to_vec(), node.clone());
            Ok(())
        }
        fn delete_node(&mut self, key: &NodeKey) -> Result<(), Self::Error> {
            self.nodes.remove(key.as_slice());
            Ok(())
        }
        fn get_record(&self, domain: &str) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.records.get(domain).cloned())
        }
        fn put_record(&mut self, domain: &str, payload: &[u8]) -> Result<(), Self::Error> {
            self.records.insert(domain.to_string(), payload.to_vec());
            Ok(())
        }
    }

    pub(crate) fn make_record(domain: &str, nonce: u64) -> LeafRecord {
        LeafRecord {
            domain: domain.to_string(),
            pubkey: [7u8; 32],
            target_address: "ps1abc".to_string(),
            price: 0,
            nonce,
        }
    }

    /// Registers a domain and returns the new root.
    pub(crate) fn put(smt: &Smt, store: &mut MemStore, domain: &str, nonce: u64) -> Hash {
        let rec = make_record(domain, nonce);
        let payload = crate::protocol::encode_record(&rec);
        smt.update(store, domain, &payload, rec.leaf()).unwrap()
    }

    // ---- key encoding (unchanged from the dense tree) ----

    #[test]
    fn root_key_is_a_single_zero_byte() {
        assert_eq!(NodeKey::root().as_slice(), &[0u8]);
    }

    #[test]
    fn key_encodes_depth_and_packed_bits() {
        let mut bits = [false; DEPTH];
        bits[0] = true;
        bits[2] = true;
        assert_eq!(NodeKey::at(&bits, 1).as_slice(), &[1, 0b1000_0000]);
        assert_eq!(NodeKey::at(&bits, 3).as_slice(), &[3, 0b1010_0000]);
    }

    #[test]
    fn depth_prefix_disambiguates_equal_packings() {
        // Without the length prefix, "0", "00" and "000" all pack to 0x00.
        let bits = [false; DEPTH];
        assert_ne!(NodeKey::at(&bits, 1).as_slice(), NodeKey::at(&bits, 2).as_slice());
        assert_ne!(NodeKey::at(&bits, 2).as_slice(), NodeKey::at(&bits, 3).as_slice());
    }

    #[test]
    fn sibling_key_flips_only_the_final_bit() {
        let bits = path_bits("example.zec");
        for depth in 1..=DEPTH {
            let node = NodeKey::at(&bits, depth);
            let sib = NodeKey::sibling_at(&bits, depth);
            assert_ne!(node.as_slice(), sib.as_slice(), "depth {depth}");
            assert_eq!(node.as_slice()[0], sib.as_slice()[0], "same depth prefix");
        }
    }

    /// Node keys start with a depth in 0..=128, so they can never be mistaken for a
    /// record key. Both live in one keyspace.
    #[test]
    fn record_keys_cannot_collide_with_node_keys() {
        assert!(RECORD_PREFIX as usize > DEPTH);
        assert_eq!(record_key("alice.zec")[0], RECORD_PREFIX);
        let bits = path_bits("alice.zec");
        for depth in 0..=DEPTH {
            assert_ne!(NodeKey::at(&bits, depth).as_slice()[0], RECORD_PREFIX);
        }
    }

    // ---- path derivation ----

    #[test]
    fn path_is_msb_first_over_the_first_16_bytes() {
        let key = pins_core::key_of("example.zec");
        let bits = path_bits("example.zec");
        assert_eq!(bits.len(), 128);
        assert_eq!(bits[0], (key[0] >> 7) & 1 == 1);
        assert_eq!(bits[7], key[0] & 1 == 1);
        assert_eq!(bits[127], key[15] & 1 == 1);
    }

    // ---- structure ----

    #[test]
    fn empty_tree_root_needs_no_storage() {
        assert_eq!(Smt::new().root(&MemStore::default()).unwrap(), EMPTY);
    }

    #[test]
    fn a_lone_leaf_sits_at_the_root() {
        let smt = Smt::new();
        let mut store = MemStore::default();
        let root = put(&smt, &mut store, "alice.zec", 1);

        assert_eq!(root, make_record("alice.zec", 1).leaf());
        assert_eq!(smt.proof(&store, "alice.zec").unwrap().depth, 0);
        // One node and one record — not a 129-node spine.
        assert_eq!(store.nodes.len(), 1);
        assert_eq!(store.records.len(), 1);
    }

    #[test]
    fn update_is_idempotent_and_changes_the_root() {
        let smt = Smt::new();
        let mut store = MemStore::default();
        let before = smt.root(&store).unwrap();
        let a = put(&smt, &mut store, "alice.zec", 1);
        let b = put(&smt, &mut store, "alice.zec", 1);
        assert_ne!(a, before);
        assert_eq!(a, b);
        assert_ne!(a, put(&smt, &mut store, "alice.zec", 2), "a new nonce must move the root");
    }

    #[test]
    fn update_order_does_not_affect_the_root() {
        let smt = Smt::new();
        let mut s1 = MemStore::default();
        for d in ["alice.zec", "bob.zec", "carol.zec"] {
            put(&smt, &mut s1, d, 1);
        }
        let mut s2 = MemStore::default();
        for d in ["carol.zec", "bob.zec", "alice.zec"] {
            put(&smt, &mut s2, d, 1);
        }
        assert_eq!(smt.root(&s1).unwrap(), smt.root(&s2).unwrap());
    }

    #[test]
    fn a_split_leaves_no_stale_node_behind() {
        let smt = Smt::new();
        let mut store = MemStore::default();
        put(&smt, &mut store, "alice.zec", 1);
        let depth_before = smt.proof(&store, "alice.zec").unwrap().depth;
        put(&smt, &mut store, "bob.zec", 1);

        // alice moved deeper, and the node she vacated must be gone or replaced by
        // an internal node — never left as a stale leaf.
        let after = smt.proof(&store, "alice.zec").unwrap();
        assert!(after.depth > depth_before, "the split must push alice deeper");
        let bits = path_bits("alice.zec");
        match store.get_node(&NodeKey::at(&bits, depth_before as usize)).unwrap() {
            Some(Node::Internal(_)) | None => {}
            Some(Node::Leaf { domain, .. }) => {
                panic!("stale leaf for {domain} left at the vacated depth")
            }
        }
    }

    #[test]
    fn leaf_roundtrips_and_absent_domains_have_none() {
        let smt = Smt::new();
        let mut store = MemStore::default();
        assert_eq!(smt.leaf(&store, "alice.zec").unwrap(), None);
        put(&smt, &mut store, "alice.zec", 1);
        assert_eq!(smt.leaf(&store, "alice.zec").unwrap(), Some(make_record("alice.zec", 1).leaf()));
        assert_eq!(smt.leaf(&store, "ghost.zec").unwrap(), None);
    }

    #[test]
    fn proofs_stay_far_shorter_than_the_dense_tree() {
        let smt = Smt::new();
        let mut store = MemStore::default();
        let domains: Vec<String> = (0..120).map(|i| format!("d{i}.zec")).collect();
        for d in &domains {
            put(&smt, &mut store, d, 1);
        }
        let max = domains
            .iter()
            .map(|d| smt.proof(&store, d).unwrap().depth)
            .max()
            .unwrap();
        assert!(max < 32, "120 domains should stay well above depth 32, got {max}");
    }

    // ---- cross-implementation agreement with the prover ----

    /// The contract that matters: a proof this daemon emits must reconstruct the
    /// root under the CIRCUIT's verifier. This calls `pins-core` directly rather than
    /// a transcription, so it cannot drift.
    #[test]
    fn proof_verifies_under_the_provers_traversal() {
        let smt = Smt::new();
        let mut store = MemStore::default();
        let root = put(&smt, &mut store, "alice.zec", 1);

        let proof = smt.proof(&store, "alice.zec").unwrap();
        let leaf = make_record("alice.zec", 1).leaf();
        let (reconstructed, _) =
            pins_core::verify_and_apply("alice.zec", &proof, Some(leaf), [0xAAu8; 32]);
        assert_eq!(reconstructed, root);
    }

    #[test]
    fn proofs_verify_for_every_domain_in_a_populated_tree() {
        let smt = Smt::new();
        let mut store = MemStore::default();
        let domains: Vec<String> = (0..64).map(|i| format!("domain{i}.zec")).collect();

        let mut root = EMPTY;
        for d in &domains {
            root = put(&smt, &mut store, d, 1);
        }

        for d in &domains {
            let proof = smt.proof(&store, d).unwrap();
            assert_eq!(proof.terminal, Terminal::Occupied, "{d}");
            let (reconstructed, _) =
                pins_core::verify_and_apply(d, &proof, Some(make_record(d, 1).leaf()), [0xAAu8; 32]);
            assert_eq!(reconstructed, root, "proof for {d} failed under the circuit");
        }
    }

    /// Registration proofs must satisfy the circuit too, for both non-inclusion
    /// terminals, and the root the circuit derives must equal the one the daemon
    /// reaches by actually inserting.
    #[test]
    fn registration_proofs_agree_with_the_circuit() {
        let smt = Smt::new();
        let mut store = MemStore::default();
        let mut root = EMPTY;
        for i in 0..40 {
            root = put(&smt, &mut store, &format!("d{i}.zec"), 1);
        }

        let (mut vacant, mut blocked) = (0, 0);
        for i in 0..40 {
            let name = format!("new{i}.zec");
            let proof = smt.proof(&store, &name).unwrap();
            match proof.terminal {
                Terminal::Vacant => vacant += 1,
                Terminal::Blocked { .. } => blocked += 1,
                Terminal::Occupied => panic!("{name} should be absent"),
            }

            let rec = make_record(&name, 1);
            let (old_root, circuit_new_root) =
                pins_core::verify_and_apply(&name, &proof, None, rec.leaf());
            assert_eq!(old_root, root, "{name}: absence proof rejected by the circuit");

            root = put(&smt, &mut store, &name, 1);
            assert_eq!(
                circuit_new_root, root,
                "{name}: the circuit's new root differs from the daemon's insert"
            );
        }
        assert!(vacant > 0 && blocked > 0, "expected both terminals, got {vacant}/{blocked}");
    }

    /// A blocked proof must carry the blocking domain's real record, since the
    /// circuit rederives both its leaf hash and its key from those bytes.
    #[test]
    fn blocked_proofs_carry_the_real_blocking_record() {
        let smt = Smt::new();
        let mut store = MemStore::default();
        for i in 0..40 {
            put(&smt, &mut store, &format!("d{i}.zec"), 1);
        }

        let (name, record) = (0..200)
            .map(|i| format!("new{i}.zec"))
            .find_map(|n| match smt.proof(&store, &n).unwrap().terminal {
                Terminal::Blocked { record } => Some((n, record)),
                _ => None,
            })
            .expect("no blocked slot found");

        // The record must match what is actually stored for the blocking domain.
        assert_eq!(record, make_record(&record.domain, 1));
        assert_eq!(smt.leaf(&store, &record.domain).unwrap(), Some(record.leaf()));
        assert_ne!(record.domain, name);
    }
}

/// Emits cross-check vectors for the PHP client.
///
/// The PHP side re-implements the `SMT_PROOF` response decoding, so it needs vectors
/// covering every terminal kind to test against. This writes, for each case, the
/// exact bytes `encode_proof` puts on the wire alongside the JSON the prover's
/// `Proof` serialises to — so PHP can be checked against both ends at once rather
/// than against a hand-written expectation.
///
/// Ignored by default; run explicitly:
/// ```bash
/// PHP_VECTOR_OUT=/tmp/vectors.json cargo test -- --ignored dump_php_proof_vectors
/// ```
#[cfg(test)]
mod php_vectors {
    use super::tests::*;
    use super::*;

    /// Path of the committed vectors, resolved through CARGO_MANIFEST_DIR so it does not
    /// depend on the working directory.
    pub const COMMITTED: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/php_proof_vectors.json");

    /// The wire bytes the committed vectors describe must still be what `encode_proof`
    /// produces.
    ///
    /// This runs by default and needs no PHP, which is the point: the PHP client decodes
    /// this exact layout, so a change here is precisely the event that silently breaks it.
    /// The full loop (`php_output_deserialises`) can only run with artefacts from a PHP
    /// run, so without this the format could drift between those runs and nothing would
    /// notice until a batch failed inside the prover.
    ///
    /// If this fails because the format changed deliberately: update the PHP decoder in
    /// `RustRocksDBProxy::decodeProof`, regenerate with
    /// `PHP_VECTOR_OUT=tests/fixtures/php_proof_vectors.json cargo test -- --ignored dump_php_proof_vectors`,
    /// and re-run the PHP cross-check.
    #[test]
    fn wire_format_matches_the_committed_vectors() {
        let committed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(COMMITTED).expect("vectors are readable"))
                .expect("vectors are JSON");

        let rebuilt = build_cases();
        let committed = committed.as_array().expect("vectors are an array");
        assert_eq!(committed.len(), rebuilt.len(), "case count differs");

        for (want, got) in committed.iter().zip(&rebuilt) {
            let name = want["name"].as_str().unwrap();
            assert_eq!(name, got["name"].as_str().unwrap(), "cases out of order");
            assert_eq!(
                want["wire_hex"], got["wire_hex"],
                "{name}: encode_proof no longer produces the committed bytes"
            );
            assert_eq!(
                want["expected_proof"], got["expected_proof"],
                "{name}: the Proof serialisation changed"
            );
        }
    }

    #[test]
    #[ignore = "run explicitly to regenerate the PHP cross-check vectors"]
    fn dump_php_proof_vectors() {
        let out = std::env::var("PHP_VECTOR_OUT").unwrap_or_else(|_| COMMITTED.to_string());
        std::fs::write(&out, serde_json::to_string_pretty(&build_cases()).unwrap()).unwrap();
        eprintln!("wrote vectors to {out}");
    }

    /// The vector set, built once so the golden check and the dump cannot describe
    /// different trees.
    fn build_cases() -> Vec<serde_json::Value> {
        let smt = Smt::new();
        let mut store = MemStore::default();
        let mut cases = Vec::new();

        // depth 0, Vacant: nothing registered yet.
        cases.push(case(&smt, &store, "alice.zcash", "vacant_depth0"));

        put(&smt, &mut store, "alice.zcash", 1);
        // depth 0, Occupied: a lone leaf sits at the root.
        cases.push(case(&smt, &store, "alice.zcash", "occupied_depth0"));
        // depth 0, Blocked: any other name lands on alice's slot.
        cases.push(case(&smt, &store, "bob.zcash", "blocked_depth0"));

        for i in 0..40 {
            put(&smt, &mut store, &format!("d{i}.zcash"), 1);
        }
        // Deeper proofs, with real sibling arrays.
        cases.push(case(&smt, &store, "d0.zcash", "occupied_deep"));
        let blocked = (0..500)
            .map(|i| format!("new{i}.zcash"))
            .find(|n| matches!(smt.proof(&store, n).unwrap().terminal, Terminal::Blocked { .. }))
            .expect("no blocked slot found");
        cases.push(case(&smt, &store, &blocked, "blocked_deep"));
        let vacant = (0..500)
            .map(|i| format!("free{i}.zcash"))
            .find(|n| smt.proof(&store, n).unwrap().terminal == Terminal::Vacant)
            .expect("no vacant slot found");
        cases.push(case(&smt, &store, &vacant, "vacant_deep"));

        cases
    }

    fn case(smt: &Smt, store: &MemStore, domain: &str, name: &str) -> serde_json::Value {
        let root = smt.root(store).unwrap();
        let proof = smt.proof(store, domain).unwrap();
        serde_json::json!({
            "name": name,
            "domain": domain,
            // Exactly what the daemon writes to the socket.
            "wire_hex": hex(&crate::protocol::encode_proof(&root, &proof)),
            "root_hex": hex(&root),
            // Exactly what the prover expects to deserialise.
            "expected_proof": serde_json::to_value(&proof).unwrap(),
        })
    }
}

/// Verifies that JSON produced by the PHP client deserialises into the prover's
/// `Proof` and matches what this daemon encoded.
///
/// Closes the loop: Rust encodes the wire bytes, PHP decodes them and renders the
/// JSON the batch payload carries, and the prover's own deserialiser reads it back.
/// A disagreement anywhere in that chain fails here.
///
/// The vectors are committed, so only the PHP artefact has to be produced:
/// ```bash
/// php resources/tools/smt_proof_crosscheck.php \
///     ../pivx-name-rr-proxy/tests/fixtures/php_proof_vectors.json /tmp/php_output.json
/// PHP_OUTPUT=/tmp/php_output.json cargo test -- --ignored php_output_deserialises
/// ```
///
/// Still ignored because it needs a PHP runtime, which CI for this crate does not have.
/// `wire_format_matches_the_committed_vectors` covers the half that can run unattended —
/// it fails the moment the encoding these vectors describe stops matching reality, which
/// is the event that would otherwise break PHP silently between cross-check runs.
#[cfg(test)]
mod php_roundtrip {
    use super::*;

    #[test]
    #[ignore = "requires artefacts from a PHP cross-check run"]
    fn php_output_deserialises() {
        // Defaults to the committed vectors: the PHP side must have decoded those exact
        // bytes for the comparison to mean anything.
        let vectors_path = std::env::var("PHP_VECTORS")
            .unwrap_or_else(|_| super::php_vectors::COMMITTED.to_string());
        let vectors: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&vectors_path).unwrap()).unwrap();
        let php: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(std::env::var("PHP_OUTPUT").expect("set PHP_OUTPUT")).unwrap(),
        )
        .unwrap();

        let expected = vectors.as_array().unwrap();
        let actual = php.as_array().unwrap();
        assert_eq!(expected.len(), actual.len(), "case count differs");

        for (want, got) in expected.iter().zip(actual) {
            let name = want["name"].as_str().unwrap();
            assert_eq!(name, got["name"].as_str().unwrap(), "cases out of order");

            // The prover's own deserialiser must accept PHP's JSON.
            let parsed: Proof = serde_json::from_value(got["proof"].clone())
                .unwrap_or_else(|e| panic!("{name}: PHP JSON is not a valid Proof: {e}"));

            let original: Proof = serde_json::from_value(want["expected_proof"].clone()).unwrap();
            assert_eq!(parsed, original, "{name}: PHP round-trip changed the proof");
        }

        eprintln!("{} PHP-produced proofs deserialised and matched", actual.len());
    }
}
