import hashlib
import heapq
from collections import defaultdict

class AdaptiveMerkleTree:
    def __init__(self):
        self.leaves = []
        self.tree = []
        self.access_freq = defaultdict(int)

    def add_leaf(self, data, hashed=True):
        if hashed:
            data = hashlib.sha256(data.encode()).hexdigest()
        self.leaves.append(data)

    def build(self):
        if not self.leaves:
            self.tree = []
            return

        curr_layer = self.leaves[:]
        layers = [curr_layer]

        while len(curr_layer) > 1:
            next_layer = []
            i = 0
            while i < len(curr_layer):
                left = curr_layer[i]
                right = curr_layer[i+1] if i+1 < len(curr_layer) else left
                parent = hashlib.sha256((left + right).encode()).hexdigest()
                next_layer.append(parent)
                i += 2
            layers.append(next_layer)
            curr_layer = next_layer

        self.tree = layers

    def optimize(self):
        # Sort by descending access frequency so most-used leaves are near root
        freq_heap = [(-count, idx) for idx, count in self.access_freq.items()]
        heapq.heapify(freq_heap)
        reordered = [self.leaves[idx] for neg_count, idx in freq_heap]
        self.leaves = reordered
        self.build()

    def get_proof(self, idx):
        """Returns list of (sibling_hash, is_current_left) tuples for verification."""
        if not self.tree:
            return []

        path = []
        pos = idx

        # tree[0] is leaves; tree[1..n-1] are internal levels; tree[-1] is root
        for level_idx in range(len(self.tree) - 1):
            level = self.tree[level_idx]
            sibling_pos = pos ^ 1
            is_left = (pos % 2 == 0)
            if sibling_pos < len(level):
                path.append((level[sibling_pos], is_left))
            pos //= 2

        return path

    def get_root(self):
        if not self.tree:
            return None
        return self.tree[-1][0] if self.tree[-1] else None

    def verify(self, leaf, path, root):
        """path must be list of (sibling_hash, is_current_left) tuples from get_proof()."""
        h = leaf
        for sib, is_left in path:
            if is_left:
                h = hashlib.sha256((h + sib).encode()).hexdigest()
            else:
                h = hashlib.sha256((sib + h).encode()).hexdigest()
        return h == root


if __name__ == "__main__":
    print("=" * 70)
    print("ADAPTIVE MERKLE TREE DEMONSTRATION")
    print("=" * 70)
    
    mt = AdaptiveMerkleTree()
    
    txs = ["tx1", "tx2", "tx3", "tx4", "tx5"]
    for tx in txs:
        mt.add_leaf(tx)
    
    mt.build()

    root = mt.get_root()
    print(f"Merkle root: {root}")
    
    proof_path = mt.get_proof(2)
    print(f"Proof for leaf 2: {proof_path}")
    
    leaf_h = hashlib.sha256("tx3".encode()).hexdigest()
    is_valid = mt.verify(leaf_h, proof_path, root)
    print(f"Proof valid: {is_valid}")
    
    print("\n✓ Demo complete!")

