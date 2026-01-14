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
        curr_layer = self.leaves[:]
        layers = []
        
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
        freq_heap = [(count, idx) for idx, count in self.access_freq.items()]
        heapq.heapify(freq_heap)
        reordered = [self.leaves[idx] for count, idx in freq_heap]
        self.leaves = reordered
        self.build()
    
    def get_proof(self, idx):
        path = []
        pos = idx
        
        for level in self.tree:
            sibling_pos = pos ^ 1
            if sibling_pos < len(level):
                path.append(level[sibling_pos])
            pos //= 2
        
        return path
    
    def verify(self, leaf, path, root):
        h = leaf
        for sib in path:
            h = hashlib.sha256((h + sib).encode()).hexdigest()
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
    
    root = mt.tree[-1][0] if mt.tree else None
    print(f"Merkle root: {root}")
    
    proof_path = mt.get_proof(2)
    print(f"Proof for leaf 2: {proof_path}")
    
    leaf_h = hashlib.sha256("tx3".encode()).hexdigest()
    is_valid = mt.verify(leaf_h, proof_path, root)
    print(f"Proof valid: {is_valid}")
    
    print("\n✓ Demo complete!")

