# adaptive_merkle_tree.py
"""
Adaptive Merkle Tree Implementation
Dynamic restructuring of Merkle tree based on usage frequency for optimized verification speed and smaller proofs.
"""

import hashlib
import heapq
from collections import defaultdict

class AdaptiveMerkleTree:
    def __init__(self):
        self.leaves = []
        self.tree = []
        self.access_map = defaultdict(int)
    
    def add_leaf(self, leaf_hash, do_hash=True):
        if do_hash:
            leaf_hash = hashlib.sha256(leaf_hash.encode()).hexdigest()
        self.leaves.append(leaf_hash)
    
    def make_tree(self):
        nodes = self.leaves[:]
        tree = []
        while len(nodes) > 1:
            layer = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i+1] if i+1 < len(nodes) else left
                combined = left + right
                parent_hash = hashlib.sha256(combined.encode()).hexdigest()
                layer.append(parent_hash)
            tree.append(layer)
            nodes = layer
        self.tree = tree
    
    def optimize(self):
        # Dynamic restructuring example (Huffman-like)
        # Count access frequency from self.access_map
        heap = [(freq, idx) for idx, freq in self.access_map.items()]
        heapq.heapify(heap)
        new_order = [self.leaves[idx] for freq, idx in heap]
        self.leaves = new_order
        self.make_tree()
    
    def get_proof(self, leaf_index):
        # Return proof path (simplified)
        proof = []
        index = leaf_index
        for layer in self.tree:
            sibling_index = index ^ 1
            if sibling_index < len(layer):
                proof.append(layer[sibling_index])
            index //= 2
        return proof
    
    def verify_proof(self, leaf_hash, proof, root):
        computed_hash = leaf_hash
        for sibling_hash in proof:
            # Combine and hash
            combined = computed_hash + sibling_hash
            computed_hash = hashlib.sha256(combined.encode()).hexdigest()
        return computed_hash == root


# Example usage
if __name__ == "__main__":
    print("="*70)
    print("ADAPTIVE MERKLE TREE DEMONSTRATION")
    print("="*70)
    
    tree = AdaptiveMerkleTree()
    
    # Add leaves
    leaves = ["tx1", "tx2", "tx3", "tx4", "tx5"]
    for leaf in leaves:
        tree.add_leaf(leaf)
    
    # Build tree
    tree.make_tree()
    
    print("Merkle root:", tree.tree[-1][0] if tree.tree else None)
    
    # Get proof for leaf 2
    proof = tree.get_proof(2)
    print("Proof for leaf 2:", proof)
    
    # Verify proof
    leaf_hash = hashlib.sha256("tx3".encode()).hexdigest()
    root = tree.tree[-1][0]
    valid = tree.verify_proof(leaf_hash, proof, root)
    print("Proof valid:", valid)
    
    print("\n✓ Adaptive Merkle Tree demo complete!")
