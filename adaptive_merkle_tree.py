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
        freq_heap = [(-count, idx) for idx, count in self.access_freq.items() if idx < len(self.leaves)]
        heapq.heapify(freq_heap)
        order = [idx for _, idx in (heapq.heappop(freq_heap) for _ in range(len(freq_heap)))]
        placed = set(order)
        order += [i for i in range(len(self.leaves)) if i not in placed]
        self.leaves = [self.leaves[i] for i in order]
        self.build()

    def get_proof(self, idx):
        if not self.tree:
            return []

        path = []
        pos = idx

        for level_idx in range(len(self.tree) - 1):
            level = self.tree[level_idx]
            sibling_pos = pos ^ 1
            is_left = (pos % 2 == 0)
            # an unpaired node is hashed with itself when the tree is built
            sibling = level[sibling_pos] if sibling_pos < len(level) else level[pos]
            path.append((sibling, is_left))
            pos //= 2

        return path

    def get_root(self):
        if not self.tree:
            return None
        return self.tree[-1][0] if self.tree[-1] else None

    def verify(self, leaf, path, root):
        h = leaf
        for sib, is_left in path:
            if is_left:
                h = hashlib.sha256((h + sib).encode()).hexdigest()
            else:
                h = hashlib.sha256((sib + h).encode()).hexdigest()
        return h == root


if __name__ == "__main__":
    mt = AdaptiveMerkleTree()
    for tx in ["tx1", "tx2", "tx3", "tx4", "tx5"]:
        mt.add_leaf(tx)
    mt.build()

    root = mt.get_root()
    proof = mt.get_proof(2)
    leaf_h = hashlib.sha256("tx3".encode()).hexdigest()
    print(f"root: {root}")
    print(f"proof[2] valid: {mt.verify(leaf_h, proof, root)}")

