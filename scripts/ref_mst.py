"""Faithful port of @atproto/repo incremental MST (mst.ts + util.ts)."""
import hashlib

def sha256(b): return hashlib.sha256(b).digest()
def leading_zeros(key):
    h = sha256(key if isinstance(key, bytes) else key.encode())
    n = 0
    for byte in h:
        if byte < 64: n += 1
        if byte < 16: n += 1
        if byte < 4: n += 1
        if byte == 0: n += 1
        else: break
    return n

class Leaf:
    def __init__(self, key, value): self.key, self.value = key, value
    def is_tree(self): return False
    def is_leaf(self): return True

class MST:
    def is_tree(self): return True
    def is_leaf(self): return False
    def __init__(self, entries=None, layer=None):
        self.entries = list(entries or [])
        self.layer = layer
    def get_layer(self):
        if self.layer is not None: return self.layer
        for e in self.entries:
            if e.is_leaf():
                self.layer = leading_zeros(e.key)
                return self.layer
        # no leaves: recurse into children
        for e in self.entries:
            if e.is_tree():
                cl = e.attempt_layer()
                if cl is not None:
                    self.layer = cl + 1
                    return self.layer
        self.layer = 0
        return 0
    def attempt_layer(self):
        if self.layer is not None: return self.layer
        for e in self.entries:
            if e.is_leaf(): return leading_zeros(e.key)
        for e in self.entries:
            if e.is_tree():
                cl = e.attempt_layer()
                if cl is not None: return cl + 1
        return None
    def find_idx(self, key):
        for i, e in enumerate(self.entries):
            if e.is_leaf() and e.key >= key: return i
        return len(self.entries)
    def at(self, i):
        return self.entries[i] if 0 <= i < len(self.entries) else None
    def splice_in(self, entry, index):
        return MST(self.entries[:index] + [entry] + self.entries[index:], self.layer)
    def update_entry(self, index, entry):
        return MST(self.entries[:index] + [entry] + self.entries[index+1:], self.layer)
    def remove_entry(self, index):
        return MST(self.entries[:index] + self.entries[index+1:], self.layer)
    def create_child(self):
        return MST([], self.get_layer() - 1)
    def add(self, key, value, known_zeros=None):
        key_zeros = known_zeros if known_zeros is not None else leading_zeros(key)
        layer = self.get_layer()
        new_leaf = Leaf(key, value)
        if key_zeros == layer:
            index = self.find_idx(key)
            found = self.at(index)
            if found and found.is_leaf() and found.key == key:
                raise Exception("dup " + key)
            prev = self.at(index - 1)
            if not prev or prev.is_leaf():
                return self.splice_in(new_leaf, index)
            else:
                left, right = prev.split_around(key)
                upd = self.entries[:index-1]
                if left: upd.append(left)
                upd.append(new_leaf)
                if right: upd.append(right)
                upd += self.entries[index:]
                return MST(upd, self.layer)
        elif key_zeros < layer:
            index = self.find_idx(key)
            prev = self.at(index - 1)
            if prev and prev.is_tree():
                return self.update_entry(index - 1, prev.add(key, value, key_zeros))
            else:
                sub = self.create_child()
                return self.splice_in(sub.add(key, value, key_zeros), index)
        else:
            left, right = self.split_around(key)
            layer0 = self.get_layer()
            extra = key_zeros - layer0
            for _ in range(1, extra):
                if left is not None: left = MST([left], left.get_layer() + 1)
                if right is not None: right = MST([right], right.get_layer() + 1)
            upd = []
            if left: upd.append(left)
            upd.append(new_leaf)
            if right: upd.append(right)
            return MST(upd, key_zeros)
    def split_around(self, key):
        index = self.find_idx(key)
        left_data, right_data = self.entries[:index], self.entries[index:]
        left, right = MST(left_data, self.layer), MST(right_data, self.layer)
        last = left_data[-1] if left_data else None
        if last and last.is_tree():
            left = left.remove_entry(len(left_data) - 1)
            s0, s1 = last.split_around(key)
            if s0: left = MST(left.entries + [s0], left.layer)
            if s1: right = MST([s1] + right.entries, right.layer)
        l = left if left.entries else None
        r = right if right.entries else None
        return l, r
