class ReplayWindow:
    def __init__(self, window_size=128):
        self.window_size = window_size
        self.max_delivered = 0
        self.buffered = set()

    def check(self, seq):
        if seq <= self.max_delivered:
            return "duplicate"

        if seq in self.buffered:
            return "duplicate"

        if seq > self.max_delivered + self.window_size:
            return "out_of_window"

        return "accept"

    def mark(self, seq):
        self.buffered.add(seq)

    def advance(self):
        next_seq = self.max_delivered + 1
        while next_seq in self.buffered:
            self.buffered.remove(next_seq)
            self.max_delivered = next_seq
            next_seq += 1

    def expected(self):
        return self.max_delivered + 1

    def debug_state(self):
        # 调试用
        return {
            "max_delivered": self.max_delivered,
            "buffered": sorted(self.buffered),
            "window_size": self.window_size,
            "expected_seq": self.expected(),
        }