class ReplayWindow:
    """
    replay protection for one transfer session

    当前版本先按单 session 使用
    后续 phase 2 可以再加 session_id manager
    """

    def __init__(self, window_size=128):
        self.window_size = window_size

        # 已连续交付的最大 seq
        self.max_delivered = 0

        # 已收到但还未连续交付的 seq
        self.buffered = set()

    def check(self, seq: int) -> str:
        """
        return:
            accept
            duplicate
            out_of_window
        """
        if seq <= self.max_delivered:
            return "duplicate"

        if seq in self.buffered:
            return "duplicate"

        if seq > self.max_delivered + self.window_size:
            return "out_of_window"

        return "accept"

    def mark_received(self, seq: int):
        self.buffered.add(seq)

    def advance(self):
        next_seq = self.max_delivered + 1
        while next_seq in self.buffered:
            self.buffered.remove(next_seq)
            self.max_delivered = next_seq
            next_seq += 1

    def check_and_mark(self, seq: int) -> str:
        status = self.check(seq)
        if status == "accept":
            self.mark_received(seq)
            self.advance()
        return status

    def expected_seq(self) -> int:
        return self.max_delivered + 1

    def debug_state(self):
        return {
            "max_delivered": self.max_delivered,
            "buffered": sorted(self.buffered),
            "window_size": self.window_size,
            "expected_seq": self.expected_seq(),
        }