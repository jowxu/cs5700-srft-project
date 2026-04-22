class ReplayWindow:
    """
    Sliding window for replay protection.
    """

    def __init__(self, window_size=64):
        self.window_size = window_size
        # Highest contiguous sequence number delivered
        self.max_delivered = 0
        # Set of received but not yet delivered sequence numbers
        self.buffered = set()

    def check(self, seq: int) -> str:
        """
        Check the status of a sequence number.
        收到一个sequence number, 检查
        num小于目前最大的seq，说明之前已经给过，return重复，丢掉
        num在buffer暂存区，说明之前收到过，还在排队不是没来，现在重复来了扔掉
        num大于目前最大seq，和窗口大小，扔掉。

        用 max_delivered 和 buffered 做重复检测，确保每个包只交付一次。
        """
        if seq <= self.max_delivered:
            return "duplicate"
        if seq in self.buffered:
            return "duplicate"
        if seq > self.max_delivered + self.window_size:
            return "out_of_window"
        return "accept"

    def mark_received(self, seq: int):
        """
        Mark a sequence number as received.
        put it in buffered.
        如果是乱序的包，eg.先来5再来4，可以把5和4都分别放进buffered，and make them in the right sequence.
        """
        self.buffered.add(seq)

    def advance(self):
        """
        每次有一个新包进来时调用
        我们先有一个已经发送的最大的seq号码，+1就是下一个
        如果期望的下一个就在buffer里，deliver 然后继续检查一下个

        如果期望的下一个还不在buffer，就终止，等下一个包进来继续检查
        等到顺序补齐，确保不乱序
        """
        next_seq = self.max_delivered + 1

        while next_seq in self.buffered:
            self.buffered.remove(next_seq)
            self.max_delivered = next_seq
            next_seq += 1

    def expected_seq(self) -> int:
        """
        让server知道我已经收到哪些包了，收到哪里了
        Return the next expected in-order sequence number.
        """
        return self.max_delivered + 1

    def debug_state(self):
        """
        Return internal state for debugging.
        """
        return {
            "max_delivered": self.max_delivered,
            "buffered": sorted(self.buffered),
            "window_size": self.window_size,
            "expected_seq": self.expected_seq(),
        }