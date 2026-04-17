class ReplayWindow:
    """
    Sliding window for replay protection.

    Tracks received sequence numbers and ensures:
    - Duplicate packets are rejected
    - Out-of-window packets are rejected
    - In-order delivery can be reconstructed
    """

    def __init__(self, window_size=128):
        self.window_size = window_size

        # Highest contiguous sequence number delivered
        self.max_delivered = 0

        # Set of received but not yet delivered sequence numbers
        self.buffered = set()

    def check(self, seq: int) -> str:
        """
        Check the status of a sequence number.

        Returns:
            "accept"         → valid new packet
            "duplicate"      → already received or delivered
            "out_of_window"  → beyond current window
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
        """
        self.buffered.add(seq)

    def advance(self):
        """
        Advance the window if the next expected sequence is available.
        This ensures contiguous delivery.
        """
        next_seq = self.max_delivered + 1

        while next_seq in self.buffered:
            self.buffered.remove(next_seq)
            self.max_delivered = next_seq
            next_seq += 1

    def expected_seq(self) -> int:
        """
        Return the next expected in-order sequence number.
        Used for cumulative ACK.
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