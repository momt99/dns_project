from functools import reduce


class Policy:

    def __init__(self, start_time: int, end_time: int, count: int, maximum_amount: int) -> None:
        self.start_time = start_time
        self.end_time = end_time
        self.count = count
        self.maximum_amount = maximum_amount

    def to_bytes(self):
        def int_to_byte(num):
            return num.to_bytes(8, 'big')

        return reduce(
            lambda a, b:  a + int_to_byte(b),
            [self.start_time, self.end_time, self.count, self.maximum_amount],
            b'')

    def from_bytes(data: bytes):
        def bytes_to_int(b):
            return int.from_bytes(b, 'big')
        return Policy(
            bytes_to_int(data[:8]),
            bytes_to_int(data[8:16]),
            bytes_to_int(data[16:24]),
            bytes_to_int(data[24:]))
