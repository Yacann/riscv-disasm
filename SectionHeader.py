class SectionHeader():
    def __init__(self, bytes, endian):
        self.data = bytes

        self.name = int.from_bytes(self.data[:4], endian)
        self.type = self.data[4:8]
        self.flags = self.data[8:12]
        self.addr = int.from_bytes(self.data[12:16], endian)
        self.offset = int.from_bytes(self.data[16:20], endian)
        self.size = int.from_bytes(self.data[20:24], endian)
        self.link = self.data[24:28]
        self.info = self.data[28:32]
        self.addralign = int.from_bytes(self.data[32:36], endian)
        self.entsize = int.from_bytes(self.data[36:40], endian)