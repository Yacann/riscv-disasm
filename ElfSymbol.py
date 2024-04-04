class ElfSymbol():
    type = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 5: "COMMON",
            6: "TLS", 10: "LOOS", 12: "HIOS", 13: "LOPROC", 15: "HIPROC"}
    binding = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK", 10: "LOOS", 12: "HIOS", 13: "LOPROC", 15: "HIPROC"}
    visibility = {0: "DEFAULT", 1: "INTERNAL", 2: "HIDDEN", 3: "PROTECTED"}
    index = {0: "UNDEF", 65521: "ABS"}
    def __init__(self, bytes, endian):
        self.data = bytes

        self.name = int.from_bytes(self.data[:4], endian)
        self.value = int.from_bytes(self.data[4:8], endian)
        self.size = int.from_bytes(self.data[8:12], endian)
        self.info = self.data[12]
        self.other = self.data[13]
        self.shndx = int.from_bytes(self.data[14:16], endian)
    
    def str(self, i, name):
        if self.shndx in self.index:
            ind = self.index[self.shndx]
        else:
            ind = self.shndx
        return "[%4i] 0x%-15X %5i %-8s %-8s %-8s %6s %s\n" % (i, self.value, self.size,
            self.type[self.info & 0xf], self.binding[self.info >> 4], self.visibility[self.other & 0x3], ind, name)