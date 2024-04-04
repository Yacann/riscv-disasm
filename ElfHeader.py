class ElfHeader():
    def __init__(self, bytes):
        self.data = bytes
        self.check()

        self.format = self.data[4]
        
        if self.data[5] == 1:
            self.endian = "little"
        elif self.data[5] == 2:
            self.endian = "big"
        
        self.version = self.data[6]
        self.abi = self.data[7]
        self.abimore = self.data[8]
        self.pad = self.data[9:16]
        self.type = self.data[16:18]
        self.machine = self.data[18:20]
        
        self.versionelf = int.from_bytes(self.data[20:24], self.endian)
        self.entry = int.from_bytes(self.data[24:28], self.endian)
        self.phoff = int.from_bytes(self.data[28:32], self.endian)
        self.shoff = int.from_bytes(self.data[32:36], self.endian)
        self.flags = self.data[36:40]
        self.ehsize = int.from_bytes(self.data[40:42], self.endian)
        self.phentsize = int.from_bytes(self.data[42:44], self.endian)
        self.phnum = int.from_bytes(self.data[44:46], self.endian)
        self.shentsize = int.from_bytes(self.data[46:48], self.endian)
        self.shnum = int.from_bytes(self.data[48:50], self.endian)
        self.shstrndx = int.from_bytes(self.data[50:52], self.endian)
    
    def check(self):
         if self.data[:4] != b'\x7f\x45\x4c\x46':
             raise ValueError("Could not parse ELF header")