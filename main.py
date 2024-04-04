import sys
from ElfHeader import ElfHeader
from ElfSymbol import ElfSymbol
from SectionHeader import SectionHeader
from constants import *


class Parser():
    register = {"00000": "zero", "00001": "ra", "00010": "sp", "00011": "gp",
                "00100": "tp", "00101": "t0", "00110": "t1", "00111": "t2",
                "01000": "s0", "01001": "s1", "01010": "a0", "01011": "a1",
                "01100": "a2", "01101": "a3", "01110": "a4", "01111": "a5",
                "10000": "a6", "10001": "a7", "10010": "s2", "10011": "s3",
                "10100": "s4", "10101": "s5", "10110": "s6", "10111": "s7",
                "11000": "s8", "11001": "s9", "11010": "s10", "11011": "s11",
                "11100": "t3", "11101": "t4", "11110": "t5", "11111": "t6"}

    mark_count = 0

    def parse_elf32(self, input_filename, output_filename):
        with open(input_filename, 'rb') as f:
            data = f.read()

        self.elf = ElfHeader(data[:Elf32_Ehdr])
        strndx = self.elf.shoff + self.elf.shstrndx * self.elf.shentsize
        entsize = self.elf.shentsize
        shift = SectionHeader(data[strndx:strndx+entsize], self.elf.endian).offset

        off = self.elf.shoff + entsize                                
        for i in range(1, self.elf.shnum):
            section = SectionHeader(data[off:off+entsize], self.elf.endian)
            i = 0
            while data[shift+section.name+i] != 0:
                i += 1
            name = data[shift+section.name:shift+section.name+i].decode()
            if name == ".text":
                self.text = section
            elif name == ".symtab":
                self.symtab = section
            elif name == ".strtab":
                self.strtab = section
            off += entsize

        self.marks = {}
        symbols = []
        off = self.symtab.offset
        shift = self.strtab.offset
        for i in range(self.symtab.size // Elf32_Stsize):
            symbol = ElfSymbol(data[off:off+Elf32_Stsize], self.elf.endian)
            i = 0
            while data[shift+symbol.name+i] != 0:
                i += 1
            name = data[shift+symbol.name:shift+symbol.name+i].decode()
            self.marks[symbol.value] = name
            symbols.append((symbol, name))
            off += Elf32_Stsize

        commands = []
        off = self.text.offset
        for i in range(self.text.size // Elf32_Csize):
            commands.append(self.parse_command(off + (1 << 16), data[off:off+Elf32_Csize], self.elf.endian))
            off += Elf32_Csize

        with open(output_filename, 'w') as f:
            f.write(".text\n")
            for cmd in commands:
                if cmd[1] in self.marks:
                    f.write( "\n%08x \t<%s>:\n" % (cmd[1], self.marks[cmd[1]]))
                if cmd[0] == -1:
                    f.write("invalid instruction\n")
                elif cmd[0] == 0:
                    f.write("   %05x:\t%08x\t%7s\t%s, %s\n" % cmd[1:])
                elif cmd[0] == 1:
                    f.write("   %05x:\t%08x\t%7s\t%s, 0x%x <%s>\n" % cmd[1:])
                elif cmd[0] == 2:
                    f.write("   %05x:\t%08x\t%7s\t%s, %d(%s)\n" % cmd[1:])
                elif cmd[0] == 3:
                    f.write("   %05x:\t%08x\t%7s\t%s, %s, 0x%x, <%s>\n" % cmd[1:])
                elif cmd[0] == 4:
                    f.write("   %05x:\t%08x\t%7s\t%s, %s, %s\n" % cmd[1:])
                elif cmd[0] == 5:
                    f.write("   %05x:\t%08x\t%7s\n" % cmd[1:])
                else:
                    f.write("invalid instruction\n")
            f.write("\n\n.symtab\n")
            f.write("\nSymbol Value              Size Type     Bind     Vis       Index Name\n")
            i = 0
            for s in symbols:
                f.write(s[0].str(i, s[1]))
                i += 1
            
    def parse_command(self, addr, bytes, endian):
        bytes = int.from_bytes(bytes, endian)
        bits = bin(bytes)[2:].zfill(32)
        opcode = bits[-7:]
        if opcode == "0110111" or opcode == "0010111":
            if opcode == "0110111":
                name = "lui"
            elif opcode == "0010111":
                name = "auipc"
            else:
                return -1
            rd = self.register[bits[-12:-7]]
            imm = int(bits[-32:-12], 2)
            return (0, addr, bytes, name, rd, hex(imm))
        elif opcode == "1101111":
            rd = self.register[bits[-12:-7]]
            offset = 12 * bits[-32] + bits[-20:-12] + bits[-21] + bits[-31:-25] + bits[-25:-21] + "0"
            jump = (addr + self.parse_uint(int(offset, 2), 32)) % (1 << 20)
            mark = self.parse_mark(jump)
            return (1, addr, bytes, "jal", rd, jump, mark)
        elif opcode == "1100111":
            rd = self.register[bits[-12:-7]]
            imm = self.parse_uint(int(bits[-32:-20], 2), 12)
            rs1 = self.register[bits[-20:-15]]
            return (2, addr, bytes, "jalr", rd, imm, rs1)
        elif opcode == "1100011":
            func3 = bits[-15:-12]
            if func3 == "000":
                name = "beq"
            elif func3 == "001":
                name = "bne"
            elif func3 == "100":
                name = "blt"
            elif func3 == "101":
                name = "bge"
            elif func3 == "110":
                name = "bltu"
            elif func3 == "111":
                name = "bgeu"
            else:
                return -1
            rs1 = self.register[bits[-20:-15]]
            rs2 = self.register[bits[-25:-20]]
            offset = 20 * bits[-32] + bits[-8] + bits[-31:-25] + bits[-12:-8] + "0"
            jump = (addr + self.parse_uint(int(offset, 2), 32)) % (1 << 20)
            mark = self.parse_mark(jump)
            return (3, addr, bytes, name, rs1, rs2, jump, mark)
        elif opcode == "0000011":
            func3 = bits[-15:-12]
            if func3 == "000":
                name = "lb"
            elif func3 == "001":
                name = "lh"
            elif func3 == "010":
                name = "lw"
            elif func3 == "100":
                name = "lbu"
            elif func3 == "101":
                name = "lhu"
            else:
                return -1
            rs1 = self.register[bits[-12:-7]]
            imm = self.parse_uint(int(bits[-32:-20], 2), 12)
            rs2 = self.register[bits[-20:-15]]
            return (2, addr, bytes, name, rs1, imm, rs2)
        elif opcode == "0100011":
            func3 = bits[-15:-12]
            if func3 == "000":
                name = "sb"
            elif func3 == "001":
                name = "sh"
            elif func3 == "010":
                name = "sw"
            else:
                return -1
            rs1 = self.register[bits[-20:-15]]
            imm = self.parse_uint(int(20 * bits[-32] + bits[-31:-25] + bits[-12:-7], 2), 31)
            rs2 = self.register[bits[-25:-20]]
            return (2, addr, bytes, name, rs2, imm, rs1)
        elif opcode == "0010011":
            func3 = bits[-15:-12]
            if func3 == "000":
                name = "addi"
            elif func3 == "010":
                name = "slti"
            elif func3 == "011":
                name = "sltiu"
            elif func3 == "100":
                name = "xori"
            elif func3 == "110":
                name = "ori"
            elif func3 == "111":
                name = "andi"
            elif func3 == "001":
                name = "slli"
            elif func3 == "101":
                func7 = bits[-32:-25]
                if func7 == "0000000":
                    name = "srli"
                elif func7 == "0100000":
                    name = "srai"
                else:
                    return -1
            else:
                return -1
            rd = self.register[bits[-12:-7]]
            rs1 = self.register[bits[-20:-15]]
            if name == "srli" or name == "srai":
                imm = int(bits[-25:-20], 2)
            else: 
                imm = self.parse_uint(int(bits[-32:-20], 2), 12)
            return (4, addr, bytes, name, rd, rs1, imm)
        elif opcode == "0110011":
            func3 = bits[-15:-12]
            func7 = bits[-32:-25]
            if func3 == "000":
                if func7 == "0000000":
                    name = "add"
                elif func7 == "0100000":
                    name = "sub"
                elif func7 == "0000001":
                    name = "mul"
                else:
                    return -1
            elif func3 == "001":
                if func7 == "0000000":
                    name = "sll"
                elif func7 == "0000001":
                    name = "mulh"
                else:
                    return -1
            elif func3 == "010":
                if func7 == "0000000":
                    name = "slt"
                elif func7 == "0000001":
                    name = "mulhsu"
                else:
                    return -1
            elif func3 == "011":
                if func7 == "0000000":
                    name = "sltu"
                elif func7 == "0000001":
                    name = "mulhu"
                else:
                    return -1
            elif func3 == "100":
                if func7 == "0000000":
                    name = "xor"
                elif func7 == "0000001":
                    name = "div"
                else:
                    return -1
            elif func3 == "101":
                if func7 == "0000000":
                    name = "srl"
                elif func7 == "0100000":
                    name = "sra"
                elif func7 == "0000001":
                    name = "divu"
                else:
                    return -1
            elif func3 == "110":
                if func7 == "0000000":
                    name = "or"
                elif func7 == "0000001":
                    name = "rem"
                else:
                    return -1
            elif func3 == "111":
                if func7 == "0000000":
                    name = "and"
                elif func7 == "0000001":
                    name = "remu"
                else:
                    return -1
            else:
                return -1
            rd = self.register[bits[-12:-7]]
            rs1 = self.register[bits[-20:-15]]
            rs2 = self.register[bits[-25:-20]]
            return (4, addr, bytes, name, rd, rs1, rs2)
        elif opcode == "0001111":
            func3 = bits[-15:-12]
            if func3 == "000":
                if bits[-32:-7] == "0000000100000000000000000":
                    name = "pause"
                else:
                    name = "fence"
            elif func3 == "001":
                name = "fence.i"
            else:
                return -1
            pred = "" + "i" * int(bits[-28]) + "o" * int(bits[-27]) + "r" * int(bits[-26]) + "w" * int(bits[-25])
            succ = "" + "i" * int(bits[-24]) + "o" * int(bits[-23]) + "r" * int(bits[-22]) + "w" * int(bits[-21])
            return (0, addr, bytes, name, pred, succ)
        elif opcode == "1110011":
            func12 = bits[-32:-20]
            if func12 == "000000000000":
                name = "ecall"
            elif func12 == "000000000001":
                name = "ebreak"
            else:
                return -1
            return (5, addr, bytes, name)
        elif opcode == "0101111":
            func5 = bits[-32:-27]
            if func5 == "00010":
                name = "lr.w"
            elif func5 == "00011":
                name = "sc.w"
            elif func5 == "00001":
                name = "amoswap.w"
            elif func5 == "00000":
                name = "amoadd.w"
            elif func5 == "00100":
                name = "amoxor.w"
            elif func5 == "01100":
                name = "amoand.w"
            elif func5 == "01000":
                name = "amoor.w"
            elif func5 == "10000":
                name = "amomin.w"
            elif func5 == "10100":
                name = "amomax.w"
            elif func5 == "11000":
                name = "amominu.w"
            elif func5 == "11100":
                name = "amomaxu.w"
            else:
                return -1 
            rd = self.register[bits[-12:-7]]
            rs1 = self.register[bits[-20:-15]]
            rs2 = self.register[bits[-25:-20]]
            if name == "lr.w":
                return (0, addr, bytes, name, rd, rs1)
            else:
                return (4, addr, bytes, name, rd, rs2, rs1)
        else:
            return -1
    
    def parse_mark(self, addr):
        if addr in self.marks:
            mark = self.marks[addr]
        else:
            mark = "L%i" % self.mark_count
            self.marks[addr] = mark
            self.mark_count += 1
        return mark

    def parse_uint(self, x, len):
        if x >= 1 << len - 1:
            return x - (1 << len)
        return x


def main():
    parser = Parser()
    parser.parse_elf32(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()