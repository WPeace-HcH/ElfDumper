import idc

def dump(dumpfile, startimg, endimg, offset):
    size = endimg - startimg
    dumpfile.seek(offset)
    for i in range(size):
        dumpfile.write(bytes([idc.get_wide_byte(startimg + i)]))

def main(addr):
    print("---Start to Dump 32bit ELF（By WPeace）")
    ImageBase = addr
    dumpfile = open("dumpELFfile.dex", "wb")
    e_phoff = ImageBase + idc.get_wide_dword(ImageBase + 0x1C)
    e_phnum = idc.get_wide_word(ImageBase + 0x2C)
    e_phentsize = idc.get_wide_word(ImageBase + 0x2A)
    for i in range(e_phnum):
        if idc.get_wide_dword(e_phoff) == 1 or idc.get_wide_dword(e_phoff) == 2:
            print("- start dump segment %d" %i)
            p_offset = idc.get_wide_dword(e_phoff + 0x4)
            p_vaddr = idc.get_wide_dword(e_phoff + 0x8)
            p_memsz = idc.get_wide_dword(e_phoff + 0x14)
            dump(dumpfile, p_vaddr, p_vaddr + p_memsz, p_offset)
        e_phoff = e_phoff + e_phentsize
    dumpfile.close()
    print("---Dump OK（By WPeace）")