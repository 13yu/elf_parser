local util = require('util')
local cjson = require('cjson')
local elf_section = require('elf_section')

local _M = {}

local function next_to_number(str, index, len)
    return util.to_number(util.cut_out(str, index, len))
end


local function next_to_hex_number(str, index, len)
    return util.to_hex_number(util.cut_out(str, index, len))
end

local function parse_ident(indent)
    local e_ident = {}
    e_ident.ei_data = util.to_number(string.sub(indent, 6, 6))

    return e_ident
end


local function parse_elf_header(header)
    local elf_header = {}

    local index = 1

    -- e_ident: first 16 bytes
    elf_header.e_ident = parse_ident(util.cut_out(header, index, 16))
    index = index + 16

    -- type
    elf_header.e_type = next_to_number(header, index, 2)
    index = index + 2

    -- machine
    elf_header.e_machine = next_to_number(header, index, 2)
    index = index + 2

    -- version
    elf_header.e_version = next_to_number(header, index, 4)
    index = index + 4

    -- entry
    elf_header.e_entry = next_to_hex_number(header, index, 8)
    index = index + 8

    -- phoff
    elf_header.e_phoff = next_to_number(header, index, 8)
    elf_header.e_phoff_hex = next_to_hex_number(header, index, 8)
    index = index + 8

    -- shoff
    elf_header.e_shoff = next_to_number(header, index, 8)
    elf_header.e_shoff_hex = next_to_hex_number(header, index, 8)
    index = index + 8

    -- flags
    elf_header.e_flags = next_to_number(header, index, 4)
    index = index + 4

    -- ehsize
    elf_header.e_ehsize = next_to_number(header, index, 2)
    index = index + 2

    -- phentsize
    elf_header.e_phentsize = next_to_number(header, index, 2)
    index = index + 2

    -- phnum
    elf_header.e_phnum = next_to_number(header, index, 2)
    index = index + 2

    -- shentsize
    elf_header.e_shentsize = next_to_number(header, index, 2)
    index = index + 2

    -- shnum
    elf_header.e_shnum = next_to_number(header, index, 2)
    index = index + 2

    -- shstrndx
    elf_header.e_shstrndx = next_to_number(header, index, 2)
    index = index + 2

    return elf_header
end

local function parse_one_program_header(p_header_str)
    print(#p_header_str)
    local p_header = {}
    local index = 1

    -- p_type
    p_header.p_type = next_to_number(p_header_str, index, 4)
    index = index + 4

    -- p_flags
    p_header.p_flags = next_to_number(p_header_str, index, 4)
    index = index + 4

    -- p_offset
    p_header.p_offset = next_to_number(p_header_str, index, 8)
    p_header.p_offset_hex = next_to_hex_number(p_header_str, index, 8)
    index = index + 8

    -- p_vaddr
    p_header.p_vaddr_hex = next_to_hex_number(p_header_str, index, 8)
    index = index + 8

    -- p_paddr
    p_header.p_paddr_hex = next_to_hex_number(p_header_str, index, 8)
    index = index + 8

    -- p_filesz
    p_header.p_filesz = next_to_number(p_header_str, index, 8)
    index = index + 8

    -- p_memsz
    p_header.p_memsz = next_to_number(p_header_str, index, 8)
    index = index + 8

    -- p_align
    p_header.p_align = next_to_number(p_header_str, index, 8)
    index = index + 8

    return p_header
end

local function parse_program_headers(p_headers_str)
    local p_headers = {}
    local n = #p_headers_str / 56
    for i = 1, n do
        local str = util.cut_out(p_headers_str, (i - 1) * 56 + 1, 56)
        local p_header = parse_one_program_header(str)

        table.insert(p_headers, p_header)
    end

    return p_headers
end

local function parse_one_section_header(s_header_str)
    local s_header = {}
    local index = 1

    -- sh_name
    s_header.sh_name = next_to_number(s_header_str, index, 4)
    index = index + 4

    -- sh_type
    s_header.sh_type = next_to_number(s_header_str, index, 4)
    index = index + 4

    -- sh_flags
    s_header.sh_flags = next_to_number(s_header_str, index, 8)
    index = index + 8

    -- sh_addr
    s_header.sh_addr = next_to_number(s_header_str, index, 8)
    s_header.sh_addr_hex = next_to_hex_number(s_header_str, index, 8)
    index = index + 8

    -- sh_offset
    s_header.sh_offset = next_to_number(s_header_str, index, 8)
    s_header.sh_offset_hex = next_to_hex_number(s_header_str, index, 8)
    index = index + 8

    -- sh_size
    s_header.sh_size = next_to_number(s_header_str, index, 8)
    index = index + 8

    -- sh_link
    s_header.sh_link = next_to_number(s_header_str, index, 4)
    index = index + 4

    -- sh_info
    s_header.sh_info = next_to_number(s_header_str, index, 4)
    index = index + 4

    -- sh_addralign
    s_header.sh_addralign = next_to_number(s_header_str, index, 8)
    index = index + 8

    -- sh_entsize
    s_header.sh_entsize = next_to_number(s_header_str, index, 8)
    index = index + 8

    return s_header
end


local function parse_section_headers(s_headers_str)
    local s_headers = {}
    local n = #s_headers_str / 64
    for i = 1, n do
        local str = util.cut_out(s_headers_str, (i - 1) * 64 + 1, 64)
        local s_header = parse_one_section_header(str)

        table.insert(s_headers, s_header)
    end

    return s_headers
end


function _M.parse()
    local file_name, err = 'a.out'
    if err ~= nil then
        print(err)
        return
    end


    local f = io.open(file_name)
    local elf_str = f:read('*a')
    print('file length: ' .. tostring(#elf_str))

    local elf = {}

    -- elf header start from 1, length is 64
    elf.elf_header = parse_elf_header(util.cut_out(elf_str, 1, 64))

    -- program headers
    local p_headers_str = util.cut_out(elf_str, elf.elf_header.e_phoff + 1,
                                       elf.elf_header.e_phnum * elf.elf_header.e_phentsize)
    elf.p_headers = parse_program_headers(p_headers_str)

    -- section headers
    local s_headers_str = util.cut_out(elf_str, elf.elf_header.e_shoff + 1,
                                       elf.elf_header.e_shnum * elf.elf_header.e_shentsize)
    elf.s_headers = parse_section_headers(s_headers_str)

    -- section headers content
    elf_section.parse_section_content(elf_str, elf.s_headers)

    print(cjson.encode(elf.s_headers))
end

_M.parse()

return _M
