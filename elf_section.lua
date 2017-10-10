local util = require('util')

local _M = {}

local SHT_STRTAB = 0x3
local SHT_SYMTAB = 0x2
local SHT_RELA = 0x4
local SHT_DYNAMIC = 0x6


local function parse_string_table(elf_str, s_header)
    s_header.sh_type_name = 'SHT_STRTAB'
    local str = util.cut_out(elf_str, s_header.sh_offset + 1,
                             s_header.sh_size)
    s_header.string_table = {}

    local entry = ''

    for i = 1, #str do
        local c = string.sub(str, i, i)
        if string.byte(c) == 0 then
            table.insert(s_header.string_table, entry)
            entry = ''
        else
            entry = entry .. c
        end
    end
end


local function parse_one_symbol(symbol_str)
    local symbol = {}
    local index = 1

    -- st_name
    symbol.st_name = util.next_to_number(symbol_str, index, 4)
    index = index + 4

    -- st_info
    symbol.st_info = util.next_to_number(symbol_str, index, 1)
    index = index + 1

    -- st_other
    symbol.st_other = util.next_to_number(symbol_str, index, 1)
    index = index + 1

    -- st_shndx
    symbol.st_shndx = util.next_to_number(symbol_str, index, 2)
    index = index + 2

    -- st_value
    symbol.st_value = util.next_to_number(symbol_str, index, 8)
    symbol.st_value_hex = util.next_to_hex_number(symbol_str, index, 8)
    index = index + 8

    -- st_size
    symbol.st_size = util.next_to_number(symbol_str, index, 8)
    index = index + 8

    return symbol
end


local function parse_symbol_table(elf_str, s_header)
    s_header.sh_type_name = 'SHT_SYMTAB'
    local str = util.cut_out(elf_str, s_header.sh_offset + 1,
                             s_header.sh_size)
    s_header.symbol_table = {}

    local n = s_header.sh_size / s_header.sh_entsize
    for i = 1, n do
        symbol_str = util.cut_out(str, (i - 1) * s_header.sh_entsize + 1,
                                  s_header.sh_entsize)
        local symbol = parse_one_symbol(symbol_str)
        table.insert(s_header.symbol_table, symbol)
    end
end


local function parse_one_relocation(relocation_str)
    local relocation = {}
    local index = 1

    -- r_offset
    relocation.r_offset = util.next_to_number(relocation_str, index, 8)
    relocation.r_offset_hex = util.next_to_hex_number(relocation_str, index, 8)
    index = index + 8

    -- r_info
    relocation.r_info = util.next_to_number(relocation_str, index, 8)
    relocation.r_info_hex = util.next_to_hex_number(relocation_str, index, 8)
    index = index + 8

    -- r_addend
    relocation.r_addend = util.next_to_number(relocation_str, index, 8)
    index = index + 8

    return relocation
end


local function parse_relocation(elf_str, s_header)
    s_header.sh_type_name = 'SHT_RELA'
    local str = util.cut_out(elf_str, s_header.sh_offset + 1,
                             s_header.sh_size)
    s_header.relocation = {}

    local n = s_header.sh_size / s_header.sh_entsize
    for i = 1, n do
        relocation_str = util.cut_out(str, (i - 1) * s_header.sh_entsize + 1,
                                  s_header.sh_entsize)
        local relocation = parse_one_relocation(relocation_str)
        table.insert(s_header.relocation, relocation)
    end
end


local function parse_one_dynamic(dynamic_str)
    local dynamic = {}
    local index = 1

    -- d_tag
    dynamic.d_tag = util.next_to_number(dynamic_str, index, 8)
    dynamic.d_tag_hex = util.next_to_hex_number(dynamic_str, index, 8)
    index = index + 8

    -- d_un
    dynamic.d_un = util.next_to_number(dynamic_str, index, 8)
    dynamic.d_un_hex = util.next_to_hex_number(dynamic_str, index, 8)
    index = index + 8

    return dynamic
end


local function parse_dynamic(elf_str, s_header)
    s_header.sh_type_name = 'SHT_DYNAMIC'
    local str = util.cut_out(elf_str, s_header.sh_offset + 1,
                             s_header.sh_size)
    s_header.dynamic= {}

    local n = s_header.sh_size / s_header.sh_entsize
    for i = 1, n do
        dynamic_str = util.cut_out(str, (i - 1) * s_header.sh_entsize + 1,
                                  s_header.sh_entsize)
        local dynamic = parse_one_dynamic(dynamic_str)
        table.insert(s_header.dynamic, dynamic)
    end
end



local function parse_one_section_content(elf_str, s_header)
    if s_header.sh_type == SHT_STRTAB then
        parse_string_table(elf_str, s_header)

    elseif s_header.sh_type == SHT_SYMTAB then
        parse_symbol_table(elf_str, s_header)

    elseif s_header.sh_type == SHT_RELA then
        parse_relocation(elf_str, s_header)

    elseif s_header.sh_type == SHT_DYNAMIC then
        parse_dynamic(elf_str, s_header)
    end
end


function _M.parse_section_content(elf_str, s_headers)
    for _, s_header in ipairs(s_headers) do
        parse_one_section_content(elf_str, s_header)
    end
end


return _M
