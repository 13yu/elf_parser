
local _M = {}


function _M.cut_out(str, from, len)
    return string.sub(str, from, from + len - 1)
end


local function char_to_hex(c)
    local hex = string.format('%02X', string.byte(c))
    return hex
end


function _M.to_hex(str)
    local hex_str = string.gsub(str, '.', char_to_hex)
    return hex_str
end


function _M.to_number(str, big_endian)
    local r = 0

    for i = 1, #str do
        local index = i
        if big_endian ~= true then
            index = #str - i + 1
        end

        local c = string.sub(str, index, index)

        r = r * 256 + string.byte(c)
    end

    return r
end


local function reverse(str)
    local reversed_str = ''
    for i = 1, #str do
        reversed_str = string.sub(str, i, i) .. reversed_str
    end

    return reversed_str
end


function _M.to_hex_number(str, big_endian)
    if big_endian ~= true then
        str = reverse(str)
    end

    local hex_str = string.gsub(str, '.', char_to_hex)
    return '0x' .. hex_str
end


function _M.next_to_number(str, index, len)
    return _M.to_number(_M.cut_out(str, index, len))
end


function _M.next_to_hex_number(str, index, len)
    return _M.to_hex_number(_M.cut_out(str, index, len))
end

return _M
