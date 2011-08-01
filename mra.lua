local mra_proto = Proto("mra", "Mail.Ru Agent Protocol")
local mra_header_length = 7 * 4 + 16

local vs_types = {          
    [0x1001] = 'MRIM_CS_HELLO',                        
    [0x1002] = 'MRIM_CS_HELLO_ACK',                    
    [0x1004] = 'MRIM_CS_LOGIN_ACK',                    
    [0x1005] = 'MRIM_CS_LOGIN_REJ',                    
    [0x1006] = 'MRIM_CS_PING',                         
    [0x1008] = 'MRIM_CS_MESSAGE',                      
    [0x1009] = 'MRIM_CS_MESSAGE_ACK',                  
    [0x1011] = 'MRIM_CS_MESSAGE_RECV',                 
    [0x1012] = 'MRIM_CS_MESSAGE_STATUS',               
    [0x100F] = 'MRIM_CS_USER_STATUS',                  
    [0x1013] = 'MRIM_CS_LOGOUT',                       
    [0x1014] = 'MRIM_CS_CONNECTION_PARAMS',            
    [0x1015] = 'MRIM_CS_USER_INFO',                    
    [0x1019] = 'MRIM_CS_ADD_CONTACT',                  
    [0x101A] = 'MRIM_CS_ADD_CONTACT_ACK',              
    [0x101B] = 'MRIM_CS_MODIFY_CONTACT',               
    [0x101C] = 'MRIM_CS_MODIFY_CONTACT_ACK',           
    [0x101D] = 'MRIM_CS_OFFLINE_MESSAGE_ACK',          
    [0x101E] = 'MRIM_CS_DELETE_OFFLINE_MESSAGE',       
    [0x1020] = 'MRIM_CS_AUTHORIZE',                    
    [0x1021] = 'MRIM_CS_AUTHORIZE_ACK',                
    [0x1022] = 'MRIM_CS_CHANGE_STATUS',                
    [0x1024] = 'MRIM_CS_GET_MPOP_SESSION',             
    [0x1025] = 'MRIM_CS_MPOP_SESSION',                 
    [0x1029] = 'MRIM_CS_WP_REQUEST',                   
    [0x1028] = 'MRIM_CS_ANKETA_INFO',                  
    [0x1033] = 'MRIM_CS_MAILBOX_STATUS',               
    [0x1037] = 'MRIM_CS_CONTACT_LIST2',
    [0x1038] = 'MRIM_CS_LOGIN2'
}

mra_proto.fields.magic  = ProtoField.uint32("mra.magic",  "Magic",    base.HEX)
mra_proto.fields.proto  = ProtoField.uint32("mra.proto",  "Proto",    base.HEX)
mra_proto.fields.seq    = ProtoField.uint32("mra.seq",    "Sequence", base.DEC)
mra_proto.fields._type  = ProtoField.uint32("mra.type",   "Type",     base.HEX, vs_types)
mra_proto.fields.length = ProtoField.uint32("mra.length", "Length",   base.DEC)

mra_proto.fields.ul     = ProtoField.uint32("mra.ul",     "UL",       base.DEC)
mra_proto.fields.lps    = ProtoField.string("mra.lps",    "LPS")
mra_proto.fields.uidl   = ProtoField.string("mra.uidl",   "UIDL")

function mra_read_ul(buf, offset, tree, title) 
	if (buf:len() < offset + 4) then
		return buf:len(), nil
	end
	local val = buf(offset, 4):le_uint()
	tree:add_le(mra_proto.fields.ul, buf(offset, 4), val, title .. ': ' .. val)
	return offset + 4, val
end

function mra_read_lps(buf, offset, tree, title)
	if (buf:len() < offset + 4) then
		return buf:len(), nil
	end
	local len = buf(offset, 4):le_uint()
	if (buf:len() < offset + 4 + len) then
		return buf:len(), nil
	end
	local val = buf(offset + 4, len):string()
	tree:add(mra_proto.fields.lps, buf(offset, len + 4), val, title .. ': ' .. val)
	return offset + 4 + len, val 
end

function mra_read_uidl(buf, offset, tree, title)
	if (buf:len() < 8) then
		return buf:len(), nil
	end
	local val = buf(offset, 8):string()
	tree:add(mra_proto.fields.uidl, buf(offset, 8), val, title .. ': ' .. val)
	return offset + 8, val
end

function is_chat_email(email)
	if (email:find("@chat.agent", -11) > 0) then
		return true
	else
		return false
	end
end

function mra_pkg_dissector(buffer, pinfo, ptree)
        pinfo.cols.protocol = "MRA"

        local tree = ptree:add(mra_proto, buffer(), "Mail.Ru Agent Protocol Data")
        tree:add_le(mra_proto.fields.magic,  buffer(0,4))
        tree:add_le(mra_proto.fields.proto,  buffer(4,4))
        tree:add_le(mra_proto.fields.seq,    buffer(8,4))
        tree:add_le(mra_proto.fields._type,  buffer(12,4))
        tree:add_le(mra_proto.fields.length, buffer(16,4))

	local type_str = vs_types[buffer(12, 4):le_uint()]
	local offset = mra_header_length

    	if (type_str == 'MRIM_CS_HELLO') then
		-- nothing
    	elseif (type_str == 'MRIM_CS_HELLO_ACK') then
        	offset = mra_read_ul(buffer, offset, tree, 'ping-period')            
    	elseif (type_str == 'MRIM_CS_LOGIN_ACK') then
		-- nothing
    	elseif (type_str == 'MRIM_CS_LOGIN_REJ') then
              	offset = mra_read_lps(buffer, offset, tree, 'reason') 
    	elseif (type_str == 'MRIM_CS_PING') then
        	-- nothing                 
    	elseif (type_str == 'MRIM_CS_MESSAGE') then
		local to = ''
                offset = mra_read_ul(buffer, offset, tree, 'flags')
		offset, to = mra_read_lps(buffer, offset, tree, 'to')
		offset = mra_read_lps(buffer, offset, tree, 'message')
		offset = mra_read_lps(buffer, offset, tree, 'rtf-message')
		if (is_chat_email(to)) then
			offset = mra_read_lps(buffer, offset, tree, 'multichat-data')
		end
    	elseif (type_str == 'MRIM_CS_MESSAGE_ACK') then
		local from = ''
                offset = mra_read_ul(buffer, offset, tree, 'msg-id')
                offset = mra_read_ul(buffer, offset, tree, 'flags')
		offset, from = mra_read_lps(buffer, offset, tree, 'from')
		offset = mra_read_lps(buffer, offset, tree, 'message')
		offset = mra_read_lps(buffer, offset, tree, 'rtf-message')
		if (is_chat_email(from)) then
			offset = mra_read_lps(buffer, offset, tree, 'multichat-data')
		end
    	elseif (type_str == 'MRIM_CS_MESSAGE_RECV') then
		offset = mra_read_lps(buffer, offset, tree, 'from')
                offset = mra_read_ul(buffer, offset, tree, 'msg-id')
    	elseif (type_str == 'MRIM_CS_MESSAGE_STATUS') then
                offset = mra_read_ul(buffer, offset, tree, 'status')
    	elseif (type_str == 'MRIM_CS_USER_STATUS') then
                offset = mra_read_ul(buffer, offset, tree, 'status')
		offset = mra_read_lps(buffer, offset, tree, 'user')
    	elseif (type_str == 'MRIM_CS_LOGOUT') then
                offset = mra_read_ul(buffer, offset, tree, 'reason')
    	elseif (type_str == 'MRIM_CS_CONNECTION_PARAMS') then
                offset = mra_read_ul(buffer, offset, tree, 'ping-period')
    	elseif (type_str == 'MRIM_CS_USER_INFO') then
        	while (offset < buffer:len()) do
			offset = mra_read_lps(buffer, offset, tree, 'pname')
			offset = mra_read_lps(buffer, offset, tree, 'value')
		end
    	elseif (type_str == 'MRIM_CS_ADD_CONTACT') then
                offset = mra_read_ul(buffer, offset, tree, 'flags')
                offset = mra_read_ul(buffer, offset, tree, 'group-id')
                offset = mra_read_lps(buffer, offset, tree, 'email')
                offset = mra_read_lps(buffer, offset, tree, 'nick')
    	elseif (type_str == 'MRIM_CS_ADD_CONTACT_ACK') then
                offset = mra_read_ul(buffer, offset, tree, 'status')
                offset = mra_read_ul(buffer, offset, tree, 'contact-id')
    	elseif (type_str == 'MRIM_CS_MODIFY_CONTACT') then
                offset = mra_read_ul(buffer, offset, tree, 'contact-id')
                offset = mra_read_ul(buffer, offset, tree, 'flags')
                offset = mra_read_ul(buffer, offset, tree, 'group-id')
                offset = mra_read_lps(buffer, offset, tree, 'email')
                offset = mra_read_lps(buffer, offset, tree, 'nick')
    	elseif (type_str == 'MRIM_CS_MODIFY_CONTACT_ACK') then
                offset = mra_read_ul(buffer, offset, tree, 'status')
    	elseif (type_str == 'MRIM_CS_OFFLINE_MESSAGE_ACK') then
                offset = mra_read_uidl(buffer, offset, tree, 'uidl')
                offset = mra_read_lps(buffer, offset, tree, 'message')
    	elseif (type_str == 'MRIM_CS_DELETE_OFFLINE_MESSAGE') then
                offset = mra_read_uidl(buffer, offset, tree, 'uidl')
    	elseif (type_str == 'MRIM_CS_AUTHORIZE') then
                offset = mra_read_lps(buffer, offset, tree, 'email')
    	elseif (type_str == 'MRIM_CS_AUTHORIZE_ACK') then
                offset = mra_read_lps(buffer, offset, tree, 'email')
    	elseif (type_str == 'MRIM_CS_CHANGE_STATUS') then
                offset = mra_read_ul(buffer, offset, tree, 'status')
    	elseif (type_str == 'MRIM_CS_GET_MPOP_SESSION') then
		-- nothing
    	elseif (type_str == 'MRIM_CS_MPOP_SESSION') then
                offset = mra_read_ul(buffer, offset, tree, 'status')
                offset = mra_read_lps(buffer, offset, tree, 'session')
    	elseif (type_str == 'MRIM_CS_WP_REQUEST') then
                offset = mra_read_ul(buffer, offset, tree, 'options')
                offset = mra_read_lps(buffer, offset, tree, 'query')
    	elseif (type_str == 'MRIM_CS_ANKETA_INFO') then
		local fields_num, rows_num = 0, 0
                offset = mra_read_ul(buffer, offset, tree, 'status')
                offset, fields_num = mra_read_ul(buffer, offset, tree, 'fields-num')
                offset, rows_num   = mra_read_ul(buffer, offset, tree, 'rows-num')
		for i = 1, rows_num do
			for j = 1, fields_num do
				offset = mra_read_lps(buffer, offset, tree, 'param ' .. i .. ' ' .. j)
			end
		end
    	elseif (type_str == 'MRIM_CS_MAILBOX_STATUS') then
                offset = mra_read_ul(buffer, offset, tree, 'unreaded')
    	elseif (type_str == 'MRIM_CS_CONTACT_LIST2') then
		local group_num, group_mask, contact_mask = 0, '', ''
                offset = mra_read_ul(buffer, offset, tree, 'status')
                offset, group_num = mra_read_ul(buffer, offset, tree, 'group-num')
                offset, group_mask = mra_read_lps(buffer, offset, tree, 'group-mask')
                offset, contact_mask = mra_read_lps(buffer, offset, tree, 'contact-mask')
		for g = 1, group_num do
			offset = mra_read_ul(buffer, offset, tree, 'group-flags')
			offset = mra_read_lps(buffer, offset, tree, 'group-name')
			for i = 3, group_mask:len() do
				local code = group_mask:sub(i, i)
				if (code == 'u') then
					offset = mra_read_ul(buffer, offset, tree, 'ul-param')
				elseif (code == 's') then
					offset = mra_read_lps(buffer, offset, tree, 'lps-param')
				else
					-- nothing
				end
			end
		end
		while (offset < buffer:len()) do
			offset = mra_read_ul(buffer, offset, tree, 'contact-flags')
			offset = mra_read_ul(buffer, offset, tree, 'contact-group')
			offset = mra_read_lps(buffer, offset, tree, 'contact-email')
			offset = mra_read_lps(buffer, offset, tree, 'contact-nick')
			offset = mra_read_ul(buffer, offset, tree, 'contact-server-status')
			offset = mra_read_ul(buffer, offset, tree, 'contact-status')
			for i = 7, contact_mask:len() do
				local code = contact_mask:sub(i, i)
				if (code == 'u') then
					offset = mra_read_ul(buffer, offset, tree, 'ul-param')
				elseif (code == 's') then
					offset = mra_read_lps(buffer, offset, tree, 'lps-param')
				else
					-- nothing
				end
			end
		end
    	elseif (type_str == 'MRIM_CS_LOGIN2') then
		offset = mra_read_lps(buffer, offset, tree, 'login')
		offset = mra_read_lps(buffer, offset, tree, 'pass')
		offset = mra_read_ul(buffer, offset, tree, 'status')
		offset = mra_read_lps(buffer, offset, tree, 'user-agent')
	else
		-- nothing
	end
end

function mra_proto.dissector(buffer, pinfo, tree)
	local offset = 0
	while (offset < buffer:len()) do
		local rest = buffer(offset)
		if (rest:len() < 20) then
			-- we event can't detect pdu mra packet length
			pinfo.desegment_offset = offset
			pinfo.desegment_len    = -1 
			return nil
		end
		local body_length = rest(16,4):le_uint()
		local length = mra_header_length + body_length
		if (rest:len() < length) then
			-- mra packet is not complete
			pinfo.desegment_offset = offset
			pinfo.desegment_len    = length - rest:len()
			return nil
		end
		mra_pkg_dissector(rest(0, length), pinfo, tree)	
		offset = offset + length
	end
end

local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(2041,mra_proto)
