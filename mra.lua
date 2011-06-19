local mra_proto = Proto("mra", "Mail.Ru Agent Protocol")

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
    [0x1038] = 'MRIM_CS_LOGIN2',
}

mra_proto.fields.magic  = ProtoField.uint32("mra.magic",  "Magic",    base.HEX)
mra_proto.fields.proto  = ProtoField.uint32("mra.proto",  "Proto",    base.HEX)
mra_proto.fields.seq    = ProtoField.uint32("mra.seq",    "Sequence", base.DEC)
mra_proto.fields._type  = ProtoField.uint32("mra.type",   "Type",     base.HEX, vs_types)
mra_proto.fields.length = ProtoField.uint32("mra.length", "Length",   base.DEC)

function mra_proto.dissector(buffer,pinfo,tree)
    local offset = 0
    while (offset < buffer:len()) do
        local rest = buffer(offset)
        if (rest:len() < 20) then
            -- we event can't detect pud mra packet length
            pinfo.desegment_offset = offset
            pinfo.desegment_len    = -1 
            return nil
        end
        local length = 7 * 4 + 16 + rest(16,4):le_uint()
        if (rest:len() < length) then
            -- mra packet is not complete
            pinfo.desegment_offset = offset
            pinfo.desegment_len    = length - rest:len()
            return nil
        end
        pinfo.cols.protocol = "MRA"
        local subtree = tree:add(mra_proto, rest(), "Mail.Ru Agent Protocol Data")
        subtree:add_le(mra_proto.fields.magic,  rest(0,4))
        subtree:add_le(mra_proto.fields.proto,  rest(4,4))
        subtree:add_le(mra_proto.fields.seq,    rest(8,4))
        subtree:add_le(mra_proto.fields._type,  rest(12,4))
        subtree:add_le(mra_proto.fields.length, rest(16,4))
        offset = offset + length
    end
end

local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(2041,mra_proto)
