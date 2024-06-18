from pwn import *

f = open("message.txt.cz", mode="rb")
# f = open("output.txt", mode="rb")

data = f.read()

l = list('\x00'*1000)

running = -1
count = 0
for i in range(len(data)//8):
    if count:
        log.info(f"found {running} at index {i}")
        idx = u64(data[i*8:(i+1)*8])
        l[idx] = chr(running)
        count = count -1
    else:
        count = u64(data[i*8:(i+1)*8])
        running = running + 1
    

print(''.join(l))
        