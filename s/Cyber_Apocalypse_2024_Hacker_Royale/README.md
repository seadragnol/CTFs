# Cyber Apocalypse 2024 Hacker Royale

writeup chi tiết nằm ở đây: [notion](https://seadragnol.notion.site/Cyber-Apocalypse-2024-Hacker-Royale-bbc9e7a6b1424c28ab08ddaffbb7fc42?pvs=4)

## I. Challenges

### 1. pwn

| id  | name                                              | points | 難易度    | status  | Summary                                                                                                                                                                                                                                                                                      |
| --- | ------------------------------------------------- | ------ | --------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Tutorial                                          | 300    | very easy | Solved  | basic integer overflow                                                                                                                                                                                                                                                                       |
| 2   | [Delulu](./pwn/delulu/)                           | 300    | very easy | Solved  | basic format string vulnerability                                                                                                                                                                                                                                                            |
| 3   | [Writing on the Wall](./pwn/writing_on_the_wall/) | 300    | very easy | Solved  | basic buffer overflow => overwrite local variable                                                                                                                                                                                                                                            |
| 4   | [Pet Companion](./pwn/pet_companion/)             | 300    | easy      | Solved  | stack buffer overflow. No Pie => ret2csu: leak libc. ret2libc => system('/bin/sh\x00)                                                                                                                                                                                                        |
| 5   | [Rocket Blaster XXX](./pwn/rocket_blaster_xxx/)   | 300    | easy      | Solved  | stack buffer overflow. No Pie => ROP chain binary gadget: leak libc. ret2libc => system('/bin/sh\x00')                                                                                                                                                                                       |
| 6   | [Deathnote](./pwn/deathnote/)                     | 325    | medium    | Solved  | leak libc through dangling pointer of unsortedbin                                                                                                                                                                                                                                            |
| 7   | [Sound of Silence](./pwn/sound_of_silence/)       | 300    | medium    | Solved  | reuse system() call in code                                                                                                                                                                                                                                                                  |
| 8   | [Oracle](./pwn/oracle/)                           | 325    | hard      | Solved  | socket program, stack buffer overflow ⇒ rop gadget chain open read write                                                                                                                                                                                                                     |
| 9   | [Gloater](./pwn/gloater/)                         | 325    | insane    | Solved  | Hai lỗ hổng không terminate user input dẫn tới leak được libc và stack. Lỗ hổng bss buffer overflow ⇒ ghi đè địa chỉ chunk ⇒ house of spirit ⇒ arbitrary write ⇒ write gadget vào ret do stack đã bị leak địa chỉ. |
| 10  | [Maze of Mist](./pwn/maze_of_mist/)               | 350    | hard      | hellnah | chua hoc kernel nen khong biet xien                                                                                                                                                                                                                                                          |

new knowledges:

- pwndbg: if PIE on, use breakrva to set break point.
- pwntools: inside flat(), don't need to use p64 p32.
- if you want to find 'syscall, ret' gadget, use pwntools or ROPgadget with flag `--multibr`.

### 2. rev

| id  | name                                  | points | 難易度    | status | Summary                                                                                                                                                          |
| --- | ------------------------------------- | ------ | --------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | [LootStash](./rev/lootstash/)         | 300    | very easy | Solved | `strings`                                                                                                                                                        |
| 2   | [PackedAway](./rev/packed_away/)      | 300    | very easy | Solved | `upx -d` => `strings`                                                                                                                                            |
| 3   | [BoxCutter](./rev/boxcutter/)         | 300    | very easy | Solved | `strace`                                                                                                                                                         |
| 4   | [Crushing](./rev/crushing/)           | 300    | easy      | Solved | reverse một thuật toán `compression`                                                                                                                             |
| 5   | [QuickScan](./rev/quickscan/)         | 300    | medium    | Solved | Players will be sent a series of small, randomly generated ELF files and must rapidly and automatically anlalyse them in order to extract required data.         |
| 6   | [FollowThePath](./rev/followthepath/) | 300    | medium    | Solved | self-decrypting code stub                                                                                                                                        |
| 7   | [Metagaming](./rev/metagaming/)       | 325    | hard      | Solved | giả lập assembly, flag được đi qua một loạt các instructions, trong đó bao gồm cả các instructions gây nhiễu, nếu lọc ra được thì có thể đi ngược lấy được flag. |
| 8   | FlecksOfGold                          | 350    | hard      | Nope   |                                                                                                                                                                  |
| 9   | MazeOfPower                           | 350    | insane    | Nope   |                                                                                                                                                                  |

## II. results

![img](./img/teammvp.jpg)

## References

scoreboard: <https://ctf.hackthebox.com/event/1386/scoreboard>
