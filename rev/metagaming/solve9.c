#include <stdio.h>

#define INT_BITS 32

__uint32_t expected_register[16] = {
    0x3ee88722,
    0xecbdbe2,
    0x60b843c4,
    0x5da67c7,
    0x171ef1e9,
    0x52d5b3f7,
    0x3ae718c0,
    0x8b4aacc2,
    0xe5cf78dd,
    0x4a848edf, // Modified value for register 9
    0x8f,
    0x4180000,
    0x0,
    0xd,
    0x0
};

int main() {
    // Define the flag template
    char flag_template[] = {'H', 'T', 'B', '{', 'a', 'a', 'a', 'a', 'b', 'b', 'b', 'b', 'c', 'c', 'c', 'c', 'd', 'd', 'd', 'd', 'e', 'e', 'e', 'e', 'f', 'f', 'f', 'f', 'g', 'g', 'g', 'g', 'h', 'h', 'h', 'h', 'i', 'i', 'i', '}'};

    // Define the instructions
    __uint32_t instructions[][3] = {
        {10, 9, 532704100},
        {10, 9, 2519542932},
        {2, 9, 2451309277},
        {2, 9, 3957445476},
        {8, 9, 2583554449},
        {10, 9, 1149665327},
        {8, 9, 3053959226},
        {8, 9, 3693780276},
        {2, 9, 609918789},
        {2, 9, 2778221635},
        {8, 9, 3133754553},
        {8, 9, 3961507338},
        {2, 9, 1829237263},
        {2, 9, 2472519933},
        {8, 9, 4061630846},
        {10, 9, 1181684786},
        {10, 9, 390349075},
        {8, 9, 2883917626},
        {10, 9, 3733394420},
        {2, 9, 3895283827},
        {2, 9, 2257053750},
        {10, 9, 2770821931},
        {2, 9, 477834410}
    };

    // Process instructions
    __uint32_t i;
    for (i = 0; i < 24; i++) {
        __uint32_t opcode = instructions[23 - i][0];
        __uint32_t op0 = instructions[23 - i][1];
        __uint32_t op1 = instructions[23 - i][2];

        // Print instruction details
        printf("i: %d\nopcode: %d\nop0: %d\nop1: %d\nflag: %s\n\n", i + 1, opcode, op0, op1, flag_template);

        // Execute instruction based on opcode
        switch (opcode) {
            case 2: // regs[Insn.op0] ^= Insn.op1;
                expected_register[op0] ^= op1;
                break;
            case 8: // regs[Insn.op0] += Insn.op1;
                expected_register[op0] -= op1;
                break;
            case 10: // regs[Insn.op0] -= Insn.op1;
                expected_register[op0] += op1;
                break;
        }

        // Print expected value of register 9
        printf("i: %d, %x\n", i + 1, expected_register[9]);
    }

    // Print final value of register 9
    printf("%x\n", expected_register[9]);

    return 0;
}