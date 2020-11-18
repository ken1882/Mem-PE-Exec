#ifndef INCLUDE_MPEE_MAIN
#define INCLUDE_MPEE_MAIN

#define RELB_ABSOLUTE 0
#define RELB_HIGH 1
#define RELB_LOW 2
#define RELB_HIGHLOW 3
#define RELB_HIGHADJ 4
#define RELB_MIPS_JMPADDR 5
#define RELB_SECTION 6
#define RELB_REL32 7
#define RELB_MIPS_JMPADDR16 9
#define RELB_IA64_IMM64c 9
#define RELB_DIR64 10
#define RELB_HIGH3ADJ 11

#define BUFFER_SIZE 0xffff

typedef unsigned long long QWORD;

#include <windows.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <vector>
#include <stack>
#include <conio.h>

typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY;

extern IMAGE_DOS_HEADER IDH;

extern IMAGE_NT_HEADERS32 INH32;
extern IMAGE_NT_HEADERS64 INH64;

#ifndef _WIN64
#define _FLAGX64 0
#define _FLAGX86 1
#else
#define _FLAGX64 1
#define _FLAGX86 0
#endif // _WIN64

#endif // INCLUDE_MPEE_MAIN
