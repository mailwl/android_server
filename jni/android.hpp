#pragma once

#include "elfbase.h"

typedef unsigned int Elf32_Addr;

struct link_map {
  Elf32_Addr l_addr;
  char* l_name;
  Elf32_Dyn* l_ld;
  struct link_map* l_next;
  struct link_map* l_prev;
};

/* Used by the dynamic linker to communicate with the debugger. */
struct r_debug {
	int32_t r_version;
	struct link_map* r_map;
	Elf32_Addr r_brk;
	enum {
		RT_CONSISTENT,
		RT_ADD,
		RT_DELETE
	} r_state;
	Elf32_Addr r_ldbase;
};