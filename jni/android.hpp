#pragma once

#include "elfbase.h"

struct link_map {
  ElfW(Addr) l_addr;
  char* l_name;
  ElfW(Dyn)* l_ld;
  struct link_map* l_next;
  struct link_map* l_prev;
};