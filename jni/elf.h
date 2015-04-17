#ifndef __ELF_H__
#define __ELF_H__

#include <map>

#pragma pack(push, 4)


#include <diskio.hpp>

// gcc does not allow to initialize indexless arrays for some reason
// put an arbitrary number here. the same with visual c++
#if defined(__GNUC__) || defined(_MSC_VER)
#define MAXRELSYMS 64
#else
#define MAXRELSYMS
#endif

typedef Elf64_Ehdr elf_ehdr_t;
typedef Elf64_Shdr elf_shdr_t;
typedef Elf64_Phdr elf_phdr_t;
typedef Elf64_Sym  elf_sym_t;
typedef Elf64_Dyn  elf_dyn_t;
typedef Elf64_Rel  elf_rel_t;
typedef Elf64_Rela elf_rela_t;

class reader_t;
struct sym_rel;
typedef qvector<const sym_rel*> symrelvec_t;


//----------------------------------------------------------------------------
// rel_data_t holds whatever relocation information appears to be common
// to most ELF relocation "algorithms", as defined in the per-CPU
// addenda.
// Note: Most comments below were picked from the abi386.pdf file.
struct rel_data_t
{
  // Relocation type: R_<processor>_<reloc-type>.
  uchar type;

  // abi386.pdf: This means the place (section offset or address) of
  // the storage unit being relocated (computed using r_offset).
  ea_t   P;

  // abi386.pdf: This means the value of the symbol whose index
  // resides in the relocation entry.
  uval_t S;

  // S, plus addend
  ea_t Sadd;

  // Whether the 'reloc' parameter passed to 'proc_rel()'
  // is a REL, or a RELA (the actual reloc entry object
  // itself will always be a elf_rela_t instance).
  enum rel_entry_t
  {
    re_rel,
    re_rela
  };
  rel_entry_t rel_entry;
};


//----------------------------------------------------------------------------
struct got_access_t
{
  got_access_t()
    : start_ea(0) {}

  // Get the start address of the GOT.
  // If no GOT currently exists, and 'create' is true, one will
  // be created in a segment called ".got".
  // If no GOT exists, 0 is returned.
  ea_t get_start_ea(reader_t &reader, bool create = false);

  //
  void set_start_ea(ea_t ea) { start_ea = ea; }

  // FIXME: IT SHOULD BE POSSIBLE TO DO W/O THIS. get_start_ea()
  // SHOULD BE IN CHARGE OF CREATING THE SEGMENT. I MET AN ERROR
  // WITH PC_NEWRELS_64.ELF, BECAUSE WE HAVE A SHITTY "START_EA"
  // BECAUSE THERE'S THE _GLOBAL_OFFSET_TABLE_, THAT'S NOT EVEN
  // A LOCAL SYMBOL!
  segment_t *get_got_segment(reader_t &reader, bool create = false) const;

  // Some relocations, such as ARM's R_ARM_TLS_IE32, require that a got entry
  // be present in the linked file, in order to point to that entry.
  // However, when we are loading a simple relocatable ELF object file,
  // there's no GOT present. This is problematic because,
  // although we _could_ be taking a shortcut and patch the fixup to refer
  // to the extern:__variable directly, it is semantically different.
  // As as example, when we meet:
  //   LDR    R3, #00000000                     ; R_ARM_TLS_IE32; Offset in GOT to __libc_errno
  // generating:
  //   LDR    R3, [__libc_errno_tls_offset]
  // is not the same as:
  //   LDR    R3, [address, in got, of libc_errno_tls_offset]
  //
  // This is obviously the last formatting that's correct, as we don't
  // even *know* what the address of __libc_errno_tls_offset is; we just
  // know where to go and look for it.
  //
  // The solution is to create a .got section anyway, and allocate an entry
  // in there with the name of the symbol, suffixed with '_tpoff'.
  //
  // - reader  : The elf reader
  // - sym     : The symbol.
  //             Ignored if the original file *did* have a GOT.
  // - sym_idx : The symbol index.
  //             Ignored if the original file *did* have a GOT.
  // - suffix  : A suffix, to be added to the symbol name. E.g., '_tpoff', '_ptr', ...
  //             Ignored if the original file *did* have a GOT.
  ea_t allocate_entry(reader_t      &reader,
                      const sym_rel &sym,
                      uint32         sym_idx,
                      const char    *suffix);

  //
  // Get the ea in the GOT section, corresponding
  // the the 'A' addend.
  //
  // * If the file already had a GOT section, then
  //   the returned ea is simply got_segment->startEA + A.
  // * On the other hand, if this file had no GOT
  //   this calls #allocate_got_entry().
  //
  // - reader  : The elf reader
  // - A       : The 'addend' (i.e., displacement) in the GOT.
  //             Ignored if the original file had *no* GOT.
  // - sym     : The symbol.
  //             Ignored if the original file *did* have a GOT.
  // - sym_idx : The symbol index.
  //             Ignored if the original file *did* have a GOT.
  // - suffix  : A suffix, to be added to the symbol name. E.g., '_tpoff', '_ptr', ...
  //             Ignored if the original file *did* have a GOT.
  //
  // - returns : An offset in the GOT segment, possibly creating
  //             one.
  ea_t get_or_allocate_entry(reader_t      &reader,
                             uval_t         A,
                             const sym_rel &sym,
                             uint32         sym_idx,
                             const char    *suffix);


private:
  ea_t start_ea;
  std::map<uint32,ea_t> allocated_entries; // Used only when original file has no GOT.
};


//----------------------------------------------------------------------------
struct reloc_tools_t
{
  // GOT accessor/creator.
  got_access_t got;
};


//--------------------------------------------------------------------------
struct proc_def_t
{
#define E_RELOC_PATCHING  (char *)1
#define E_RELOC_UNKNOWN   (char *)2
#define E_RELOC_UNIMPL    (char *)3
#define E_RELOC_UNTESTED  (char *)4
  ea_t    _UNUSED1_gtb_ea;
  // Relocator function.
  // Note: symbol might be NULL
  const char  *(*proc_rel)          (reader_t         &reader,
                                     const rel_data_t &rel_data,
                                     const sym_rel    *symbol,
                                     const elf_rela_t *reloc,
                                     reloc_tools_t    *tools);
  // Patcher function
  size_t       (*proc_patch)        (reader_t      &reader,
                                     elf_shdr_t    *plt,
                                     const void    *gotps,
                                     reloc_tools_t *tools);
  const char * (*proc_flag)         (reader_t &reader, uint32 &e_flags);
  const char *stubname;
  int          (*proc_sec_ext)      (reader_t &reader, Elf64_Shdr *sh);
  int          (*proc_sym_ext)      (reader_t &reader, sym_rel *st, const char *name);
  const char * (*proc_dyn_ext)      (reader_t &reader, const Elf64_Dyn *dyn);
  bool         (*proc_file_ext)     (reader_t &reader, ushort filetype);
  void         (*proc_start_ext)    (reader_t &reader, ushort type, uint32 &flags, ea_t &entry);
  bool         (*proc_post_process) (reader_t &reader);

  int          (*proc_sym_init)     (reader_t &reader);
  enum sym_handling_t
  {
    normal = 0,
    skip
  };
  sym_handling_t (*proc_sym_handle) (reader_t &reader,
                                     sym_rel &sym,
                                     const char *symname);
  ushort patch_mode;
  uchar  r_drop;
  uchar  r_gotset;      // relocation type: GOT
  uchar  r_err;         // relocation type: usually R_xxx_JUMP_SLOT
  uchar  r_chk;         // relocation type: usually R_xxx_GLOB_DAT
  uchar  relsyms[MAXRELSYMS]; // relocation types which must be to loaded symbols

  // Gives a processor the opportunity to specify the ea at which
  // a given section should be loaded. If this function is not present,
  // or BADADDR is returned, the default segment ea computation is used.
  // See elf_m16c.cpp.
  ea_t         (*proc_segment_ea)   (reader_t &reader, elf_shdr_t &sh);
  const char * (*calc_procname)     (reader_t &reader, uint32 &e_flags, const char *procname);
};

//----------------------------------------------------------------------------
struct sym_rel;
class symrel_cache_t
{
public:
  enum slice_type_t
  {
    invalid = 0,
    symtab  = 1,
    dynsym  = 2,
    whole   = 3
  };

  class slice_t
  {
  public:
    slice_t(symrel_cache_t &_src, slice_type_t _t)
      : src(_src), tp(_t)
    {
      check_type(tp);
    }

    static void check_type(slice_type_t t) { QASSERT(722, t > invalid && t <= whole); }

    symrel_cache_t &get_symrel_cache() const { return src; }

    const sym_rel &get(uint64 idx) const { return src.get(*this, idx); }
    sym_rel &get(uint64 idx) { return src.get(*this, idx); }
    sym_rel &append() { return src.append(*this); }
    size_t size() const { return src.slice_size(*this); }
    slice_type_t type() const { return tp; }

    enum sort_type_t
    {
      section_and_value = 1
    };
    void sorted(sort_type_t t, qvector<const sym_rel*> &out) const;

  private:
    symrel_cache_t &src;
    slice_type_t tp;
  };

  struct ptr_t
  {
    ptr_t() : cache(NULL), type(invalid), idx(uint64(-1)) {}
    ptr_t(symrel_cache_t *c, slice_type_t t, uint64 i)
      : cache(c),
        type(t),
        idx(i)
    {
    }

    symrel_cache_t *cache;
    symrel_cache_t::slice_type_t type;
    uint64 idx;

    bool operator==(const ptr_t &other) const
    {
      return other.type == type
          && other.idx  == idx;
    }

    sym_rel &deref() const
    {
      return symrel_cache_t::slice_t(*cache, type).get(idx);
    }
  };

  symrel_cache_t()
    : storage(),
      dynsym_index(0) {}

  uint64 slice_start(const slice_t &slice) const { return slice_start(slice.type()); }
  uint64 slice_start(slice_type_t t) const;
  uint64 slice_end(const slice_t &slice) const { return slice_end(slice.type()); }
  uint64 slice_end(slice_type_t t) const;
  size_t slice_size(const slice_t &slice) const { return slice_size(slice.type()); }
  size_t slice_size(slice_type_t t) const { return slice_end(t) - slice_start(t); }

  const sym_rel &get(const slice_t &slice, uint64 idx) const { return get(slice.type(), idx); }
  const sym_rel &get(slice_type_t t, uint64 idx) const { return storage[slice_start(t) + idx]; }
  sym_rel &get(const slice_t &slice, uint64 idx) { return get(slice.type(), idx); }
  sym_rel &get(slice_type_t t, uint64 idx) { return storage[slice_start(t) + idx]; }
  sym_rel &append(const slice_t &slice) { return append(slice.type()); }
  sym_rel &append(slice_type_t t);

  void reserve(uint64 room) { storage.reserve(room); }
  ptr_t get_ptr(const sym_rel &symbol);

private:
  qvector<sym_rel> storage;
  uint64 dynsym_index;
};

//--------------------------------------------------------------------------
// relocation speed
struct sym_rel
{
  sym_rel()
  : original(),
    value(0),
    bind(0),
    type(0),
    sec(0),
    symsec(0),
    name(NULL),
    size(0),
    original_name(NULL),
    original_name_resolved(false),
    flags(0) {}

  ~sym_rel()
  {
    clear_name();
    clear_original_name();
  }

  sym_rel(const sym_rel &r)
  {
    memcpy(this, &r, sizeof(r));
    if ( name != NULL )
      name = qstrdup(name);
    if ( original_name != NULL )
      original_name = qstrdup(original_name);
  }

  void swap(sym_rel &r)
  {
    qswap(*this, r);
  }

  void clear_name()
  {
    if ( name != NULL )
    {
      qfree(name);
      name = NULL;
    }
  }

  void clear_original_name()
  {
    if ( original_name != NULL )
    {
      qfree(original_name);
      original_name = NULL;
    }
    original_name_resolved = false;
  }

  bool overlaps(uint16 section_index, uint64 offset) const
  {
    return sec == section_index
        && offset >= value
        && offset <  value + size;
  }

  void set_name(const qstring &n)
  {
    set_name(n.c_str());
  }

  void set_name(const char *n)
  {
    clear_name();
    if ( n != NULL && n[0] != '\0' )
      name = qstrdup(n);
    else
      name = NULL;
  }

  ea_t get_ea(const reader_t &reader, ea_t _debug_segbase=0) const;

  symrel_cache_t::slice_type_t get_slice_type(const symrel_cache_t &symbols) const;
  uint64 get_slice_index(const symrel_cache_t &symbols) const;

  void get_original_name(reader_t &reader, qstring *out);
  const char *get_original_name(reader_t &reader);

  void set_flag(uchar flag) { flags |= flag; }
  bool has_flag(uchar flag) const { return (flags & flag) != 0; }
  void clr_flag(uchar flag) { flags &= ~flag; }

  elf_sym_t original;

  uval_t value;         // absolute value or addr
  uchar bind;           // binding
  char type;            // type (-1 - not defined,
                        // -2 temp for rename NOTYPE)
                        // -3 temp for comment unloaded
  ushort sec;           // index, in the section header table, of the section
                        // to which this symbol applies.
  ushort symsec;        // index, in the section header table, of the section
                        // this symbol comes from.
  char *name;           // temporary for NOTYPE only
  uint64 size;

private:
  bool  original_name_lookup_performed() const {return original_name_resolved;}
  void  lookup_original_name(reader_t &reader);
  char *original_name;
  bool  original_name_resolved;
  uchar flags;
};
DECLARE_TYPE_AS_MOVABLE(sym_rel);

//--------------------------------------------------------------------------
// ids-loading
struct implib_name
{
  char        *name;
  implib_name *prev;
};

//--------------------------------------------------------------------------
typedef void idaapi set_elf_reloc_t(
        ea_t fixaddr,
        ea_t toea,
        uval_t value,
        adiff_t displ,
        int type,
        uval_t offbase);

//----------------------------------------------------------------------------
void idaapi set_reloc(
        reader_t &reader,

        // The ea of the data to be modified.
        ea_t P,

        // The ea that the instruction would point to,
        // if it were interpreted by the CPU.
        ea_t target_ea,

        // The data to be inserted at 'P'. Depending on whether
        // 'type' is a 64-bit fixup type or not, either the
        // first 32-bits, or the full 64 bits of 'data' will be
        // put in the database. Of course, this patch data
        // must hold the possible instruction bits, if they
        // are interleaved w/ the address data
        // (e.g., R_ARM_THM_MOVW_ABS_NC, ...).
        uval_t patch_data,

        adiff_t displ,

        // The type of relocation. See fixup.hpp's FIXUP_*
        int type,

        uval_t offbase=0);

void set_reloc_cmt(ea_t ea, int cmt);
#define RCM_PIC   0
#define RCM_ATT   1
#define RCM_COPY  2
#define RCM_TLS   3
#define RCM_IREL  4
void set_thunk_name(ea_t ea, ea_t name_ea);
void overflow(ea_t fixaddr, ea_t ea);
void handle_mips_dsym(reader_t &reader, const sym_rel &symrel, int isym, const char* name);

// It is assumed the 'in_out_offset' is relative to the start of
// the TLS block at runtime. Since those blocks have the following layout:
// +---------------+
// |               |
// |     .tdata    |
// |               |
// +---------------+
// |               |
// |     .tbss     |
// |               |
// +---------------+
// we'll associate 'in_out_offset' to either the '.tdata' segment,
// or the '.tbss' one, depending on whether it overflows
// .tdata or not.
//
// As a side-effect, note that the value pointed to by 'in_out_offset' will
// be different after this function returns, in case it lands into '.tbss'.
// (it will be: in_out_offset_after = in_out_offset - segment_size(".tdata"))
ea_t get_tls_ea_by_offset(uint32 *in_out_offset);
ea_t unwide_ea(ea_t ea, const char* diagn);
void parse_attributes(reader_t &reader, uint32 offset, size_t size);
int  elf_machine_2_proc_module_id(reader_t &reader);

//--------------------------------------------------------------------------
extern proc_def_t elf_alpha;
extern proc_def_t elf_arc;
extern proc_def_t elf_arcompact;
extern proc_def_t elf_arm;
extern proc_def_t elf_avr;
extern proc_def_t elf_c166;
extern proc_def_t elf_fr;
extern proc_def_t elf_h8;
extern proc_def_t elf_hp;
extern proc_def_t elf_i960;
extern proc_def_t elf_ia64;
extern proc_def_t elf_m16c;
extern proc_def_t elf_m32r;
extern proc_def_t elf_m68k;
extern proc_def_t elf_mc12;
extern proc_def_t elf_mips;
extern proc_def_t elf_mn10200;
extern proc_def_t elf_mn10300;
extern proc_def_t elf_pc;
extern proc_def_t elf_ppc;
extern proc_def_t elf_ppc64;
extern proc_def_t elf_sh;
extern proc_def_t elf_sparc;
extern proc_def_t elf_st9;
extern proc_def_t elf_v850;
extern proc_def_t elf_x64;
extern proc_def_t elf_tricore;

//--------------------------------------------------------------------------
extern Elf64_Shdr *sh_plt;
extern bool unpatched;
extern ea_t prgend;
extern uval_t debug_segbase;
extern char rel_mode;   // 1 - STT_SECTION
                        // 0 - !STT_SECTION
                        //-1 - STT_NOTYPE or undefined

// user parameters. these definitions and the input form are interdependent
// if you change the 'dialog_form' string, change these definitions too!
#define ELF_RPL_PLP   0x0001 // Replace PIC form of 'Procedure Linkage Table' to non PIC form
#define ELF_RPL_PLD   0x0002 // Direct jumping from PLT (without GOT) irrespective of its form
#define ELF_RPL_GL    0x0004 // Convert PIC form of loading '_GLOBAL_OFFSET_TABLE_[]' of address
#define ELF_RPL_UNL   0x0008 // Obliterate auxiliary bytes in PLT & GOT for 'final autoanalysis'
#define ELF_RPL_NPR   0x0010 // Natural form of PIC GOT address loading in relocatable file
#define ELF_RPL_UNP   0x0020 // Unpatched form of PIC GOT references in relocatable file
#define ELF_AT_LIB    0x0040 // Mark 'allocated' objects as library-objects (MIPS only)
#define ELF_BUG_GOT   0x0080 // Force conversion of all GOT entries to offsets
#define ELF_FIL_GAP   0x0100 // Fill gaps between segments
#define ELF_LD_CHNK   0x0200 // Load huge segments by chunks

// noform bits
#define ELF_DIS_GPLT  0x4000 // disable search got reference in plt
#define ELF_DIS_OFFW  0x8000 // can present offset bypass segment's

#define ELF_RPL_PTEST  (ELF_RPL_PLP | ELF_RPL_PLD | ELF_RPL_UNL)
#define ELF_RPL_NOTRN  (ELF_RPL_NPR | ELF_RPL_UNP)

#define FLAGS_CMT(bit, text)  if(e_flags & bit) { \
                               e_flags &= ~bit;   \
                               return(text);    }

//--------------------------------------------------------------------------
inline uval_t make64(uval_t oldval, uval_t newval, uval_t mask)
{
  return (oldval & ~mask) | (newval & mask);
}

//--------------------------------------------------------------------------
inline uint32 make32(uint32 oldval, uint32 newval, uint32 mask)
{
  return (oldval & ~mask) | (newval & mask);
}

#define MASK(x) ((1 << x) - 1)

static const uval_t M32 = uint32(-1);
static const uval_t M24 = MASK(24);
static const uval_t M16 = MASK(16);
static const uval_t M8  = MASK(8);

inline uval_t extend_sign(uval_t value, unsigned bits)
{
  return (value & ((uval_t)1 << (bits-1)))
        ? value | ~MASK(bits)
        : value & MASK(bits);
}

#undef MASK

#pragma pack(pop)

//----------------------------------------------------------------------------
struct dynamic_linking_tables_t
{
  dynamic_linking_tables_t()
    : offset(0),
      size(0),
      link(0) {}

  dynamic_linking_tables_t(size_t _o, size_t _s, int _l)
    : offset(_o),
      size(_s),
      link(_l) {}

  bool is_valid() const { return offset != 0; }

  size_t offset;
  size_t size;
  int link;
};

//----------------------------------------------------------------------------
class dynamic_linking_tables_provider_t
{
public:
  dynamic_linking_tables_provider_t()
    : dlt() {}
  const dynamic_linking_tables_t &get_dynamic_linking_tables_info() const { return dlt; }
  bool has_valid_dynamic_linking_tables_info() const { return dlt.is_valid(); }
  void set_dynamic_linking_tables_info(dynamic_linking_tables_t &other) { dlt = other; }
  void set_dynamic_linking_tables_info(size_t offset, size_t size, int link)
  {
    dynamic_linking_tables_t tmp(offset, size, link);
    set_dynamic_linking_tables_info(tmp);
  }

private:
  dynamic_linking_tables_t dlt;
};

//----------------------------------------------------------------------------
struct dynamic_info_t
{
  dynamic_info_t()
  {
    memset(this, 0, sizeof(dynamic_info_t));
    status = nok;
  }

  void initialize(const reader_t &reader);

  struct strtab_t
  {
    uint64 offset;
    uint64 size;
  } strtab;

  struct symtab_t
  {
    uint64 offset;
    uint64 size;
    uint16 entsize;
  } symtab;

  struct rel_t
  {
    uint64 offset;
    uint64 size;
    uint16 entsize;
  } rel;

  struct rela_t
  {
    uint64 offset;
    uint64 size;
    uint16 entsize;
  } rela;

  struct plt_t
  {
    uint64 offset;
    uint64 size;
    uint32 type;
  } plt;

  enum status_t
  {
    nok = 0,
    initialized = 1,
    ok  = 2
  };

  status_t get_status() const { return status; }
  const char *d_tag_str(uint16 e_machine, int64 d_tag) const;

  // Fill a "fake" header, typically to be used w/
  // a buffered_input_t.
  void fill_section_header(
          const reader_t &reader,
          const symtab_t &symtab,
          elf_shdr_t &header) const;
  void fill_section_header(
          const reader_t &reader,
          const rel_t &rel,
          elf_shdr_t &header) const;
  void fill_section_header(
          const reader_t &reader,
          const rela_t &rela,
          elf_shdr_t &header) const;
  void fill_section_header(
          const reader_t &reader,
          const plt_t &plt,
          elf_shdr_t &header) const;

private:
  void set_status(status_t s)
  {
    if ( s == ok )
      QASSERT(20036, status == initialized);
    status = s;
  }
  status_t status;

  friend class reader_t;
};

//----------------------------------------------------------------------------
// Can be used when parsing dynamic_info_t.
class dynamic_info_handler_t
{
public:
  dynamic_info_handler_t(reader_t &_r);

  // If other than 0 is returned, parsing is stopped.
  virtual int handle(const elf_dyn_t &dyn) = 0;
  virtual uint64 file_offset(uint64 ea) const;

protected:
  reader_t &reader;

private:
  dynamic_info_handler_t();
};

//----------------------------------------------------------------------------
class section_headers_t : public dynamic_linking_tables_provider_t
{
public:
  // Well-known section.
  enum wks_t
  {
    wks_bss = 1,
    wks_borlandcomment,
    wks_comment,
    wks_data,
    wks_dynamic,
    wks_dynstr,
    wks_dynsym,
    wks_got,
    wks_gotplt,
    wks_hash,
    wks_interp,
    wks_note,
    wks_plt,
    wks_rodata,
    wks_shstrtab,
    wks_strtab,
    wks_symtab,
    wks_text,
    wks_last
  };
  void        reset();
  elf_shdr_t* get(wks_t wks) { assert_initialized(); return &headers[wks2index(wks)]; }
  elf_shdr_t* get_safe(wks_t wks)
  {
    int index = wks2index(wks);
    if ( index > 0 )
      return &headers[index];
    else
      return NULL;
  }
  elf_shdr_t *get(uint32 index);
  elf_shdr_t *get(uint32 sh_type, const char *name);
  const elf_shdr_t *get(wks_t wks) const { return &headers[wks2index(wks)]; }
  const elf_shdr_t *get_safe(wks_t wks) const
  {
    int index = wks2index(wks);
    if ( index > 0 )
      return &headers[index];
    else
      return NULL;
  }
  const elf_shdr_t *get(uint32 index) const { assert_initialized(); return &headers[index]; }
  const elf_shdr_t *get(uint32 sh_type, const char *name) const;
  // Look for '.rel.<section_name>', or '.rela.<section_name>'.
  const elf_shdr_t *get_rel_for(bool *is_rela, uint32 index) const { return get_rel_for(is_rela, get(index)); }
  const elf_shdr_t *get_rel_for(bool *is_rela, const elf_shdr_t *section) const;
  int get_index(const elf_shdr_t *) const;
  uint32 get_index(wks_t wks) const { return wks2index(wks); }
  void set_index(wks_t wks, uint32 index, bool is_original);
  int add(const elf_shdr_t &);
  void set(wks_t wks, uint32 index);
  void clear() { reset(); } // FIXME: This shouldn't be part of the public API
  bool empty() const { return headers.empty(); }
  void resize(size_t size) { headers.resize(size); } // FIXME: This shouldn't be part of the public API
  void get_name(qstring *out, uint32 index) const;
  void get_name(qstring *out, const elf_shdr_t*) const;
  void get_name(qstring *out, const elf_shdr_t &sh) const { get_name(out, &sh); }
  void get_name(qstring *out, uint16 names_section_index, uint32 offset) const;
  bool is_original(wks_t wks) const;
  qvector<elf_shdr_t>::const_iterator begin() const { return headers.begin(); }
  qvector<elf_shdr_t>::const_iterator end  () const { return headers.end(); }
  qvector<elf_shdr_t>::iterator begin() { return headers.begin(); }
  qvector<elf_shdr_t>::iterator end  () { return headers.end(); }

  const char *sh_type_str(uint32 sh_type) const;

private:
  uint32 wks2index(wks_t wks) const;
  void set_reader(reader_t *r) { reader = r; }
  void assert_initialized() const { if ( !initialized ) INTERR(724); }

  qvector<elf_shdr_t> headers;
  uint32 wks_lut[wks_last];
  bool  wks_orig[wks_last];
  reader_t *reader;
  bool initialized;
  friend class reader_t;
};

//----------------------------------------------------------------------------
class program_headers_t : public dynamic_linking_tables_provider_t
{
public:
  program_headers_t()
  {
    reset();
  }
  void reset();
  qvector<elf_phdr_t>::const_iterator begin() const { return pheaders.begin(); }
  qvector<elf_phdr_t>::const_iterator end  () const { return pheaders.end(); }
  qvector<elf_phdr_t>::iterator begin() { return pheaders.begin(); }
  qvector<elf_phdr_t>::iterator end  () { return pheaders.end(); }
  elf_phdr_t *get(uint32 index) {  if ( !initialized ) INTERR(725); return &pheaders[index]; }
  ea_t get_image_base() const { return image_base; }
  void set_image_base(ea_t ea) { image_base = ea; }
  void resize(size_t size) { pheaders.resize(size); } // FIXME: This shouldn't be part of the pu
  void set_reader(reader_t *r) { reader = r; }
  const char *p_type_str(uint32 p_type) const;

private:
  qvector<elf_phdr_t> pheaders;
  ea_t image_base;
  reader_t *reader;
  bool initialized;

  friend class reader_t;
};

template<typename T> class buffered_input_t;
//----------------------------------------------------------------------------
class arch_specific_t
{
public:
  virtual ~arch_specific_t() {}
  virtual void on_start_symbols(reader_t &/*reader*/) {}
  virtual void on_symbol_read(
        reader_t & /*reader*/,
        buffered_input_t<sym_rel> &/*buffered_input*/,
        sym_rel &/*sym*/) {}
private:
};

//----------------------------------------------------------------------------
class reader_t
{
public:
  reader_t()
    : li(NULL), sif(0), arch_specific(NULL), load_bias(0)
  {
    init();
  }
  reader_t(linput_t *_li)
    : li(_li), sif(0), arch_specific(NULL), load_bias(0)
  {
    init();
  }
  reader_t(linput_t *_li, uint64 _start_in_file)
    : li(_li), sif(_start_in_file), arch_specific(NULL), load_bias(0)
  {
    init();
  }
  ~reader_t()
  {
    clear_arch_specific();
  }
  void reset();
  void set_linput(linput_t *_li) { li = _li; }
  linput_t *get_linput() const { return li; }
  void set_load_bias(adiff_t lb) { load_bias = lb; }
  adiff_t get_load_bias() const { return load_bias; }

  // DOCME
  enum unhandled_section_handling_t
  {
    ush_none = 0,
    ush_load,
    ush_skip
  };

  /*
   * The list of notifications to which the user of the reader
   * can react.
   * It is documented as follows:
   *  1) a short description of the notification, and possibly a hint
   *     on how it should be considered/treated.
   *  2) the list of arguments, to be consumed in a vararg fashion.
   */
  enum errcode_t
  {
    /*
     * The "class" of the ELF module is not properly defined. It
     * should really be one of (ELFCLASS32, ELFCLASS64).
     * We will fallback to the ELFCLASS32 class.
     *   - uint8: the ELF class, as defined in the file.
     */
    BAD_CLASS = 1,

    /*
     * The size of the ELF header conflicts with what was expected.
     *   - uint16: the size of the ELF header, as defined in the file
     *             (i.e., eh_ehsize)
     *   - uint16: the expected size.
     */
    BAD_EHSIZE,

    /*
     * The byte ordering is not properly defineed. It should
     * really be one of (ELFDATA2LSB, ELFDATA2MSB).
     * We will fallback to the ELFDATA2LSB ordering.
     *   - uint8: the byte ordering, as defined in the file.
     */
    BAD_ENDIANNESS,

    /*
     * The ELF module defines there are Program Header entries,
     * but it defines an entry size to be of an odd size.
     * We will fallback to the default size for program header
     * entries, which depends on the "class" of this ELF module.
     *   - uint16: the size of a program header entry, as defined in
     *     the file.
     *   - uint16: the expected size (to which we will fallback).
     */
    BAD_PHENTSIZE,

    /*
     * The ELF module either:
     * 1) defines an offset for the Program Header entries data but a
     *    count of 0 entries, or
     * 2) defines no offset for the Program Header entries data but a
     *    count of 1+ entries.
     * We will set the program header entries count to 0.
     *   - uint16: the number of entries, as defined in the file.
     *   - uint64: the offset for the entries data.
     */
    BAD_PHLOC,

    /*
     * The ELF module defines there are Section Header entries,
     * but it defines an entry size to be of an odd size.
     * We will fallback to the default size for section header
     * entries, which depends on the "class" of this ELF module.
     *   - uint16: the size of a section header entry, as defined in
     *     the file.
     *   - uint16: the expected size (to which we will fallback).
     */
    BAD_SHENTSIZE,

    /*
     * The ELF module:
     * 1) defines an offset for the Section Header entries data but a
     *    count of 0 entries, or
     * 2) defines no offset for the Section Header entries data but a
     *    count of 1+ entries, or
     * 3) defines too many entries, which would cause an EOF to occur
     *    while reading those.
     * We will set the section header entries count to 0.
     *   - uint16: the number of entries, as defined in the file.
     *   - uint64: the offset for the entries data.
     *   - int32 : the size of the file.
     */
    BAD_SHLOC,

    /*
     * The reader has encountered an unhandled section.
     *   - uint16     : The index of the section header.
     *   - Elf64_Shdr*: A pointer to the section header structure.
     * If handled, this notification should return a
     * "unhandled_section_handling_t", specifying how the
     * reader should proceed with it.
     */
    UNHANDLED_SECHDR,

    /*
     * The reader has encountered an unhandled section,
     * which even the reader instance user couldn't handle.
     *   - uint16     : The index of the section header.
     *   - Elf64_Shdr*: A pointer to the section header structure.
     */
    UNKNOWN_SECHDR,

    /*
     * The reader has spotted that the section's address
     * in memory (i.e., sh_addr) is not aligned on the
     * specified alignment (i.e., sh_addralign).
     *   - uint16     : The index of the section header.
     *   - Elf64_Shdr*: A pointer to the section header structure.
     */
    BAD_SECHDR_ALIGN,

    /*
     * The section header 0 is supposed to be SHT_NULL. But it wasn't.
     */
    BAD_SECHDR0,

    /*
     * The type of file (e_type) appears to be ET_CORE, and the
     * machine is SPARC. Those files usually have wrong SHT's. We
     * will rather opt for the PHT view.
     */
    USING_PHT_SPARC_CORE,

    /*
     * TLS definitions occured more than once in the file.
     */
    EXCESS_TLS_DEF,

    /*
     * The section with the given name is being redefined.
     *   - const char *: The name of the section
     */
    SECTION_REDEFINED,

    /*
     * While parsing the dynamic_info_t, the reader spotted
     * an invalid value for the DT_PLTREL entry.
     *   - uint32: The 'value' of that entry.
     */
    BAD_DYN_PLT_TYPE,

    /*
     * One of the symbols in the symbols tables has a bad binding.
     *   - unsigned char: The binding.
     */
    BAD_SYMBOL_BINDING,

    /*
     * The ELF module has a Section Header String Table index, but
     * it is out-of-bounds.
     *   - uint16: the section header string table index (i.e., e_shstrndx).
     *   - uint16: the number of section header entries (i.e., e_shnum).
     */
    BAD_SHSTRNDX,

    /*
     * The ELF module has Program Header entries, which means it's
     * ready to be loaded as a process image, but claims it is of
     * type ET_REL which makes it a relocatable object file.
     *   - uint16: the number of program header entries (i.e., e_phnum).
     *   - uint16: the type of the ELF module (i.e., e_type).
     */
    CONFLICTING_FILE_TYPE,

    LAST_WARNING = CONFLICTING_FILE_TYPE,

    /*
     * Couldn't read as many bytes as required.
     * This is a fatal issue, and should be treated as such.
     *  - size_t: expected bytes.
     *  - size_t: actually read.
     *  - int32 : position in file when reading was initiated.
     */
    ERR_READ,

    LAST_ERROR = ERR_READ
  };

  bool is_warning(errcode_t notif) const;
  bool is_error  (errcode_t notif) const;
  ssize_t prepare_error_string(char *buf, size_t bufsize, reader_t::errcode_t notif, va_list va) const;

  void set_handler(bool (*_handler)(const reader_t &reader, errcode_t notif, ...));

  int read_addr(void *buf);
  int read_off(void *buf);
  int read_xword(void *buf);
  int read_sxword(void *buf);
  int read_word(uint32 *buf);
  int read_half(uint16 *buf);
  int read_byte(uint8  *buf);
  int safe_read(void *buf, size_t size);

  //
  bool read_ident(); // false - bad elf file

  // Is the file a valid relocatable file? That is, it must have
  // the ET_REL ehdr e_type, and have a proper section table.
  bool is_valid_rel_file() const
  {
    return sections.initialized && !sections.empty() && get_header().e_type == ET_REL;
  }

  // //
  // bool      read_ident();
  const elf_ident_t &get_ident() const { return header.e_ident; }

  //
  bool read_header();
        elf_ehdr_t &get_header () { return header; }
  const elf_ehdr_t &get_header () const { return header; }

  //
  bool read_section_headers();

  //
  bool read_program_headers();

  // Android elf files can have a prelink.
  //
  // If such a prelink was found, this will return 'true' and
  // '*base' will be set to that prelink address.
  bool read_prelink_base(uint32 *base);

  uint64 get_start_in_file() const { return sif; }

  // Seek in the elf module, at the given position. If the elf
  // module has an offset in the file,
  // it will be added to 'pos' to compose the final position
  // in file.
  void seek(uint64 pos) { qlseek(li, sif+pos); }

  // Seek to section header #index.
  // (Note that this does not seek to the section's contents!)
  bool seek_to_section_header(uint32 index)
  {
    uint64 pos = header.e_shoff + uint64(index) * uint64(header.e_shentsize);
    if ( pos < header.e_shoff )
      return false;
    seek(pos);
    return true;
  }

  // Seek to program header #index.
  // (Note that this does not seek to the segment's contents!)
  bool seek_to_program_header(uint32 index)
  {
    uint64 pos = header.e_phoff + uint64(index) * uint64(header.e_phentsize);
    if ( pos < header.e_phoff )
      return false;
    seek(pos);
    return true;
  }

  // Get the current position, in the elf module (which could
  // start at an offset different than 0 in the file).
  uint64 tell() const { return qltell(li) - sif; }

  //
  uint32 rel_info_index(const elf_rel_t &r)  const;
  uint32 rel_info_index(const elf_rela_t &r) const;
  uchar rel_info_type(const elf_rel_t &r)  const;
  uchar rel_info_type(const elf_rela_t &r) const;

  void add_mapping(const elf_phdr_t &p);
  // Searches all defined mapping for one that would
  // encompass 'ea'. Returns -1 if not found.
  int64 file_offset(uint64 ea) const;

  void get_string_at(qstring *out, uint64 offset);
  bool get_symbol_name(const sym_rel &sym, qstring &out) const;

  // Sets the dynamic info
  int parse_dynamic_info(
        const dynamic_linking_tables_t &dlt,
        dynamic_info_t &di,
        dynamic_info_handler_t &handler,
        bool set = true);
  int parse_dynamic_info(
        const dynamic_linking_tables_t &dlt,
        dynamic_info_t &di);
  bool has_dynamic_info() const { return dyninfo.get_status() == dynamic_info_t::ok; }
  const dynamic_info_t &get_dynamic_info() const { QASSERT(726, has_dynamic_info()); return dyninfo; }
  void set_dynamic_info(const dynamic_info_t &source) { dyninfo = source; }

  arch_specific_t *get_arch_specific() const { return arch_specific; }

  // Human-friendly representations of
  // header (or ident) values.
  const char *file_type_str()    const;
  const char *os_abi_str()       const;
  const char *machine_name_str() const;

  program_headers_t pheaders;
  section_headers_t sections;

  struct standard_sizes_in_file_t
  {
    int ehdr;
    int phdr;
    int shdr;

    struct
    {
      uint sym;
      int dyn;
      int rel;
      int rela;
    } entries;

    struct
    {
      int elf_addr;
      int elf_off;
      int elf_xword;
      int elf_sxword;
    } types;
  } stdsizes;

private:
  void init();
  void clear_arch_specific()
  {
    if ( arch_specific != NULL )
    {
      delete arch_specific;
      arch_specific = NULL;
    }
  }

  linput_t *li;
  uint64 sif; // ELF start in file
  // Handle an error. If this function returns false, the reader will stop.
  bool (*handle_error)(const reader_t &reader, errcode_t notif, ...);
  elf_ehdr_t header;
  dynamic_info_t dyninfo;

  struct mapping_t
  {
    uint64 offset;
    uint64 size;
    uint64 ea;
  };
  qvector<mapping_t> mappings;

  arch_specific_t *arch_specific;
  adiff_t load_bias; // An offset to apply to the ea's
                     // when loading the program in memory.
};

/* extern reader_t reader; */

//----------------------------------------------------------------------------
struct input_status_t
{
  input_status_t(reader_t &_reader)
    : reader(_reader),
      pos(reader.tell())
  {
  }

  input_status_t(reader_t &_reader, int32 new_pos)
    : reader(_reader),
      pos(reader.tell())
  {
    reader.seek(new_pos);
  }

  ~input_status_t()
  {
    reader.seek(pos);
  }
private:
  reader_t &reader;
  uint64 pos;
  input_status_t();
};

//----------------------------------------------------------------------------
template<typename T> class buffered_input_t
{
public:
  buffered_input_t(reader_t &_reader, const elf_shdr_t &_section)
    : reader(_reader),
      section(_section),
      offset(section.sh_offset),
      count (section.sh_size/section.sh_entsize),
      isize (section.sh_entsize),
      read  (0),
      cur   (0),
      end   (0),
      section_idx(0)
  {
    is_64 = reader.get_ident().is_64();
    section_idx = reader.sections.get_index(&section);
  }

  bool has_next();

  bool next(T *&storage)
  {
    if ( cur >= end )
    {
      uint64 left = count - read;
      if ( !left )
        return false;

      if ( left > qnumber(buffer) )
        left = qnumber(buffer);

      cur  = 0;
      if ( read == 0 )
        start_reading();
      end  = read_items(left); //reader.read_symbols(offset, read, &symbols[0], left);
      read += end;
    }

    if ( cur < end )
    {
      storage = &buffer[cur];
      cur++;
      return true;
    }
    else
    {
      return false;
    }
  }

  const elf_shdr_t &get_section() const { return section; }
  int get_section_index() const { return section_idx; }

private:
  buffered_input_t();
  uint64 read_items(uint64 max)
  {
    uint64 i;
    input_status_t save_excursion(reader, offset + (read * isize));
    for ( i = 0; i < max; i++ )
      read_item(buffer[i]);
    return i;
  }

  void read_item(T &);

  void start_reading() {}

  reader_t &reader;
  const elf_shdr_t &section;
  uint64 offset;
  uint64 count;
  size_t isize;
  bool is_64;

  T buffer[200];
  uint64 read;
  uint32 cur;
  uint32 end;
  int section_idx;
};

#endif
