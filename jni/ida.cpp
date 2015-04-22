
#include <pro.h>
#include <diskio.hpp>
#include <kernwin.hpp>
#include <prodir.h>

bool under_debugger;

bool __fastcall is_32bit_thumb_insn(unsigned short a1)
{
	return (unsigned int) ((a1 >> 11) - 29) <= 2;
}



idaman THREAD_SAFE uchar *ida_export pack_dd(uchar *ptr, uchar *end, uint32 x) {
	return NULL;
}

idaman THREAD_SAFE uint32 ida_export unpack_dd(const uchar **pptr, const uchar *end) {
	return 0;
}

idaman THREAD_SAFE uchar *ida_export pack_dq(uchar *ptr, uchar *end, uint64 x) {
	return NULL;
}

idaman THREAD_SAFE uint64 ida_export unpack_dq(const uchar **pptr, const uchar *end) {
	return 0;
}
 

idaman THREAD_SAFE NORETURN void ida_export qexit(int code) {

}

idaman NORETURN AS_PRINTF(1, 0) void ida_export verror(const char *format, va_list va) {

}

idaman AS_PRINTF(3, 0) THREAD_SAFE int ida_export qvsnprintf(char *buffer, size_t n, const char *format, va_list va) {

}

idaman THREAD_SAFE AS_PRINTF(1, 0) int ida_export qvprintf(const char *format, va_list va) {
	return 0;
}

idaman THREAD_SAFE AS_PRINTF(1, 0) int ida_export qveprintf(const char *format, va_list va) {
	return 0;
}

idaman THREAD_SAFE char *ida_export qstrncpy(char *dst, const char *src, size_t dstsize) {
	return NULL;
}

idaman AS_PRINTF(3, 4) THREAD_SAFE int ida_export qsnprintf(char *buffer, size_t n, const char *format, ...) {

}

idaman THREAD_SAFE void  ida_export qfree(void *alloc) {

}

idaman THREAD_SAFE void *ida_export qalloc(size_t size) {
	return NULL;
}

idaman THREAD_SAFE void *ida_export qalloc_or_throw(size_t size) {
	return NULL;
}

idaman THREAD_SAFE void *ida_export qrealloc(void *alloc, size_t newsize) {

}

idaman THREAD_SAFE void *ida_export qvector_reserve(void *vec, void *old, size_t cnt, size_t elsize) {
	return NULL;
}

idaman THREAD_SAFE int ida_export qerrcode(int new_code=-1) {
	return 0;
}

idaman THREAD_SAFE char* ida_export winerr() {
	return NULL;
}

idaman THREAD_SAFE hit_counter_t *ida_export create_hit_counter(const char *name) {
	return NULL;
}

idaman THREAD_SAFE void ida_export hit_counter_timer(hit_counter_t *, bool enable) {

}

idaman THREAD_SAFE NORETURN void ida_export interr(int code) {

}

idaman THREAD_SAFE int   ida_export qfwrite(FILE *fp, const void *buf, size_t n) {
	return 0;
}

idaman THREAD_SAFE int   ida_export qfseek(FILE *fp, int32 offset, int whence) {
	return 0;
}

idaman THREAD_SAFE FILE *ida_export fopenWB(const char *file) {
	return NULL;
}

idaman THREAD_SAFE FILE *ida_export qfopen(const char *file, const char *mode) {
	return NULL;
}

idaman THREAD_SAFE FILE *ida_export fopenRT(const char *file) {
	return NULL;
}

idaman THREAD_SAFE FILE *ida_export fopenRB(const char *file) {
	return NULL;
}

idaman THREAD_SAFE int   ida_export qfread(FILE *fp, void *buf, size_t n) {
	return 0;
}

idaman THREAD_SAFE char *ida_export qfgets(char *s, size_t len, FILE *fp) {
	return NULL;
}

idaman THREAD_SAFE int   ida_export qfclose(FILE *fp) {
	return 0;
}

idaman int32 ida_export qlsize(linput_t *li) {
	return 0;
}

idaman THREAD_SAFE uint32 ida_export qfsize(FILE *fp) {

}

idaman THREAD_SAFE const char *ida_export qbasename(const char *path) {
	return NULL;
}

idaman THREAD_SAFE bool ida_export relocate_relobj(struct relobj_t *_relobj, ea_t ea, bool mf) {
	return true;
} 

idaman THREAD_SAFE uint32 ida_export calc_file_crc32(linput_t *fp) {
	return 0;
}

idaman THREAD_SAFE bool  ida_export qfileexist(const char *file) {
	return false;
}

idaman THREAD_SAFE char *ida_export qmake_full_path(char *dst, size_t dstsize, const char *src) {
	return NULL;
}

idaman linput_t *ida_export open_linput(const char *file, bool remote) {
	return NULL;
}

idaman void ida_export close_linput(linput_t *li) {

}

idaman THREAD_SAFE void ida_export get_nsec_stamp(uint64 *nsecs) {

}

idaman THREAD_SAFE int ida_export call_system(const char *command) {
	return 0;
}

idaman THREAD_SAFE void *ida_export launch_process(
        const launch_process_params_t &lpp,
        qstring *errbuf) {
	return NULL;
}		

idaman AS_PRINTF(3, 0) void ida_export vshow_hex(
        const void *dataptr,
        size_t len,
        const char *format,
        va_list va) {
		
}

idaman THREAD_SAFE void ida_export del_qatexit(void (idaapi*func)(void)) {

}

idaman THREAD_SAFE void ida_export qatexit(void (idaapi *func)(void)) {

}

idaman THREAD_SAFE bool ida_export qisabspath(const char *file) {	
	return true;
}

idaman AS_SCANF (2, 3) THREAD_SAFE int ida_export qsscanf(const char *input, const char *format, ...) {

}

idaman THREAD_SAFE const char *ida_export skipSpaces(const char *ptr) {
	return NULL;
}

idaman THREAD_SAFE char *ida_export qstrdup(const char *string) {
	return NULL;
}

idaman THREAD_SAFE const char *ida_export stristr(const char *s1, const char *s2) {

}

idaman THREAD_SAFE qsemaphore_t ida_export qsem_create(const char *name, int init_count) {

}

idaman THREAD_SAFE bool ida_export qsem_free(qsemaphore_t sem) {
	return false;
}

idaman THREAD_SAFE bool ida_export qsem_post(qsemaphore_t sem) {

}

idaman THREAD_SAFE bool ida_export qsem_wait(qsemaphore_t sem, int timeout_ms) {

}
 
idaman THREAD_SAFE qthread_t ida_export qthread_create(qthread_cb_t thread_cb, void *ud) {

}
 
idaman THREAD_SAFE bool ida_export qthread_join(qthread_t q) {

}

idaman THREAD_SAFE int ida_export qfindfirst(const char *pattern, qffblk_t *blk, int attr) {
	return 0;
}

idaman THREAD_SAFE int ida_export qfindnext(qffblk_t *blk) {
	return 0;
}

idaman THREAD_SAFE void ida_export qfindclose(qffblk_t *blk) {

}

idaman THREAD_SAFE char *ida_export str2user(char *dst, const char *src, size_t dstsize) {

}

idaman int32 ida_export qlseek(linput_t *li, int32 pos, int whence) {

}

idaman qoff64_t ida_export qlseek64(linput_t *li, qoff64_t pos, int whence) {

} 

idaman THREAD_SAFE char *ida_export qstpncpy(char *dst, const char *src, size_t dstsize) {

}

idaman ssize_t ida_export qlread(linput_t *li, void *buf, size_t size) {

} 

idaman int ida_export lreadbytes(linput_t *li, void *buf, size_t size, bool mf) {

}







