
version 0.0.0.1

this is attempt to recompile android_server from idasdk66.
at this moment it compiles in some way (and starts on lollipop without any out).

all absent functions are stub in ida.cpp file (none implemented)

Plus need to implement this at the end of linux_debmod.cpp:

#ifdef __ANDROID__
// android reports simple library names without path. try to find it.
void linux_debmod_t::find_android_lib(ea_t base, char *lib, size_t bufsize)
{

}

bool linux_debmod_t::add_android_shlib_bpt(const meminfo_vec_t &miv, bool attaching)
{
	return false;
}
#endif