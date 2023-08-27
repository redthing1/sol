project('sol', 'c',
  version : '0.1',
  default_options : ['warning_level=3'])

# These arguments are only used to build the shared library
# not the executables that use the library.
lib_args = ['-DBUILDING_SOL']

sol_lib = shared_library('sol',
  'sol_nacl.c', 'sol_rb.c',
  install : true,
  c_args : lib_args,
  gnu_symbol_visibility : 'default',
)

sol_demo_exe = executable('sol_demo', 'sol_demo.c',
  link_with : sol_lib)
test('sol', sol_demo_exe)

# Make this library usable as a Meson subproject.
sol_dep = declare_dependency(
  include_directories: include_directories('.'),
  link_with : sol_lib)

# Make this library usable from the system's
# package manager.
install_headers('sol.h', subdir : 'sol')

pkg_mod = import('pkgconfig')
pkg_mod.generate(
  name : 'sol',
  filebase : 'sol',
  description : 'Meson sample project.',
  subdirs : 'sol',
  libraries : sol_lib,
  version : '0.1',
)
