project('sol', 'c',
  version : '0.1',
  default_options : [
    'warning_level=3',
    'optimization=2',
  ]
)

# These arguments are only used to build the shared library
# not the executables that use the library.
lib_args = ['-DBUILDING_SOL']

sol_include = include_directories('sol')
sol_src = files('sol/sol_nacl.c', 'sol/sol_rb.c')

# sol_shlib = shared_library('sol',
#   sol_src,
#   install : true,
#   c_args : lib_args,
#   gnu_symbol_visibility : 'default',
# )

sol_stlib = static_library('sol',
  sol_src,
  include_directories : sol_include,
  install : true,
  c_args : lib_args,
)

sol_demo_exe = executable('sol_demo', 'demo/sol_demo.c',
  include_directories : sol_include,
  link_with : sol_stlib)
test('sol', sol_demo_exe)

# Make this library usable as a Meson subproject.
sol_dep = declare_dependency(
  include_directories: sol_include,
  link_with : sol_stlib)

# Make this library usable from the system's
# package manager.
install_headers('sol/sol.h', subdir : 'sol')

pkg_mod = import('pkgconfig')
pkg_mod.generate(
  name : 'sol',
  filebase : 'sol',
  description : 'a tiny crypto library.',
  subdirs : 'sol',
  libraries : sol_stlib,
  version : '0.1',
)
