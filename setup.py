import os, platform
import sysconfig
from setuptools import find_packages, setup, Extension
from setuptools.command.build_ext import build_ext
from setuptools.command.build import build
from setup_helpers import build_lib_from_dll, get_ld_flags, is_windows, run_command_silently, touch, is_android

libdir = "build/lib"


# Define a custom command class that inherits from build_ext
class CustomBuildExtCommand(build_ext):
    extra_dlls = []
    def initialize_options(self):
        # Set environment variables here
        self.configure_env = os.environ.copy()
        include_path = sysconfig.get_config_var('INCLUDEPY')

        self.gosrc = "./src"
        self.configure_env["CGO_CFLAGS"] = f"-I '{include_path}' -I '{self.gosrc}'"
        super().initialize_options()
    def run(self):
        # Run custom command here
        libname = 'libgoutls.dll'
        buildmode = 'c-shared'
        if is_windows():
            version = sysconfig.get_config_var('VERSION')
            prefix = sysconfig.get_config_var('prefix')
            self.configure_env['CGO_LDFLAGS'] = f"-L '{prefix}' -lpython{version}"
            self.extra_dlls.append(os.path.join(libdir, libname))
        elif is_android():
            print("Building for android")
            libname = "libgoutls.so"
            self.extra_dlls.append(os.path.join(libdir, libname))
        else:
            buildmode = "c-archive"
            touch(libdir, libname)
            libname = "libgoutls.a"
        if platform.system() == 'Darwin':
            ld_flags = get_ld_flags()
            self.configure_env['CGO_LDFLAGS'] = ld_flags
        # print("$env:LDFLAGS = ", self.configure_env['LDFLAGS'])
        run_command_silently(['go', 'build', '-buildmode='+buildmode, '-o', f'./{libdir}/{libname}', self.gosrc], env=self.configure_env)
        # print(' '.join(['go', 'build', '-buildmode='+buildmode, '-o', f'../{libdir}/{libname}', '-C', self.gosrc]))
        if is_windows():
            build_lib_from_dll(libdir, libname, "goutls.lib")
        # Call the original build_ext command
        build_ext.run(self)

        # Copy the dlls we added with external command
        self.copy_dlls()


    def copy_dlls(self):
        out = os.path.join(self.build_lib, self.package)
        # touch(out, "useless.py")
        for dllpath in self.extra_dlls:
            self.copy_file(dllpath, out)
            
    def get_ext_fullpath(self, extname):
        out = build_ext.get_ext_fullpath(self, extname)
        return out
    
    def build_extension(self, ext) -> None:
        return super().build_extension(ext)

def get_rpath_dirs():
    if is_windows():
        return None
    return ['$ORIGIN']

# Define the extension module
_pyutls = Extension('_pyutls',
                    sources=['src/pyapi/cgo.cc'],
                    include_dirs=["build/lib", "src"],
                    library_dirs=["build/lib"],
                    libraries=["goutls"],
                    runtime_library_dirs=get_rpath_dirs(),
    )


# Define the setup parameters
setup(name='pyutls',
      version='0.0.1',
      description='My Python extension module',
      ext_modules=[_pyutls],
      packages=["pyutls"],
      cmdclass={'build_ext': CustomBuildExtCommand},
    #   package_data={"pyutls": [libdir+"/"+"libgoutls"]},
    #   data_files=[("dlls", [libdir+"/"+"libgoutls"])],
      package_dir = {'': 'src'},
    #   include_package_data=True,
      ext_package="pyutls",
      install_requires=['six', 'asn1crypto'],
      setup_requires=["wheel"],
)
