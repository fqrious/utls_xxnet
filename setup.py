import os
import subprocess
import sysconfig
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext

# Define a custom command class that inherits from build_ext
class CustomBuildExtCommand(build_ext):
    def initialize_options(self):
        # Set environment variables here
        self.configure_env = os.environ.copy()
        include_path = sysconfig.get_config_var('INCLUDEPY')

        self.configure_env["CGO_CFLAGS"] = f"-I '{include_path}'"
        super().initialize_options()
    def run(self):
        # Run custom command here

        subprocess.run(['go', 'build', '-buildmode=c-archive', '-o', 'build/pyutls.a'], env=self.configure_env)
        # Call the original build_ext command
        build_ext.run(self)
# Define the extension module
my_module = Extension('pyutls',
                      sources=['pyapi/cgo.cc', 'pyapi/safepy.cc'],
                    #   extra_objects=['build/pyutls.a'],
                      extra_link_args=['-Lbuild', '-l:pyutls.a'],
                      include_dirs=["./build", "."],
    )

# Define the setup parameters
setup(name='pyutls',
      version='0.0.1',
      description='My Python extension module',
      ext_modules=[my_module],
      cmdclass={'build_ext': CustomBuildExtCommand}
      )
