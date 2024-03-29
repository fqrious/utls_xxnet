import subprocess, platform
import os, re
import sys
import sysconfig
FUNCTION_MATCH = re.compile('\d+\s+[0-9A-F]+\s+[0-9A-F]+\s(\w+)')

def build_lib_from_dll(libdir, dllname, libname):
    def_file = os.path.join(libdir, dllname + ".def")
    with open(def_file, "w") as outfile:
        gendef(libdir, dllname, outfile)
    libpath = os.path.join(libdir, libname)
    subprocess.run(["dlltool", "-d", def_file, "-l", libpath])


def touch(libdir, dllname):
    os.makedirs(libdir, exist_ok=True)
    with open(os.path.join(libdir, dllname), "w") as f:
        f.write("Autogenerated file, pretty fucking useless")


def gendef(dir, name, outfile):
    lib = os.path.join(dir, name)
    # p = subprocess.Popen(['dumpbin', '/EXPORTS', lib], stdout=subprocess.PIPE)
    # output, _ = p.communicate()
    output = run_command_silently(['dumpbin', '/EXPORTS', lib])
    outfile.write(f'LIBRARY "{name}"\n')
    outfile.write('EXPORTS\n')
    for line in output.splitlines():
        match = FUNCTION_MATCH.search(line)
        if match:
            fn = match.group(1)
            outfile.write(f'  {fn}\n')
            
def get_data():
    data = []
    if platform.system() == "Windows":
        data.append(("lib", ))
    return data
# build_lib_from_dll("build/lib", "libgoutls", "goutls.lib")

def run_command_silently(cmd, **kw):
    try:
        print(f"setup: running `{' '.join(cmd)}`")
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, encoding='utf-8', **kw)
        return output.strip()
    except subprocess.CalledProcessError as e:
        error_message = e.output.strip()
        raise RuntimeError(f"Error running command '{' '.join(cmd)}': {error_message}")

def get_ld_flags():
    cmd = sysconfig.get_config_var('LDSHARED')
    exe = cmd.split(' ', 1)[0]
    if 'clang' in exe or 'g++' in exe or 'gcc' in exe:
        return ' '.join(cmd.split(' ')[2:])
    raise Exception('Unsupported compiler/os: %s'%exe)

def is_android():
    # return True
    return hasattr(sys, "getandroidapilevel")

def is_windows():
    return platform.system() == "Windows"