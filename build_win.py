import os, sys, sysconfig
import re

cmd = ["go", "build", "-buildmode=c-shared", "-o", "build/pyutls.so", "."] #, '-n']
cmd = ["go", "build", "-buildmode=c-shared", "-o", "build/pyutls.so", '-x', "."]

def get_library_path():
    return ""
    import os.path as op;
    libdir = sysconfig.get_config_var('LIBDIR')
    libpl = sysconfig.get_config_var('LIBPL')
    ldlib = sysconfig.get_config_var('LDLIBRARY')
    fpaths = [op.join(pv, ldlib) for pv in (libdir, libpl)];
    paths = set()
    for path in filter(op.exists, fpaths):
        dirpath = os.path.dirname(path)
        paths.add(f"-L '{dirpath}'")
    bldlib = 'BLDLIBRARY'
    libpath = ' '.join(paths)
    libpath += " " + (sysconfig.get_config_var("BLDLIBRARY") or "")
    return libpath


config = sysconfig.get_config_vars()
# for k, v in config.items():
#     if not isinstance(v, str):
#         config[k] = str(v)
include = sysconfig.get_config_var('INCLUDEPY')
cflags  = f"-I '{include}'"
libpath = config['prefix']
print(f"$env:CGO_LDFLAGS = \"-L '{libpath}' -l python311 \" ")
print(f"$env:CGO_CFLAGS = '{cflags}'")
# os.environ.update(config)
# os.system("env")
# sys.exit(0)



print(libpath, cflags)
os.environ['CGO_CFLAGS']   = cflags
os.environ['CGO_CXXFLAGS'] = cflags
os.environ['CGO_LDFLAGS']  = libpath
# os.system(" ".join(cmd))
# os.system("cp ./build/pyutls.so ./python/")

