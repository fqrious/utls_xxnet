import os, sys, sysconfig, shutil
import re

cmd = ["go", "build", "-buildmode=c-shared", "-o", "build/pyutls.so", "."] #, '-n']
cmd = ["go", "build", "-buildmode=c-shared", "-o", "build/pyutls.so", '-x', "."]

def get_library_path():
    import os.path as op;
    libdir = sysconfig.get_config_var('LIBDIR')
    libpl = sysconfig.get_config_var('LIBPL')
    ldlib = sysconfig.get_config_var('LDLIBRARY')
    fpaths = [op.join(pv, ldlib) for pv in (libdir, libpl)]; 
    paths = set()
    for path in filter(op.exists, fpaths):
        dirpath = os.path.dirname(path)
        paths.add(f"-L '{dirpath}'")
    ldflags = ' '.join(paths)
    ldflags += " " + (sysconfig.get_config_var("BLDLIBRARY") or "")
    ldflags += " -lm"
    return ldflags


config = sysconfig.get_config_vars()
for k, v in config.items():
    if not isinstance(v, str):
        config[k] = str(v)
include = sysconfig.get_config_var('INCLUDEPY')
cflags  = f"-I '{include}' " #+ sysconfig.get_config_var('CFLAGS')
ldflags = get_library_path() + " " + sysconfig.get_config_var('LDFLAGS')

# os.environ.update(config)
# os.system("env")
# sys.exit(0)


cflags += ' ' + os.environ.get("CFLAGS", '')
ldflags += ' ' + os.environ.get("LDFLAGS", '')
print(ldflags, cflags)
os.environ['CGO_CFLAGS']   = cflags
os.environ['CGO_CXXFLAGS'] = cflags
os.environ['CGO_LDFLAGS']  = ldflags
os.system(" ".join(cmd)) and (print("failed"), sys.exit(121))
# os.system("cp ./build/pyutls.so ./python/")
shutil.copyfile('build/pyutls.so', 'python/pyutls.so')

print("done")