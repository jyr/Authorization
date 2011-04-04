import os, sys, struct, tempfile
from Authorization import Authorization, kAuthorizationFlagDestroyRights

AUTHORIZEDTOOL = "#!%s\n%s" % (sys.executable,
r"""
import os
print os.getuid(), os.geteuid()
os.setuid(0)
print "I'm root!"
""")
   
def main():
    auth = Authorization(destroyflags=(kAuthorizationFlagDestroyRights,))
    fd, name = tempfile.mkstemp('.py')
    os.write(fd, AUTHORIZEDTOOL)
    os.close(fd)
    os.chmod(name, 0700)
    try:
        pipe = auth.executeWithPrivileges(name)
        sys.stdout.write(pipe.read())
        pipe.close()
    finally:
        os.unlink(name)

if __name__=='__main__':
    main()
