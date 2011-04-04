from distutils.core import setup
from distutils.extension import Extension
from Pyrex.Distutils import build_ext

setup(
    name        = 'Authorization',
    version     = '0.1',
    description = "Pythonic wrapper for the Apple's Authorization API",
    long_description = "Pythonic wrapper for Apple's Authorization API in OS X (part of the Security framework).\nIncludes functionality up to Mac OS X 10.2.",
    url         = 'http://undefined.org/python/',
    maintainer  = 'Bob Ippolito',
    maintainer_email = 'bob@redivi.com',
    license     = 'Python',
    platforms   = ['Mac OSX'],
    keywords    = ['Authorization', 'Security', 'su', 'sudo'],
    ext_modules=[
        Extension('Authorization._Authorization', ['src/_Authorization.pyx'], extra_link_args=['-framework', 'Security']),
    ],
    packages = ['Authorization'],
    package_dir = {'Authorization':'lib'},
    cmdclass = {'build_ext': build_ext}
)
