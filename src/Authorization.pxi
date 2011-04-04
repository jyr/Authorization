include "Authorization_h.pxi"

import Enumerators
import MacOS

cdef int CheckError(int _err) except -1:
    if (_err == noErr):
        return 0
    if _err in Enumerators.AuthorizationErrors:
        err = Enumerators.AuthorizationErrors.fromValue(_err)
        raise MacOS.Error(_err, err.name, err.doc)
    else:
        PyMac_Error(_err)
        #raise
    return -1
    
cdef UInt32 createFlags(flags):
    cdef UInt32 _flags
    if isinstance(flags, (int, long)):
        _flags = flags
    else:
        _flags = 0
        for flag in flags:
            _flags = _flags | flag
    return _flags 

cdef object createAuthorizationItem(c_AuthorizationItem *item):
    if item.value == NULL:
        value = None
    else:
        value = PyString_FromStringAndSize(<char*>item.value, item.valueLength)
    return AuthorizationItem(item.name, value, item.flags)

cdef object createAuthorizationItemSet(c_AuthorizationItemSet *itemset):
    cdef int i
    lst = []
    for i in range(itemset.count):
        lst.append(createAuthorizationItem(&itemset.items[i]))
    return AuthorizationItemSet(lst)

cdef class AuthorizationItem:
    cdef c_AuthorizationItem item
    cdef readonly object name
    cdef readonly object value
    cdef readonly object flags
    def __cinit__(self, name, value=None, flags=()):
        self.item.name = PyString_AsString(name)
        if value is None:
            self.item.valueLength = 0
            self.item.value = NULL
        else:
            PyObject_CheckReadBuffer(value)
            PyObject_AsReadBuffer(value, <char **>&self.item.value, <int *>&self.item.valueLength)
        self.item.flags = createFlags(flags)
        self.name = name
        self.value = value
        self.flags = flags

    def __repr__(self):
        return "(%r, %r, %r)" % (self.name, self.value, self.flags)

cdef class AuthorizationItemSet:
    cdef c_AuthorizationItemSet itemset
    cdef object _itemRefs

    def __cinit__(self, items):
        lst = []
        for item in items:
            if not isinstance(item, AuthorizationItem):
                item = AuthorizationItem(*item)
            lst.append(item)
        self._itemRefs = tuple(lst)
        self.itemset.count = len(lst)
        self.itemset.items = NULL
        # XXX - assume pointer length is 4 bytes
        self.itemset.items = <c_AuthorizationItem *>PyMem_Malloc(4 * self.itemset.count)

    def __dealloc__(self):
        if self.itemset.items != NULL:
            PyMem_Free(self.itemset.items)
            self.itemset.items = NULL
            self.itemset.count = 0

    def __repr__(self):
        return repr(self._itemRefs)

    def __getitem__(self, item):
        return self._itemRefs[item]

    def __len__(self):
        return self.itemset.count

    def __iter__(self):
        return iter(self._itemRefs)

cdef class _AuthorizationBase:
    cdef AuthorizationRef authorization
    cdef public UInt32 destroyflags

    def external(self):
        cdef OSStatus err
        cdef AuthorizationExternalForm extForm
        if self.authorization == NULL:
            raise ValueError, "Invalidated"
        err = AuthorizationMakeExternalForm(self.authorization, &extForm)
        CheckError(err)
        return PyString_FromStringAndSize(<char *>&extForm, Enumerators.kAuthorizationExternalFormLength)
    
    def invalidate(self):
        self.authorization = NULL

    def copyRights(self, rights=(), environment=(), flags=()):
        cdef OSStatus err
        cdef AuthorizationItemSet _rights
        cdef AuthorizationItemSet _environment
        cdef c_AuthorizationItemSet *__rights
        cdef c_AuthorizationItemSet *__environment
        cdef UInt32 _flags
        cdef c_AuthorizationItemSet *_outrights
        cdef object rval
        if self.authorization == NULL:
            raise ValueError, "Invalidated"
        _rights = AuthorizationItemSet(rights)
        _environment = AuthorizationItemSet(environment)
        __rights = &_rights.itemset
        if environment:
            __environment = &_environment.itemset
        else:
            __environment = NULL
        _flags = createFlags(flags)
        err = AuthorizationCopyRights(self.authorization, __rights, __environment, _flags, &_outrights)
        CheckError(err)
        rval = createAuthorizationItemSet(_outrights)
        AuthorizationFreeItemSet(_outrights)
        return rval
        
    def copyInfo(self, tag=None):
        cdef OSStatus err
        cdef c_AuthorizationItemSet *_outrights
        cdef char *_tag
        if self.authorization == NULL:
            raise ValueError, "Invalidated"
        if tag is None:
            _tag = NULL
        else:
            _tag = tag
        err = AuthorizationCopyInfo(self.authorization, tag, &_outrights)
        CheckError(err)
        rval = createAuthorizationItemSet(_outrights)
        AuthorizationFreeItemSet(_outrights)
        return rval

    def executeWithPrivileges(self, path, *arguments):
        cdef OSStatus err
        cdef FILE *_commPipe
        cdef char *_pathToTool
        cdef AuthorizationFlags _options
        cdef char **_arguments
        cdef int _size
        cdef char **argvlist
        cdef int i, argc
        if self.authorization == NULL:
            raise ValueError, "Invalidated"
        _options = 0

        path = path.encode('utf-8')
        PyObject_AsReadBuffer(path, &_pathToTool, &_size)
        argv = []
        for elem in arguments:
            argv.append(elem.encode('utf-8'))
        argc = len(argv)
        argvlist = <char **>PyMem_Malloc(4 * (argc+1))
        if (argvlist == NULL):
            raise MemoryError, "Couldn't allocate memory for argvlist"
        for i in range(argc):
            PyObject_AsReadBuffer(argv[i], &(argvlist[i]), &_size)
        argvlist[argc] = NULL;
        err = AuthorizationExecuteWithPrivileges(self.authorization, _pathToTool, _options, argvlist, &_commPipe)
        PyMem_Free(argvlist);
        CheckError(err)
        return PyFile_FromFile(_commPipe, "<authtool>", "r+b", fclose)

    #def getInfo(tag=None):
    #    AuthorizationCopyInfo(self.authorization, tag, info..)
        
cdef class Authorization(_AuthorizationBase):
    cdef AuthorizationItemSet rights
    cdef AuthorizationItemSet environment
    cdef readonly UInt32 flags
    def __cinit__(self, rights=(), environment=(), flags=(), destroyflags=()):
        cdef OSStatus err
        cdef c_AuthorizationItemSet *_rights
        cdef c_AuthorizationItemSet *_environment
        self.authorization = NULL
        self.rights = AuthorizationItemSet(rights)
        self.environment = AuthorizationItemSet(environment)
        _rights = &self.rights.itemset
        if environment:
            _environment = &self.environment.itemset
        else:
            _environment = NULL
        self.flags = createFlags(flags)
        self.destroyflags = createFlags(destroyflags)
        err = AuthorizationCreate(_rights, _environment, self.flags, &self.authorization)
        CheckError(err)

    def __dealloc__(self):
        cdef OSStatus err
        if self.authorization != NULL:
            err = AuthorizationFree(self.authorization, self.destroyflags)
            self.authorization = NULL
            #CheckError(err)


cdef class ExternalAuthorization(_AuthorizationBase):
    def __cinit__(self, external, destroyflags=()):
        cdef OSStatus err
        cdef int _buffer_len
        cdef char *_buffer
        self.authorization = NULL
        self.destroyflags = createFlags(destroyflags)
        PyObject_CheckReadBuffer(external)
        PyObject_AsReadBuffer(external, &_buffer, &_buffer_len)
        if _buffer_len != Enumerators.kAuthorizationExternalFormLength:
            raise ValueError, "External form must be exactly kAuthorizationExternalFormLength bytes long"
        err = AuthorizationCreateFromExternalForm(<AuthorizationExternalForm*>&_buffer, &self.authorization)
        CheckError(err)

cdef class PrivilegedReference(_AuthorizationBase):
    cdef readonly UInt32 flags
    def __cinit__(self, flags=(), destroyflags=()):
        cdef OSStatus err
        self.authorization = NULL
        self.flags = createFlags(flags)
        self.destroyflags = createFlags(destroyflags)
        err = AuthorizationCopyPrivilegedReference(&self.authorization, self.flags)
        CheckError(err)
     
def checkAuthorization(rights=(), environment=(), flags=()):
    cdef OSStatus err
    cdef AuthorizationItemSet _rights
    cdef AuthorizationItemSet _environment
    cdef c_AuthorizationItemSet *__rights
    cdef c_AuthorizationItemSet *__environment
    cdef UInt32 _flags
    _rights = AuthorizationItemSet(rights)
    _environment = AuthorizationItemSet(environment)
    __rights = &_rights.itemset
    if environment:
        __environment = &_environment.itemset
    else:
        __environment = NULL

    _flags = createFlags(flags)
    err = AuthorizationCreate(__rights, __environment, _flags, NULL)
    CheckError(err)
