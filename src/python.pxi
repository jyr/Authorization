cdef extern from "Python.h":
    void PyErr_Clear()
    void PyErr_NoMemory()
    int PyObject_AsCharBuffer(object obj, char **buffer, int *buffer_len) except -1
    int PyObject_AsReadBuffer(object obj, char **buffer, int *buffer_len) except -1
    int PyObject_AsWriteBuffer(object obj, char **buffer, int *buffer_len) except -1
    int PyObject_CheckReadBuffer(object obj) except -1
    int PyMac_GetStr255(object obj, Str255 pbuf) except 0
    int PyString_AsStringAndSize(object obj, char **buffer, int *length) except -1
    char* PyString_AsString(object string) except NULL
    object PyString_FromStringAndSize(char *v, int len)
    object PyUnicode_FromUnicode(UniChar *u, int size)
    cdef UniChar* PyUnicode_AS_UNICODE(object o)
    void* PyMem_Realloc(void *p, int n)
    void* PyMem_Malloc(int n)
    void PyMem_Free(void *p)

    int PyFile_Check(object)
    int PyFile_CheckExact(object)

    ctypedef void* FILE
    int fclose(FILE *)

    object PyFile_FromString(char *, char *)

    void PyFile_SetBufSize(object, int)
    int PyFile_SetEncoding(object, char *)
    object PyFile_FromFile(FILE *, char *, char *, int (*)(FILE *))
    FILE *PyFile_AsFile(object)
    object PyFile_Name(object)
    object PyFile_GetLine(object, int)
    int PyFile_WriteObject(object, object, int)
    int PyFile_SoftSpace(object, int)
    int PyFile_WriteString(char *, object)
    int PyObject_AsFileDescriptor(object)
