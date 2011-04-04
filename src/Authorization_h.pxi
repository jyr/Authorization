cdef extern from "include_Security.h":
    ctypedef UInt32 AuthorizationFlags
    ctypedef void *AuthorizationRef
    ctypedef char *AuthorizationString
    ctypedef struct c_AuthorizationItem "AuthorizationItem":
        AuthorizationString name
        UInt32 valueLength
        void *value
        UInt32 flags
    ctypedef struct c_AuthorizationItemSet "AuthorizationItemSet":
        UInt32 count
        c_AuthorizationItem *items
    ctypedef struct AuthorizationExternalForm:
        char bytes[32]
    ctypedef c_AuthorizationItemSet AuthorizationRights
    ctypedef c_AuthorizationItemSet AuthorizationEnvironment
    OSStatus AuthorizationCreate(AuthorizationRights *rights, AuthorizationEnvironment *environment, 
        AuthorizationFlags flags, AuthorizationRef *authorization)
    OSStatus AuthorizationFree(AuthorizationRef authorization, AuthorizationFlags flags)
    OSStatus AuthorizationCopyRights(AuthorizationRef authorization, AuthorizationRights *rights, 
        AuthorizationEnvironment *environment, AuthorizationFlags flags, AuthorizationRights **authorizedRights)
    OSStatus AuthorizationCopyInfo(AuthorizationRef authorization, AuthorizationString tag, c_AuthorizationItemSet **info)
    OSStatus AuthorizationMakeExternalForm(AuthorizationRef authorization, AuthorizationExternalForm *extForm)
    OSStatus AuthorizationCreateFromExternalForm(AuthorizationExternalForm *, AuthorizationRef *authorization)
    OSStatus AuthorizationFreeItemSet(c_AuthorizationItemSet *set)
    OSStatus AuthorizationExecuteWithPrivileges(AuthorizationRef authorization, char *pathToTool, AuthorizationFlags options,
        char **arguments, FILE **communicationsPipe)
    OSStatus AuthorizationCopyPrivilegedReference(AuthorizationRef *authorization, AuthorizationFlags flags)
    
