# nimpersonate
Impersonate Windows tokens in Nim based on https://github.com/sensepost/impersonate but with Nt* function calls.

## Usage
```powershell
Usage:
  nimpersonate {SUBCMD}  [sub-command options & parameters]
where {SUBCMD} is one of:
  help    print comprehensive or per-cmd help
  list    List available tokens
  thread  Impersonate thread
  runcmd  Spawn cmd.exe as impersonated user
```


### list
```powershell
PS> .\nimpersonate.exe list
[*] Adjusting privileges #1
[*] Adjusting privileges #2
[*] Listing tokens details
[PID: 5532 ]  [User: robb.stark     ]  [TokenType: primary    ]  [Integrity: Low   ]  [ImpersonationLevel: N/A]
[PID: 1416 ]  [User: NETWORK SERVICE]  [TokenType: impersonate]  [Integrity: System]  [ImpersonationLevel: SecurityIdentification]
[PID: 4924 ]  [User: eddard.stark   ]  [TokenType: primary    ]  [Integrity: Low   ]  [ImpersonationLevel: N/A]
[PID: 784  ]  [User: SYSTEM         ]  [TokenType: impersonate]  [Integrity: System]  
[SNIP]
```

### thread
```powershell
PS> .\nimpersonate.exe thread -u system
[*] Adjusting privileges #1
[*] Adjusting privileges #2
[*] Selected token: (pid: 1808, tokentype: "impersonate", tokenhandle: 1124, user: "SYSTEM", integrity: "System", impersonation: "SecurityImpersonation")
[*] Duplicating target thread token
[*] Thread Owner : S-1-5-18
```

### runcmd
Only works with current loggedon user and system, doesn't spawn a console for another RDP'ed user for some reason. 
