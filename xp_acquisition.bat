@echo off
setlocal ENABLEEXTENSIONS

:: Timestamp for output folder
set hour=%TIME:~0,2%
set hour=%hour: =0%
set minute=%TIME:~3,2%
set timestamp=%DATE:~10,4%-%DATE:~4,2%-%DATE:~7,2%_%hour%%minute%

:: Base directory: where script is run
set basedir=%~dp0
set outdir=%basedir%XP_Forensics_%timestamp%
set hashdir=%outdir%\Hashes
set copiedir=%hashdir%\CopiedDeniedFiles

:: Create output folders
mkdir "%outdir%"
mkdir "%outdir%\RegistryExports"
mkdir "%outdir%\EventLogs"
mkdir "%outdir%\Prefetch"
mkdir "%hashdir%"
mkdir "%copiedir%"

echo [*] Collecting system info...
systeminfo > "%outdir%\systeminfo.txt"
ver > "%outdir%\os_version.txt"
set > "%outdir%\environment_variables.txt"

echo [*] Collecting network configuration...
ipconfig /all > "%outdir%\ipconfig_all.txt"
netstat -ano > "%outdir%\netstat.txt"
arp -a > "%outdir%\arp_table.txt"
route print > "%outdir%\routing_table.txt"

echo [*] Collecting running processes and services...
tasklist > "%outdir%\tasklist.txt"
tasklist /svc > "%outdir%\tasklist_svc.txt"
net start > "%outdir%\services_running.txt"

echo [*] Collecting autorun registry entries...
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" > "%outdir%\autorun_hklm.txt" 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" > "%outdir%\autorun_hkcu.txt" 2>&1

echo [*] Collecting scheduled tasks...
dir "%WINDIR%\Tasks" /a > "%outdir%\scheduled_tasks.txt"

echo [*] Collecting startup folders...
dir "%ALLUSERSPROFILE%\Start Menu\Programs\Startup" /a > "%outdir%\startup_all_users.txt"
dir "%USERPROFILE%\Start Menu\Programs\Startup" /a > "%outdir%\startup_current_user.txt"

echo [*] Collecting user accounts...
net user > "%outdir%\user_accounts.txt"
net localgroup administrators > "%outdir%\admin_group.txt"

echo [*] Copying HOSTS file...
copy "%WINDIR%\system32\drivers\etc\hosts" "%outdir%\hosts.txt" >nul 2>&1

echo [*] Collecting Windows Firewall configuration...
netsh firewall show config > "%outdir%\firewall_config.txt"
netsh firewall show portopening > "%outdir%\firewall_ports.txt"
netsh firewall show allowedprogram > "%outdir%\firewall_programs.txt"
netsh firewall show service > "%outdir%\firewall_services.txt"

echo [*] Exporting full registry hives (.reg)...
reg export HKCR "%outdir%\RegistryExports\HKCR_full.reg"
reg export HKCU "%outdir%\RegistryExports\HKCU_full.reg"
reg export HKLM "%outdir%\RegistryExports\HKLM_full.reg"
reg export HKU "%outdir%\RegistryExports\HKU_full.reg"
reg export HKCC "%outdir%\RegistryExports\HKCC_full.reg"

echo [*] Copying Event Logs (.evt)...
copy "%WINDIR%\system32\config\SecEvent.EVT" "%outdir%\EventLogs\Security.EVT" >nul 2>&1
copy "%WINDIR%\system32\config\AppEvent.EVT" "%outdir%\EventLogs\Application.EVT" >nul 2>&1
copy "%WINDIR%\system32\config\SysEvent.EVT" "%outdir%\EventLogs\System.EVT" >nul 2>&1

echo [*] Listing and copying Prefetch files...
dir /a /s "C:\WINDOWS\Prefetch" > "%outdir%\prefetch_list.txt"
copy /Y "C:\WINDOWS\Prefetch\*.pf" "%outdir%\Prefetch\" >nul 2>&1

echo [*] Listing Recycle Bin contents...
dir /a /s "C:\RECYCLER" > "%outdir%\recycle_bin.txt"

echo [*] Listing IE cache and history...
dir /a /s "%USERPROFILE%\Local Settings\Temporary Internet Files" > "%outdir%\ie_cache.txt"
dir /a /s "%USERPROFILE%\Local Settings\History" > "%outdir%\ie_history.txt"

echo [*] Listing Recent Documents...
dir /a /s "%USERPROFILE%\Recent" > "%outdir%\recent_docs.txt"

echo [*] Exporting list of installed software...
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s > "%outdir%\installed_programs.txt" 2>&1

echo [*] Listing installed drivers...
driverquery /v > "%outdir%\drivers.txt"

echo [*] Computing MD5, SHA1, SHA256 hashes in Program Files...
hashdeep.exe -r -c md5,sha1,sha256 "%ProgramFiles%" > "%hashdir%\programfiles_hashes.txt" 2> "%hashdir%\temp_programfiles_errors.txt"

echo [*] Computing MD5, SHA1, SHA256 hashes in Documents and Settings...
hashdeep.exe -r -c md5,sha1,sha256 "C:\Documents and Settings" > "%hashdir%\user_profiles_hashes.txt" 2> "%hashdir%\temp_user_errors.txt"

echo [*] Computing MD5, SHA1, SHA256 hashes in C:\WINDOWS\Temp...
hashdeep.exe -r -c md5,sha1,sha256 "C:\WINDOWS\Temp" > "%hashdir%\windows_temp_hashes.txt" 2> "%hashdir%\temp_windows_temp_errors.txt"

echo [*] Checking for permission denied errors...
findstr /I "denied" "%hashdir%\temp_user_errors.txt" > "%hashdir%\user_profiles_failed.txt"
del "%hashdir%\temp_user_errors.txt"

findstr /I "denied" "%hashdir%\temp_windows_temp_errors.txt" > "%hashdir%\windows_temp_failed.txt"
del "%hashdir%\temp_windows_temp_errors.txt"

findstr /I "denied" "%hashdir%\temp_programfiles_errors.txt" > "%hashdir%\programfiles_failed.txt"
del "%hashdir%\temp_programfiles_errors.txt"

if exist "%hashdir%\user_profiles_failed.txt" (
    echo [!] Detected access-denied files in user profiles. Attempting recovery...

    for /f "usebackq delims=" %%F in ("%hashdir%\user_profiles_failed.txt") do (
        set "line=%%F"
        call :extractpath "%%F"
    )
)

if exist "%hashdir%\windows_temp_failed.txt" (
    echo [!] Detected access-denied files in Windows\Temp. Attempting recovery...

    for /f "usebackq delims=" %%F in ("%hashdir%\windows_temp_failed.txt") do (
        set "line=%%F"
        call :extractpath "%%F"
    )
)

if exist "%hashdir%\programfiles_failed.txt" (
    echo [!] Detected access-denied files in Program Files. Attempting recovery...

    for /f "usebackq delims=" %%F in ("%hashdir%\programfiles_failed.txt") do (
        set "line=%%F"
        call :extractpath "%%F"
    )
)

if exist "%copiedir%" (
    echo [*] Hashing recovered files (MD5, SHA1, SHA256)...
    hashdeep.exe -r -c md5,sha1,sha256 "%copiedir%" > "%hashdir%\recovered_hashes.txt" 2>nul
)

echo.
echo Forensic collection complete.
echo     Output saved in: %outdir%
pause
goto :eof

:: Extract file path from permission denied line
:extractpath
setlocal
set "full= %~1"
for %%A in (%full%) do set "filepath=%%A"
endlocal & call :copyfile "%filepath%"
goto :eof

:: Copy inaccessible file to recovered folder
:copyfile
setlocal
set "srcfile=%~1"
set "filename=%~nx1"
copy /Y "%srcfile%" "%copiedir%\%filename%" >nul 2>&1
endlocal
goto :eof

