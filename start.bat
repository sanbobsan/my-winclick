
title my-userclick
color 97
chcp 65001 >nul
cls

echo my-userclick...
pause

REM Удаление файлов обновлений
del /q /f /s "%SystemRoot%\SoftwareDistribution\Download\*.*" >nul 2>&1
rd /q /s "%SystemRoot%\SoftwareDistribution\Download\" >nul 2>&1
del /q /f /s "%SystemRoot%\SoftwareDistribution\Download" >nul 2>&1
del /q /f /s "%ProgramFiles(x86)%\Microsoft\EdgeUpdate\Download\*.*" >nul 2>&1
rd /q /s "%ProgramFiles(x86)%\Microsoft\EdgeUpdate\Download\" >nul 2>&1

REM Удаление кэша Windows Store
del /q /f /s "%userprofile%\AppData\Local\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalCache\*.*" >nul 2>&1
rd /q /s "%userprofile%\AppData\Local\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalCache\" >nul 2>&1

REM Удаление кэша Проводника
pushd "%LocalAppData%\Microsoft\Windows\Explorer" >nul 2>&1
del /s /q /a:h "IconCache*" "thumbcache*" >nul 2>&1
del /s /q /f "IconCache*" "thumbcache*" >nul 2>&1
popd
pushd "%LocalAppData%" >nul 2>&1
if exist IconCache.db del /a /q IconCache.db >nul 2>&1
if exist IconCache.db-wal del /a /q IconCache.db-wal >nul 2>&1
del /s /q /a:h "IconCache*" "thumbcache*" >nul 2>&1
popd

REM Удаление лишних папок на диске С
for %%F in ("%SystemDrive%\Windows.old" "%SystemDrive%\PerfLogs" "%SystemDrive%\inetpub") do %TI% rd /q /s %%F

REM Удаление ShellBags
for %%k in (Bags BagMRU BagsMRU) do (
reg delete "HKCU\Software\Microsoft\Windows\Shell\%%k" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\ShellNoRoam\%%k" /f >nul 2>&1
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\%%k" /f >nul 2>&1
)

echo "Удаление всех предустановленных приложений"
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-AppxPackage | Where-Object { $_.NonREMovable -eq $false } | ForEach-Object { REMove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue }" >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f >nul 2>&1

REM Удаление OneDrive
taskkill /f /im OneDrive.exe >nul 2>&1
%SystemRoot%\System32\OneDriveSetup.exe /uninstall >nul 2>&1
for %%P in ("%LocalAppData%\OneDrive" "%ProgramData%\Microsoft OneDrive" "%UserProfile%\OneDrive" "%LocalAppData%\Microsoft\OneDrive") do rd /s /q "%%P" >nul 2>&1
for /d %%i in ("%SystemRoot%\WinSxS\amd64_microsoft-windows-onedrive-setup*") do %TI% rd /s /q "%%i"
for %%F in ("OneDriveSetup.exe" "OneDrive.ico") do %TI% del /q "%SystemRoot%\System32\%%F"
if exist "%SystemRoot%\WinSxS\amd64_microsoft-windows-onedrive-setup*" for /d %%i in ("%SystemRoot%\WinSxS\amd64_microsoft-windows-onedrive-setup*") do %TI% rd /s /q "%%i"
reg delete "HKCU\Software\Microsoft\OneDrive" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\OneDrive" /f >nul 2>&1

REM Удаление лишних папок с приложениями в Пуске
rd "%AppData%\Microsoft\Windows\Start Menu\Programs\Accessibility" /Q /S >nul 2>&1
rd "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Accessories\System Tools" /Q /S >nul 2>&1

REM Отключение предложений в поиске Windows (поиска в интернете в меню пуск)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f >nul 2>&1

REM Отключение вкладки Главная в Параметрах Windows 11
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "SettingsPageVisibility" /t REG_SZ /d "hide:home" /f >nul 2>&1

REM Удаление Помощника по удаленному подключению
PowerShell "Start-Process mstsc.exe -ArgumentList '/uninstall' -WindowStyle Hidden -ErrorAction SilentlyContinue"
timeout /t 5 /nobreak >nul 2>&1
taskkill /f /im mstsc.exe >nul 2>&1

echo "Удаление браузера Edge и WebView2"
%TI% taskkill /f /im MicrosoftEdge.exe >nul 2>&1
%TI% taskkill /f /im MicrosoftEdgeUpdate.exe >nul 2>&1
start /wait "" "%~dp0\Work\setup.exe" --uninstall --system-level --force-uninstall --msedge >nul 2>&1
start /wait "" "%~dp0\Work\setup.exe" --uninstall --system-level --force-uninstall --msedgewebview >nul 2>&1

REM Минимизация системных отчетов
"%~dp0\Work\Eventlog" >nul 2>&1

REM Ускорить открытие папок
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v "FolderType" /t REG_SZ /d NotSpecified /f >nul 2>&1
for %%k in (Directory.Audio Directory.Image Directory.Video) do (for %%c in (Enqueue Play) do (reg add "HKCR\SystemFileAssociations\%%k\shell\%%c" /v "LegacyDisable" /t REG_SZ /d "" /f >nul)) >nul 2>&1

REM Отключить GameDVR 
reg add "HKCR\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f >nul 
reg add "HKCR\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\Software\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "Value" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f >nul

REM Функция Возобновить
"%~dp0\Work\vivetool.exe" /disable /id:56517033 >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration" /v "IsResumeAllowed" /t REG_DWORD /d 0 /f >nul 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration" /v "IsOneDriveResumeAllowed" /t REG_DWORD /d 0 /f >

REM Отключение залипания клавиш
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d 506 /f >nul

REM Отключение залипания клавиш
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d 506 /f >nul

REM Скрытие реального TTL
reg add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v DefaultTTL /t REG_DWORD /d 0x41 /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services\Tcpip6\Parameters" /v DefaultTTL /t REG_DWORD /d 0x41 /f >nul

REM Отключение уведомлений и рекомендаций в Система > Уведомления
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f >nul

REM Отключение уведомлений и рекомендаций в Персонализация > Пуск
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Start" /v "ShowRecentList" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Start" /v "ShowFrequentList" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_AccountNotifications" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_Layout" /t REG_DWORD /d 1 /f >nul

REM Отключение рекомендаций в Проводнике
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowCloudFilesInQuickAccess" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecommendations" /t REG_DWORD /d 0 /f >nul

REM Отключение других рекомендаций и предложений
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f >nul

REM Удаление Главная из Проводника 
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Classes\CLSID\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Classes\Wow6432Node\CLSID\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f >nul

REM Удаление Галерея из Проводника 
reg add "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Classes\Wow6432Node\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f >nul 2>&1

REM Удаление Сеть из Проводника 
reg add "HKCU\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f >nul 2>&1

REM Темная тема
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f >nul 2>&1

REM Установка секунд в трее
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSecondsInSystemClock /t REG_DWORD /d 1 /f >nul

REM Установка даты в трее
reg add "HKCU\Control Panel\International" /v sShortDate /t REG_SZ /d "ddd, dd.MM.yy" /f >nul 2>&1

REM Установка Завершить задачу
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" /v "TaskbarEndTask" /t REG_DWORD /d 1 /f >nul

REM Удаление лишних значков
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f >nul 

REM Удаления сжатия обоев
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d 0x64 /f >nul

REM Удаление тени на значках Рабочего стола
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d 0 /f >nul

REM Открывать Проводник в Этот компьютер
reg add  "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 0 /f >nul

REM Показывать расширения файлов
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f >nul