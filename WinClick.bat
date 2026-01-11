@echo off
	cls
	Title WinClick by MartyFiles
Rem Начало
	Color 0f
	Mode 20,1
	chcp 65001 >nul
	echo "%~dp0\Work" | findstr /r "[()!]" >nul && echo Путь до .bat содержит недопустимые символы. && timeout /t 7 >nul && exit
	SetLocal EnableDelayedExpansion
	cd /d "%~dp0\Work"
	reg query "HKU\S-1-5-19" >nul 2>&1 || (Helper /Elevate "%~f0" && exit || %ch% {red} Права не выданы.{\n#}&& pause>nul && exit)

Rem Установка переменных
	set "TI=NSudoLG -U:T -P:E -ShowWindowMode:Hide -Wait cmd.exe /c"
	
REM Принудительный запуск в CMD
	reg query "HKCU\Console\%%%%Startup" /v DelegationConsole | find /i "B23D10C0" >nul 2>&1 || (
	tasklist /fi "imagename eq WindowsTerminal.exe" 2>nul | find /i "WindowsTerminal" >nul 2>&1 && (
	for %%p in (DelegationConsole DelegationTerminal) do reg add "HKCU\Console\%%%%Startup" /v "%%p" /t reg_sz /d "{B23D10C0-E52E-411E-9D5B-C09FDF709C7D}" /f >nul 2>&1
	start "" "%~f0" && exit
))


Rem Скрытие консоли и проверка версии
	call :WinVer && exit /b
	start /b "" Helper /Overlay "Скоро ваша Windows 11 станет лучше (Надписи не отредактированы)" /Font "Impact" /Size "40"
	Helper /HideConsole
	timeout /t 3 /nobreak >nul 2>&1
	
	start /b "" Helper /Overlay "Удаление мусора `n`n [1/13]" /Font "Impact" /Size "40"
	sc query wuauserv | find /i "RUNNING" >nul 2>&1 && (
		net stop wuauserv >nul 2>&1
		timeout /t 1 /nobreak >nul 2>&1
		sc query wuauserv | find /i "RUNNING" >nul 2>&1 && %TI% net stop wuauserv
	)

Rem Удаление кэша Windows Store
	del /q /f /s "%userprofile%\AppData\Local\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalCache\*.*" >nul 2>&1
	rd /q /s "%userprofile%\AppData\Local\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalCache\" >nul 2>&1

Rem Удаление ShellBags
for %%k in (Bags BagMRU BagsMRU) do (
    reg delete "HKCU\Software\Microsoft\Windows\Shell\%%k" /f >nul 2>&1
    reg delete "HKCU\Software\Microsoft\Windows\ShellNoRoam\%%k" /f >nul 2>&1
    reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\%%k" /f >nul 2>&1
)

	start /b "" Helper /Overlay "Удаление всех предустановленных приложений `n`n[2/13]" /Font "Impact" /Size "40"
	PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-AppxPackage | Where-Object { $_.NonRemovable -eq $false } | ForEach-Object { Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue }" >nul 2>&1
	reg add "HKLM\Software\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f >nul 2>&1
Rem Удаление OneDrive
	taskkill /f /im OneDrive.exe >nul 2>&1
	%SystemRoot%\System32\OneDriveSetup.exe /uninstall >nul 2>&1
	for %%P in ("%LocalAppData%\OneDrive" "%ProgramData%\Microsoft OneDrive" "%UserProfile%\OneDrive" "%LocalAppData%\Microsoft\OneDrive") do rd /s /q "%%P" >nul 2>&1
	for /d %%i in ("%SystemRoot%\WinSxS\amd64_microsoft-windows-onedrive-setup*") do %TI% rd /s /q "%%i"
	for %%F in ("OneDriveSetup.exe" "OneDrive.ico") do %TI% del /q "%SystemRoot%\System32\%%F"
	if exist "%SystemRoot%\WinSxS\amd64_microsoft-windows-onedrive-setup*" for /d %%i in ("%SystemRoot%\WinSxS\amd64_microsoft-windows-onedrive-setup*") do %TI% rd /s /q "%%i"
	reg delete "HKCU\Software\Microsoft\OneDrive" /f >nul 2>&1
	reg delete "HKLM\Software\Microsoft\OneDrive" /f >nul 2>&1
Rem Удаление лишних папок с приложениями в Пуске
	rd "%AppData%\Microsoft\Windows\Start Menu\Programs\Accessibility" /Q /S >nul 2>&1
	rd "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Accessories\System Tools" /Q /S >nul 2>&1
Rem Отключение предложений в поиске Windows (поиска в интернете в меню пуск)
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f >nul 2>&1
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f >nul 2>&1
Rem Отключение вкладки Главная в Параметрах Windows 11
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "SettingsPageVisibility" /t REG_SZ /d "hide:home" /f >nul 2>&1
Rem Удаление Помощника по удаленному подключению
	PowerShell "Start-Process mstsc.exe -ArgumentList '/uninstall' -WindowStyle Hidden -ErrorAction SilentlyContinue"
	timeout /t 5 /nobreak >nul 2>&1
	taskkill /f /im mstsc.exe >nul 2>&1

	start /b "" Helper /Overlay "Удаление браузера Edge и WebView2 `n`n [3/13]" /Font "Impact" /Size "40"
	%TI% taskkill /f /im MicrosoftEdge.exe >nul 2>&1
	%TI% taskkill /f /im MicrosoftEdgeUpdate.exe >nul 2>&1
	start /wait "" "%~dp0\Work\setup.exe" --uninstall --system-level --force-uninstall --msedge >nul 2>&1
	start /wait "" "%~dp0\Work\setup.exe" --uninstall --system-level --force-uninstall --msedgewebview >nul 2>&1
	
	start /b "" Helper /Overlay "Удаление дополнительных компонентов `n`n [5/13]" /Font "Impact" /Size "40"
	for %%C in (
		Microsoft.Windows.Notepad.System
		Microsoft.Windows.PowerShell.ISE
		Print.Management.Console
		VBSCRIPT
		OpenSSH.Client
		Hello.Face
		MathRecognizer
		InternetExplorer
		StepsRecorder
		Media.WindowsMediaPlayer
		Microsoft.Wallpapers.Extended
	) do (
		for /f "tokens=2 delims=:" %%A in ('dism /Online /Get-Capabilities ^| findstr /I "%%C"') do (
			set "cap=%%A"
			set "cap=!cap:~1!"
			dism /Online /Remove-Capability /CapabilityName:!cap! /NoRestart
		)
	) >nul 2>&1

	start /b "" Helper /Overlay "Отключение лишнего в Планировщике задач... `n`n [6/13]" /Font "Impact" /Size "40"
	timeout /t 3 /nobreak >nul 2>&1
	chcp 866 >nul
for %%T in (
    "\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Automated)" "\Microsoft\Windows\AppID\EDP Policy Manager" "\Microsoft\Windows\AppID\PolicyConverter"
    "\Microsoft\Windows\Application Experience\MareBackup" "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser Exp"
    "\Microsoft\Windows\Application Experience\PcaPatchDbTask" "\Microsoft\Windows\Application Experience\SdbinstMergeDbTask" "\Microsoft\Windows\Application Experience\StartupAppTask"
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater" "\Microsoft\Windows\Application Experience\ProgramInventoryUpdater" "\Microsoft\Windows\ApplicationData\appuriverifierdaily"
    "\Microsoft\Windows\ApplicationData\appuriverifierinstall" "\Microsoft\Windows\ApplicationData\DsSvcCleanup" "\Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup"
    "\Microsoft\Windows\AppxDeploymentClient\UCPD velocity" "\Microsoft\Windows\Autochk\Proxy" "\Microsoft\Windows\AutoLogger\AutoLogger-Diagtrack-Listener" "\Microsoft\Windows\AutoLogger\AutoLogger-FileSizeTracking"
    "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" "\Microsoft\Windows\CEIP\Uploader" "\Microsoft\Windows\CertificateServicesClient\AikCertEnrollTask" "\Microsoft\Windows\CertificateServicesClient\CryptoPolicyTask"
	"\Microsoft\Windows\CertificateServicesClient\KeyPreGenTask" "\Microsoft\Windows\CertificateServicesClient\SystemTask" "\Microsoft\Windows\Cleanup\UpdateCleanup" "\Microsoft\Windows\Clip\License Validation" "\Microsoft\Windows\Clip\LicenseImdsIntegration"
    "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" "\Microsoft\Windows\CloudExperienceHost\SyncHost" "\Microsoft\Windows\CloudRestore\Backup" "\Microsoft\Windows\CloudRestore\Restore" "\Microsoft\Windows\ContactSupport\Scheduled"
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
    "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" "\Microsoft\Windows\Device Information\Device" "\Microsoft\Windows\Device Information\Device User"
	"\Microsoft\Windows\Device Setup\Driver Recovery on Reboot" "\Microsoft\Windows\Device Setup\Metadata Refresh" "\Microsoft\Windows\DeviceDirectoryClient\HandleCommand" "\Microsoft\Windows\DeviceDirectoryClient\HandleWnsCommand"
    "\Microsoft\Windows\DeviceDirectoryClient\IntegrityCheck" "\Microsoft\Windows\DeviceDirectoryClient\LocateCommandUserSession" "\Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceAccountChange" "\Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceLocationRightsChange"
    "\Microsoft\Windows\DeviceDirectoryClient\RegisterDevicePeriodic24" "\Microsoft\Windows\DeviceDirectoryClient\RegisterDevicePolicyChange" "\Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceProtectionStateChanged"
    "\Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceSettingChange" "\Microsoft\Windows\DeviceDirectoryClient\RegisterUserDevice" "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" "\Microsoft\Windows\Diagnosis\Scheduled"
    "\Microsoft\Windows\Diagnosis\UnexpectedCodepath" "\Microsoft\Windows\DiskCleanup\SilentCleanup" "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"
    "\Microsoft\Windows\DiskDiagnostic\DiagnosticResolver" "\Microsoft\Windows\DiskDiagnostic\DiskDiagnostic" "\Microsoft\Windows\DiskFootprint\Diagnostics" "\Microsoft\Windows\DiskFootprint\StorageSense" "\Microsoft\Windows\DUSM\dusmtask" "\Microsoft\Windows\ErrorReporting\QueueReporting"
    "\Microsoft\Windows\ErrorReporting\KernelCeipTask" "\Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" "\Microsoft\Windows\Feedback\Siuf\DmClient" "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioUpload"
    "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioRun" "\Microsoft\Windows\Feedback\Siuf\DmClientOnUserSignIn" "\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync" "\Microsoft\Windows\FileHistory\File History (maintenance mode)"
    "\Microsoft\Windows\Help\OEMSupport" "\Microsoft\Windows\Help\WindowsHelpUpdateTask" "\Microsoft\Windows\HelloFace\FODCleanupTask" "\Microsoft\Windows\HelloFace\FeatureCleanup" "\Microsoft\Windows\input\InputSettingsRestoreDataAvailable"
    "\Microsoft\Windows\input\LocalUserSyncDataAvailable" "\Microsoft\Windows\input\MouseSyncDataAvailable" "\Microsoft\Windows\input\PenSyncDataAvailable" "\Microsoft\Windows\input\RemoteMouseSyncDataAvailable" "\Microsoft\Windows\input\RemotePenSyncDataAvailable"
    "\Microsoft\Windows\input\RemoteTouchpadSyncDataAvailable" "\Microsoft\Windows\input\TouchpadSyncDataAvailable" "\Microsoft\Windows\InstallService\WakeUpAndContinueUpdates" "\Microsoft\Windows\InstallService\WakeUpAndScanForUpdates"
    "\Microsoft\Windows\International\Synchronize Language Settings" "\Microsoft\Windows\LanguageComponentsInstaller\Installation" "\Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" "\Microsoft\Windows\LanguageComponentsInstaller\Uninstallation"
    "\Microsoft\Windows\License Manager\TempSignedLicenseExchange" "\Microsoft\Windows\Location\WindowsActionDialog" "\Microsoft\Windows\Maintenance\WinSAT" "\Microsoft\Windows\Maps\MapsToastTask"
    "\Microsoft\Windows\Maps\MapsUpdateTask" "\Microsoft\Windows\MemoryDiagnostic\AutomaticOfflineMemoryDiagnostic" "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" "\Microsoft\Windows\NlaSvc\WiFiTask"
    "\Microsoft\Windows\Offline Files\Background Synchronization" "\Microsoft\Windows\Offline Files\Logon Synchronization" "\Microsoft\Windows\PCRPF\PCR Prediction Framework Firmware Update Task" "\Microsoft\Windows\PerformanceTrace\WhesvcToast"
    "\Microsoft\Windows\PI\Secure-Boot-Update" "\Microsoft\Windows\PI\Sqm-Tasks" "\Microsoft\Windows\Pluton\Pluton-Ksp-Provisioning" "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" "\Microsoft\Windows\Printing\EduPrintProv"
    "\Microsoft\Windows\Printing\PrintJobCleanupTask" "\Microsoft\Windows\PushToInstall\LoginCheck" "\Microsoft\Windows\PushToInstall\Registration" "\Microsoft\Windows\Ras\MobilityManager" "\Microsoft\Windows\ReFsDedupSvc\Initialization"
    "\Microsoft\Windows\Registry\RegIdleBackup" "\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" "\Microsoft\Windows\Search\IndexerDiagnosticsTask"
    "\Microsoft\Windows\Search\SearchIndexerMaintenance" "\Microsoft\Windows\Setup\SetupCleanupTask" "\Microsoft\Windows\SharedPC\Account Cleanup" "\Microsoft\Windows\Shell\FamilySafetyMonitor" "\Microsoft\Windows\Shell\FamilySafetyRefreshTask"
    "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance" "\Microsoft\Windows\Shell\ThemeAssetTask_SyncFODState" "\Microsoft\Windows\Shell\ThemesSyncedImageDownload" "\Microsoft\Windows\Shell\UndockedFlightingUpdate" "\Microsoft\Windows\Shell\UpdateUserPictureTask"
	"\Microsoft\Windows\Storage Tiers Management\Storage Tiers Optimization" "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" "\Microsoft\Windows\Subscription\LicenseAcquisition" "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask" "\Microsoft\Windows\Sysmain\HybridDriveCacheRebalance"
    "\Microsoft\Windows\Sysmain\HybridDriveCachePrepopulate" "\Microsoft\Windows\UPnP\UPnPHostConfig" "\Microsoft\Windows\UpdateOrchestrator\CleanupUpdateTask" "\Microsoft\Windows\User Profile Service\HiveUploadTask" "\Microsoft\Windows\WaaSMedic\PerformRemediation"
    "\Microsoft\Windows\WaaSMedic\ScanForUpdates" "\Microsoft\Windows\WaaSMedic\WsusScan" "\Microsoft\Windows\Windows Error Reporting\QueueReporting" "\Microsoft\Windows\Windows Error Reporting\ReportQueue" "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange"
    "\Microsoft\Windows\WindowsAI\Recall\InitialConfiguration" "\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration" "\Microsoft\Windows\WindowsAI\Settings\InitialConfiguration" "\Microsoft\Windows\WindowsAI\Copilot\CopilotDataCollectionTask"
    "\Microsoft\Windows\WindowsAI\Insights\InsightsDataCollectionTask" "\Microsoft\Windows\WindowsUpdate\Refresh Group Policy Cache" "\Microsoft\Windows\WlanSvc\CDSSync" "\Microsoft\Windows\WOF\WIM-Hash-Management" "\Microsoft\Windows\WOF\WIM-Hash-Validation"
    "\Microsoft\Windows\Workplace Join\Automatic-Device-Join" "\Microsoft\Windows\Workplace Join\Device-Sync" "\Microsoft\Windows\Workplace Join\Recovery-Check" "\Microsoft\Windows\UNP\RunCampaignManager" "\MicrosoftEdgeUpdateTaskMachineCore"
    "\MicrosoftEdgeUpdateTaskMachineUA" "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" "\Microsoft\Windows\Windows Defender Cleanup" "\Microsoft\Windows\Windows Defender Scheduled Scan" "\Microsoft\Windows\Windows Defender Verification"
) do (
    schtasks /Change /TN %%T /Disable >nul 2>&1
)
	chcp 65001 >nul

	start /b "" Helper /Overlay "Оптимизация параметров `n`n [7/13]" /Font "Impact" /Size "40"
Rem Отключение гибернации
    powercfg -h off >nul 2>&1
	reg add "HKLM\System\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d 0x0 /f >nul 2>&1
Rem Отключение зарезервированного хранилища
	Dism /Online /Set-ReservedStorageState /State:Disabled >nul 2>&1
Rem Отключение точек восстановления
	vssadmin resize shadowstorage /on=c: /for=c: /maxsize=1%% >nul 2>&1
	PowerShell -Command "Disable-ComputerRestore -Drive '%SystemDrive%\'" >nul 2>&1
	vssadmin delete shadows /all /quiet >nul 2>&1
	reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "RPSessionInterval" /f >nul 2>&1
Rem Отложенный запуск автоматических служб
	for %%p in (EventSystem NlaSvc) do reg add "HKLM\System\CurrentControlSet\Services\%%p" /v "DelayedAutostart" /t reg_dword /d 1 /f >nul 2>&1
Rem Минимизация системных отчетов
	"%~dp0\Work\Eventlog" >nul 2>&1
Rem Увеличение порога разделения SVC
    PowerShell "$key = 'HKLM:\SYSTEM\CurrentControlSet\Control'; if (-not (Get-ItemProperty -Path $key -Name 'SvcHostSplitThresholdInKB' -ErrorAction SilentlyContinue)) { Write-Output ' Параметра SvcHostSplitThresholdInKB нет, отмена действий'; Pause; Exit } elseif (-not (Get-ItemProperty -Path $key -Name 'SvcHostSplitThresholdInKB_orig' -ErrorAction SilentlyContinue)) { Rename-ItemProperty -Path $key -Name 'SvcHostSplitThresholdInKB' -NewName 'SvcHostSplitThresholdInKB_orig'; $mem = (Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize + 1024000; Set-ItemProperty -Path $key -Name 'SvcHostSplitThresholdInKB' -Value $mem -Type DWord }
Rem Ускорить открытие папок
	reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v "FolderType" /t REG_SZ /d NotSpecified /f >nul 2>&1
	for %%k in (Directory.Audio Directory.Image Directory.Video) do (for %%c in (Enqueue Play) do (reg add "HKCR\SystemFileAssociations\%%k\shell\%%c" /v "LegacyDisable" /t REG_SZ /d "" /f >nul)) >nul 2>&1
Rem Отключить GameDVR 
    reg add "HKCR\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f >nul 
    reg add "HKCR\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f >nul
	reg add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f >nul
	reg add "HKLM\Software\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "Value" /t REG_DWORD /d 0 /f >nul
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f >nul
	"%~dp0\Work\vivetool.exe" /disable /id:56517033 >nul
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration" /v "IsResumeAllowed" /t REG_DWORD /d 0 /f >nul 
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration" /v "IsOneDriveResumeAllowed" /t REG_DWORD /d 0 /f >nul
	
	start /b "" Helper /Overlay "Настройка Центра обновления Windows `n`n [8/13]" /Font "Impact" /Size "40"
	timeout /t 5 /nobreak >nul 2>&1
Rem Запрет автоматических обновлений
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f >nul

	start /b "" Helper /Overlay "Применение полезных твиков `n`n [9/13]" /Font "Impact" /Size "40"
	timeout /t 3 /nobreak >nul 2>&1
Rem Отключение UAC
    for %%a in (EnableLUA PromptOnSecureDesktop EnableVirtualization ConsentPromptBehaviorAdmin) do reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "%%a" /t REG_DWORD /d 0 /f >nul
    for %%b in (batfile cmdfile exefile cplfile mscfile) do reg add "HKLM\Software\Classes\%%b\shell\runas" /v "ProgrammaticAccessOnly" /t REG_SZ /d "" /f >nul
    reg add "HKLM\Software\Classes\exefile\shell\runas2" /v "ProgrammaticAccessOnly" /t REG_SZ /d "" /f >nul
Rem Административная учетная запись
	net user "%UserName%" /active:yes >nul
Rem Снятие региональных ограничений
	sc start TrustedInstaller >nul
	%TI% ren "%SystemRoot%\System32\IntegratedServicesRegionPolicySet.json" IntegratedServicesRegionPolicySet.json_bak
	%TI% copy "%~dp0\Work\IntegratedServicesRegionPolicySet.json" "%SystemRoot%\System32"
Rem Принудительное завершение программ при зависании
	reg add "HKCR\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d 1 /f >nul
Rem Отключение Удаленного помощника
	reg add "HKLM\System\ControlSet001\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f >nul
	reg add "HKLM\System\ControlSet001\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d 0 /f >nul
	reg add "HKLM\System\ControlSet001\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f >nul
	reg add "HKLM\System\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp" /v "UserAuthentication" /t REG_DWORD /d 0 /f >nul
Rem Отключение залипания клавиш
	reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d 506 /f >nul
Rem Скрытие реального TTL
	reg add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v DefaultTTL /t REG_DWORD /d 0x41 /f >nul
	reg add "HKLM\SYSTEM\ControlSet001\Services\Tcpip6\Parameters" /v DefaultTTL /t REG_DWORD /d 0x41 /f >nul
Rem Отключение уведомлений и рекомендаций в Система > Уведомления
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f >nul
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f >nul
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f >nul
Rem Отключение уведомлений и рекомендаций в Персонализация > Пуск
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Start" /v "ShowRecentList" /t REG_DWORD /d 0 /f >nul
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Start" /v "ShowFrequentList" /t REG_DWORD /d 0 /f >nul
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f >nul
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d 0 /f >nul
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_AccountNotifications" /t REG_DWORD /d 0 /f >nul
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_Layout" /t REG_DWORD /d 1 /f >nul
Rem Отключение рекомендаций в Проводнике
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f >nul
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 0 /f >nul
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowCloudFilesInQuickAccess" /t REG_DWORD /d 0 /f >nul
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecommendations" /t REG_DWORD /d 0 /f >nul
Rem Отключение других рекомендаций и предложений
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f >nul
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f >nul
Rem Установка DNS на Wi-Fi адаптеры
set adapters=Ethernet "Беспроводная сеть" "Бездротова мережа" "Wireless network"
for %%a in (!adapters!) do (
	netsh interface ipv4 set dns name=%%a static 8.8.8.8 >nul
	netsh interface ip add dns name=%%a address=8.8.4.4 index=2 >nul
)

	start /b "" Helper /Overlay "Установки драйверов не будет `n`n [10/13]" /Font "Impact" /Size "40"
	timeout /t 3 /nobreak >nul 2>&1


	start /b "" Helper /Overlay "Установка Visual C++ и DirectX `n`n [11/13]" /Font "Impact" /Size "40"
	start "" /wait "%~dp0\Work\VisualCppRedist_AIO_x86_x64.exe" /aiA /gm2
	start "" /wait "%~dp0\Work\DirectX.exe"
	
	
	start /b "" Helper /Overlay "Установка визуальных твиков `n`n [12/13]" /Font "Impact" /Size "40"
    timeout /t 5 /nobreak >nul 2>&1
Rem Удаление Главная из Проводника 
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d 1 /f >nul
    reg add "HKCU\Software\Classes\CLSID\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f >nul
    reg add "HKCU\Software\Classes\Wow6432Node\CLSID\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f >nul
Rem Удаление Галерея из Проводника 
    reg add "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f >nul 2>&1
    reg add "HKCU\Software\Classes\Wow6432Node\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f >nul 2>&1
Rem Удаление Сеть из Проводника 
	reg add "HKCU\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f >nul 2>&1
Rem Темная тема
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /t REG_DWORD /d 0 /f >nul 2>&1
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f >nul 2>&1

Rem Установка секунд в трее
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSecondsInSystemClock /t REG_DWORD /d 1 /f >nul
Rem Установка даты в трее
    reg add "HKCU\Control Panel\International" /v sShortDate /t REG_SZ /d "ddd, dd.MM.yy" /f >nul 2>&1
Rem Установка Завершить задачу
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" /v "TaskbarEndTask" /t REG_DWORD /d 1 /f >nul
Rem Удаление лишних значков
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f >nul
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f >nul 
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f >nul 
Rem Скрытие Рекомендуем
	reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "HideRecommendedSection" /t REG_DWORD /d 1 /f >nul
	reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Education" /v "IsEducationEnvironment" /t REG_DWORD /d 1 /f >nul
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecommendedSection" /t REG_DWORD /d 1 /f >nul
Rem Удаления сжатия обоев
	reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d 0x64 /f >nul
Rem Удаление экрана блокировки
	reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v NoLockScreen /t REG_DWORD /d 1 /f >nul
	reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f >nul
Rem Удаление тени на значках Рабочего стола
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d 0 /f >nul
Rem Открывать Проводник в Этот компьютер
	reg add  "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 0 /f >nul
Rem Показывать расширения файлов
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f >nul

Rem Очистка Центра уведомлений
	set "NameSvcMask="
	for /f "delims=" %%A in (' 2^>nul reg query HKLM\System\CurrentControlSet\Services /k /f WpnUserService_ ^| find "HKEY_"') do set "NameSvcMask=%%~nxA"
	if defined NameSvcMask (
	  net stop %NameSvcMask%
	  del /q /f "%LocalAppData%\Microsoft\Windows\Notifications\*.db*"
	 timeout /t 1 /nobreak >nul 2>&1
	  net start %NameSvcMask%
	) >nul 2>&1
Rem Тут нет сжатия файлов, но здесь есть добавление в реестр информации о себе
	reg add "HKCU\Software\WinClick" >nul
	start /b "" Helper /Overlay "Готово. Перезагружаюсь..." /Font "Impact" /Size "40"
	timeout /t 4 /nobreak >nul 2>&1
Rem Перезагрузка
	shutdown /r /t 2
	Helper /Overlay
	Exit

Rem Проверка версии Windows
:WinVer
    for /f "skip=2 tokens=3" %%a in ('2^>nul reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber') do set /a build=%%a
    if !build! LSS 22000 start /b "" Helper /Overlay "Утилита предназначена для Windows 11" /Font "Impact" /Size "40" && Helper /HideConsole && timeout /t 4 /nobreak >nul && start /b "" Helper /Overlay && exit /b
	reg query "HKCU\Software\WinClick" && start /b "" Helper /Overlay "Настройка и оптимизация уже выполнены" /Font "Impact" /Size "40" && Helper /HideConsole && timeout /t 4 /nobreak >nul && start /b "" Helper /Overlay && exit /b
