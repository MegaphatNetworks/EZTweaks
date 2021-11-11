# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# #                                                                                                   # # 
# #                                                                                                   # # 
# #                                  	  Windows 10 EZ Tweak                                  		  # # 
# #                                        by Gabriel Polmar                                          # # 
# #                                        Megaphat Networks                                          # # 
# #                                        www.megaphat.info                                          # #
# #                                                                                                   # # 
# #                                                                                                   # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

Function regSet ($KeyPath, $KeyItem, $KeyValue) {
	$Key = $KeyPath.Split("\")
	ForEach ($level in $Key) {
		If (!($ThisKey)) {
			$ThisKey = "$level"
		} Else {
			$ThisKey = "$ThisKey\$level"
		}
		If (!(Test-Path $ThisKey)) {New-Item $ThisKey -Force -ErrorAction SilentlyContinue | out-null}
	}
	Set-ItemProperty $KeyPath $KeyItem -Value $KeyValue -ErrorAction SilentlyContinue 
}

Function regDel ($KeyPath, $KeyItem) {
	if (!($KeyItem)) {
		Remove-Item $KeyPath  -ErrorAction SilentlyContinue 
	} else {
		Remove-ItemProperty $KeyPath $KeyItem -ErrorAction SilentlyContinue 
	}
}

Function regGet($Key, $Item) {
	If (!(Test-Path $Key)) {
		Return
	} Else {
		If (!($Item)) {$Item = "(Default)"}
		$ret = (Get-ItemProperty -Path $Key -Name $Item -ErrorAction SilentlyContinue).$Item
		Return $ret
	}
}

Function Wait ($secs) {
	if (!($secs)) {$secs = 1}
	Start-Sleep $secs
}

Function Say($something) {
	Write-Host $something 
}

Function SayB($something) {
	Write-Host $something -ForegroundColor darkblue -BackgroundColor white
}

Function isOSTypeHome {
	$ret = (Get-WmiObject -class Win32_OperatingSystem).Caption | select-string "Home"
	Return $ret
}

Function isOSTypePro {
	$ret = (Get-WmiObject -class Win32_OperatingSystem).Caption | select-string "Pro"
	Return $ret
}

Function isOSTypeEnt {
	$ret = (Get-WmiObject -class Win32_OperatingSystem).Caption | select-string "Ent"
	Return $ret
}

Function getWinVer {
	$ret = (Get-WMIObject win32_operatingsystem).version
	Return $ret
}

Function isAdminLocal {
	$ret = (new-object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole("Administrators")
	Return $ret
}

Function isAdminDomain {
	$ret = (new-object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole("Domain Admins")
	Return $ret
}

Function isElevated {
	$ret = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
	Return $ret
}


Function Get-KeyInput() {
	$key = ([string]($Host.UI.RawUI.ReadKey()).character).ToLower()
	Return $key
}

Function Get-Restart() {
	$ready = $false
	While ($ready -eq $false) {
		Say "You will need to restart this computer in order for the changes to take effect."
		Say "Do you want to restart your computer now? (Y/N)"
		$ki = (Get-KeyInput).toLower()
		If ($ki -eq "y") {
			Say " - Restarting..."
			Restart-Computer -force
			$ready=$true
		} ElseIf ($ki -eq "n") {
			Say " - Not Restarting Now..."
			$ready=$true
		} Else {Say " - Invalid Response."}
	}
}

If (!(isElevated)) {
	Wait 1
	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`" elevate" -f $PSCommandPath) -Verb RunAs
} else {
	Say "Windows Verbose Mode"
	regSet "HKLM:\SOFTWARE\WOW6432Node\Microsoft" "VerboseStatus" 32
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "VerboseStatus" 32
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "VerboseStatus" 1
	regDel "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableStatusMessages"

	################################################################################################################
	Say "Windows Update Manually"
	regSet "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "ElevateNonAdmins" 0 #(only admins) | 1 (anyone)
	regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AuOptions" 2
	# 1 = Do not check
	# 2 = Notify before download
	# 3 = Automatically download and notify of installation
	# 4 = Automatic download and scheduled installation (Only valid if values exist for ScheduledInstallDay and ScheduledInstallTime.) 
	# 5 = Automatic Updates is required, but end users can configure it.

	regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AutoInstallMinorUpdates" 0
	# 0 = Treat minor updates like other updates
	# 1 = Silently install minor updates.

	regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "DetectionFrequency" 0 #(n = 1-22 hours, Time between detection cycles)
	regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "DetectionFrequencyEnabled" 0
	# DetectionFrequencyEnabled 1 = Enable DetectionFrequency
	# DetectionFrequencyEnabled 0 = Disable custom DetectionFrequency (use default value of 22 hours).

	regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoRebootWithLoggedOnUsers" 1
	# 1 = Logged-on user gets to choose whether or not to restart his or her computer. 
	# 0 = Automatic Updates notifies user that the computer will restart in 5 minutes.

	regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 1
	# 0 = Enable Automatic Updates. 
	# 1 = Disable Automatic Updates.

	regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "RebootRelaunchTimeout" 1440 
	#Range=n; where n=time in minutes (1-1440). Time between prompting again for a scheduled restart.
	regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "RebootRelaunchTimeoutEnabled" 0
	# 1 = Enable RebootRelaunchTimeout. 
	# 0 = Disable custom RebootRelaunchTimeout(use default value of 10 minutes).	

	regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "RebootWarningTimeout" 30
	# (Range=n; where n=time in minutes (1-30). Length, in minutes, of the restart warning countdown after installing updates with a deadline or scheduled updates.)

	regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "RebootWarningTimeoutEnabled" 0
	# 1 = Enable RebootWarningTimeout. 
	# 0 = Disable custom RebootWarningTimeout (use default value of 5 minutes).

	################################################################################################################
	Say "Windows Animation Timing"
	regSet "HKCU:\Control Panel\Desktop" MenuShowDelay 0 #no animation (fast response)

	################################################################################################################
	Say "Taskbar Show Seconds"
	regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSecondsInSystemClock" 1

	################################################################################################################
	Say "Stop Windows Update restarting your PC"
	regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoRebootWithLoggedOnUsers" 1

	################################################################################################################
	Say "Startup Delay"
	regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" "StartupDelayInMSec" 0

	################################################################################################################
	Say "RDP CredSSP Fix"
	regSet "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters\" "AllowEncryptionOracle" 2

	################################################################################################################
	Say "Enable PDF preview in Explorer Fix"
	regSet "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID\{DC6EFB56-9CFA-464D-8880-44885D7DC193}" "DisplayName" "@C:\\Program Files (x86)\\Adobe\\Acrobat 10.0\\Acrobat\\pdfprevhndlr.dll,-101"
	regSet "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID\{DC6EFB56-9CFA-464D-8880-44885D7DC193}" "AppID" "{534A1E02-D58F-44f0-B58B-36CBED287C7C}"
	regSet "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID\{DC6EFB56-9CFA-464D-8880-44885D7DC193}" "DisableLowILProcessIsolation" 0
	regSet "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID\{DC6EFB56-9CFA-464D-8880-44885D7DC193}" "@" "Adobe PDF Preview Handler for Windows"
	regSet "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID\{DC6EFB56-9CFA-464D-8880-44885D7DC193}\InprocServer32" "ThreadingModel" "Apartment"
	regSet "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID\{DC6EFB56-9CFA-464D-8880-44885D7DC193}\InprocServer32" "@" "C:\\Program Files (x86)\\Adobe\\Acrobat 10.0\\Acrobat\\pdfprevhndlr.dll"
	regSet "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID\{DC6EFB56-9CFA-464D-8880-44885D7DC193}\ProgID" "@" "PDFPrevHndlr.PDFPreviewHandler.1"
	regSet "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID\{DC6EFB56-9CFA-464D-8880-44885D7DC193}\TypeLib" "@" "{0F6D3808-7974-4B1A-94C2-3200767EACE8}"
	regSet "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID\{DC6EFB56-9CFA-464D-8880-44885D7DC193}\VersionIndependentProgID" "@" "PDFPrevHndlr.PDFPreviewHandler"

	################################################################################################################
	Say "Force Disk Cleanup Delete New Files"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files\" "LastAccess" 7

	################################################################################################################
	Say "Disable automatic driver updates in Windows 10"
	regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows" "ExcludeWUDriversInQualityUpdate" 1

	################################################################################################################
	Say "Remove Quick Access from Explorer"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "HubMode" 1

	################################################################################################################
	Say "Remove OneDrive"
	regSet "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
	regSet "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
	regDel "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"

	################################################################################################################
	Say "Hide Hi greeting in Windows 10"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableFirstLogonAnimation" 0

	################################################################################################################
	Say "No hide file extensions"
	regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0

	################################################################################################################
	Say "Remove 3D objects"
	regDel "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
	regDel "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"

	################################################################################################################
	Say "Disable Security Center Notifications"
	regSet "HKLM:\SOFTWARE\Microsoft\Security Center\Svc" "AntiVirusDisableNotify" 1
	regSet "HKLM:\SOFTWARE\Microsoft\Security Center\Svc" "FirewallDisableNotify" 1
	regSet "HKLM:\SOFTWARE\Microsoft\Security Center\Svc" "UpdatesDisableNotify" 1
	regSet "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableNotificationCentre" 1
	regSet "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableNotificationCenter" 1

	################################################################################################################
	Say "Task bar preview delay (ms)"
	regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ExtendedUIHoverTime" 50

	################################################################################################################
	Say "Disable MS Ads in explorer"
	regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSyncProviderNotification" 0

	################################################################################################################
	Say "No Glomming (keep every icon on the taskbar separate)"
	regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "TaskbarGlomming" 0
	# Never combine Taskbar icons
	regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarGlomLevel" 2

	################################################################################################################
	Say "Don't add ""-Shortcut"" text to the name of newly created shortcuts"
	$byte = "00,00,00,00".Split(',') | % { "0x$_"}
	regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "link" ([byte[]]$byte)

	################################################################################################################
	Say "Disable Telemetry in Microsoft Office"
	regSet "HKCU:\Software\Policies\Microsoft\Office\16.0\osm" "Enablelogging" 0
	regSet "HKCU:\Software\Policies\Microsoft\Office\16.0\osm" "EnableUpload" 0
	regSet "HKCU:\Software\Microsoft\Office\Common\ClientTelemetry" "DisableTelemetry" 1

	################################################################################################################
	Say "Don't hide recently opened Programs from the Start menu /Start Run"
	regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Start_TrackProgs" 1

	################################################################################################################
	Say "Don't hide recently opened Documents from the Start menu /Start Run"
	regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Start_TrackDocs" 1

	################################################################################################################
	Say "Don't show notifications/adverts (OneDrive & new feature alerts) in Windows Explorer"
	regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSyncProviderNotifications" 1

	################################################################################################################
	Say "Don't change the upper/lower case of filenames"
	regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DontPrettyPath" 0

	SayB "Quick patches have been applied!"
	Get-Restart
}
