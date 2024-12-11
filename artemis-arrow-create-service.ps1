#Copy all items from zip to specific directory
$sourcePath = @( Get-Item .\dist ).FullName
$destPath = "C:\Program Files (x86)\Artemis Arrow"
$fileList = @(Get-ChildItem -Path .\dist -File -Recurse)
$directoryList = @(Get-ChildItem -Path .\dist -Directory -Recurse)
ForEach($directory in $directoryList){
    $directories = New-Item ($directory.FullName).Replace("$($sourcePath)",$destPath) -ItemType Directory -ea SilentlyContinue | Out-Null
}
ForEach($file in $fileList){
    try {
        Copy-Item -Path $file.FullName -Destination ((Split-Path $file.FullName).Replace("$($sourcePath)",$destPath)) -Force -ErrorAction Stop
    }
    catch{
        Write-Warning "Unable to move '$($file.FullName)' to '$(((Split-Path $file.FullName).Replace("$($sourcePath)",$destPath)))': $($_)"
        return
    }
}
#see if the npac drivers exist, if not install
if (-not (Test-Path "C:\Windows\System32\drivers\npcap.sys") ){
	.\npcap-1.80.exe
}
#if a service already exists, delete it
if (Get-Service ArtemisArrow -ErrorAction SilentlyContinue) {
  $service = Get-WmiObject -Class Win32_Service -Filter "name='ArtemisArrow'"
  $service.StopService()
  Start-Sleep -s 1
  $service.delete()
}
#make a new service
New-Service -name ArtemisArrow `
  -displayName "ArtemisArrow" `
  -binaryPathName "`"C:\Program Files (x86)\Artemis Arrow\ArtemisArrow.exe`""
#register the service to delayed start to make persistent
Try {
  Start-Process -FilePath sc.exe -ArgumentList 'config ArtemisArrow start= delayed-auto'
}
Catch { Write-Host -f red "An error occured setting the service to delayed start." }
#change MTU size of outbound interface in order to account for extra bytes from VXLAN encapsulation
netsh interface ipv4 set subinterface "$((get-netipaddress | ? {$_.IpAddress -match 10.10}).InterfaceAlias)" mtu=1600 store=persistent
