
$destPath = "C:\Program Files (x86)\Artemis Arrow"
Copy-Item -Path .\ArtemisArrow.exe -Destination $destPath
Copy-Item -Path .\config.json -Destination $destPath

if (Get-Service ArtemisArrow -ErrorAction SilentlyContinue) {
  $service = Get-WmiObject -Class Win32_Service -Filter "name='ArtemisArrow'"
  $service.StopService()
  Start-Sleep -s 1
  $service.delete()
}

New-Service -name ArtemisArrow `
  -displayName "ArtemisArrow" `
  -binaryPathName "`"C:\Program Files (x86)\Artemis Arrow\ArtemisArrow.exe`""

Try {
  Start-Process -FilePath sc.exe -ArgumentList 'config ArtemisArrow start= delayed-auto'
}
Catch { Write-Host -f red "An error occured setting the service to delayed start." }
