# Self build <br>
 <br>
download all files into a directory <br>
open console in directory <br>
>go mod init <br>
>go build -ldflags -H=windowsgui .\ArtemisArrow.go <br>

copy the exe and config into a folder with the ps1 script <br>

# Installation Instructions <br>
 <br>
move folder to desired host <br>
run ps1 script as admin <br>
you may need to restart endpoint <br>
 <br>
 <br>
 <br>
intended for use with a 10.10.0.0/16 network as a "offline" aggregator network allowing all endpoints to send to aggregator without useing live interfaces <br>
will need to compile new binaries to change this
