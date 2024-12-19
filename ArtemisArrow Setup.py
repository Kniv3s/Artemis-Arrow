from distutils.core import setup
import py2exe, sys, os, shutil

sys.argv.append('py2exe')



setup(
    options = {'py2exe': {'bundle_files': 1, 'compressed': True}},
    windows = [{'script': "ArtemisArrow.py"}],
    zipfile = None,
)
os.makedirs("dist\\installers", exist_ok=True)
shutil.copyfile('npcap-1.80.exe', 'dist\\installers\\npcap-1.80.exe')
shutil.copyfile('artemis-arrow-create-service.ps1', 'dist\\artemis-arrow-create-service.ps1')
shutil.make_archive("ArtemisArrow", 'zip', "dist")
