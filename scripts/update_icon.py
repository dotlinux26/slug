import shutil, os, subprocess

src = r'd:\slugdoc\assets\slug-icon.ico'
slug_dir = os.path.expanduser('~/.slug')
os.makedirs(slug_dir, exist_ok=True)
dst = os.path.join(slug_dir, 'slug-icon.ico')
shutil.copyfile(src, dst)
print('Copied to', dst)

localapp = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'slug')
if os.path.exists(localapp):
    shutil.copyfile(src, os.path.join(localapp, 'slug-icon.ico'))

desktop = os.path.join(os.environ['USERPROFILE'], 'Desktop')
lnk = os.path.join(desktop, 'Slug Workspace.lnk')

ps_code = f"""
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut('{lnk}')
$sc.IconLocation = '{dst},0'
$sc.Save()
Write-Host "Updated shortcut icon to: $sc.IconLocation"
"""

subprocess.run(["powershell", "-NoProfile", "-Command", ps_code], check=True)
print("Done updating shortcut icon!")
