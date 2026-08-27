# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build spec for the checktls standalone executable.

Build with:  py -m PyInstaller checktls.spec
Output:      dist/checktls.exe   (single portable file)
"""

block_cipher = None

a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=[],
    datas=[('templates', 'templates')],
    hiddenimports=['dns.rdata', 'dns.rdatatype', 'dns.rdtypes', 'bs4', 'cryptography.hazmat.bindings._openssl'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='checktls',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # keep a console so the Flask startup log is visible; set False for a silent GUI launch
)
