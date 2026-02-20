# edr-graph.spec — PyInstaller spec file
a = Analysis(
    ['agent/main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'kuzu',
        'psutil',
        'pydantic',
        'fastapi',
        'uvicorn',
        'structlog',
        'grpcio',
        'google.protobuf',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='edr-graph',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
)
