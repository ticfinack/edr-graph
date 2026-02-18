# edr-graph.spec — PyInstaller spec file
# Bundles NiceGUI's web assets which are required for the dashboard
import os
import nicegui

a = Analysis(
    ['edr_graph/main.py'],
    pathex=[],
    binaries=[],
    datas=[
        (os.path.dirname(nicegui.__file__), 'nicegui'),
    ],
    hiddenimports=['nicegui', 'plotly', 'kuzu', 'psutil', 'pydantic'],
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
    console=False,
    disable_windowed_traceback=False,
)
