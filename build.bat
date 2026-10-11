@echo off
setlocal

echo ========================================
echo        Building LunaGuard.exe
echo ========================================
echo.

rem Install / update required packages
python -m pip install --upgrade pywebview yara-python pyinstaller

if errorlevel 1 (
    echo.
    echo [ERROR] Failed to install packages.
    pause
    exit /b %errorlevel%
)

rem Remove old build files
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist LunaGuard.spec del /q LunaGuard.spec

echo.
echo [BUILD] Creating LunaGuard.exe...
echo.

python -m PyInstaller ^
    --clean ^
    --onefile ^
    --noconsole ^
    --uac-admin ^
    --icon="logo\Luna_Guard.ico" ^
    --name="LunaGuard" ^
    --collect-all="webview" ^
    --add-data="dashboard.html;." ^
    --add-data="locales.json;." ^
    --add-data="logo\Luna_Guard.png;logo" ^
    --add-data="luna_rules.yar;." ^
    luna_app.py

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed.
    pause
    exit /b %errorlevel%
)

echo.
echo ========================================
echo        BUILD SUCCESS
echo ========================================
echo.
echo LunaGuard.exe:
echo dist\LunaGuard.exe
echo.

pause