@echo off
setlocal
rem สร้าง LunaGuard.exe (ดับเบิลคลิกไฟล์นี้บน Windows ที่ติดตั้ง Python แล้ว)
python -m pip install -r requirements-build.txt
if errorlevel 1 exit /b %errorlevel%
python -m PyInstaller --clean --onefile --noconsole --uac-admin --icon "logo\Luna_Guard.ico" --name LunaGuard --collect-all webview ^
  --add-data "dashboard.html;." --add-data "locales.json;." --add-data "logo\Luna_Guard.png;logo" ^
  --add-data "luna_rules.yar;." --add-data "rules;rules" --add-data "malware_knowledge.json;." --distpath "dist\release" luna_app.py
if errorlevel 1 exit /b %errorlevel%
python scripts\record_build.py dist\release\LunaGuard.exe
if errorlevel 1 exit /b %errorlevel%
echo.
echo เสร็จแล้ว: dist\release\LunaGuard.exe พร้อม SHA256SUMS.txt และ build-provenance.json
pause
