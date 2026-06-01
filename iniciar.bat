@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

REM Ir al directorio del script (donde sea que esté ubicado)
cd /d "%~dp0"

set "VENV_PY=%cd%\.venv\Scripts\python.exe"

REM Si el venv ya existe, saltamos a correr directo
if exist "%VENV_PY%" goto run

REM ==============================================================
REM Primera vez: hay que crear el venv. Buscamos Python instalado.
REM ==============================================================

echo.
echo === Primera vez: configurando entorno ===
echo.

set "PY_LAUNCHER="

REM 1) py launcher (instalado por el instalador oficial de Python)
where py >nul 2>&1
if not errorlevel 1 (
    set "PY_LAUNCHER=py"
    goto setup
)

REM 2) python en el PATH
where python >nul 2>&1
if not errorlevel 1 (
    set "PY_LAUNCHER=python"
    goto setup
)

REM 3) Rutas tipicas de instalacion por usuario
for %%V in (313 312 311 310) do (
    if exist "%LocalAppData%\Programs\Python\Python%%V\python.exe" (
        set "PY_LAUNCHER=%LocalAppData%\Programs\Python\Python%%V\python.exe"
        goto setup
    )
)

REM 4) Rutas tipicas de instalacion global
for %%V in (313 312 311 310) do (
    if exist "C:\Program Files\Python%%V\python.exe" (
        set "PY_LAUNCHER=C:\Program Files\Python%%V\python.exe"
        goto setup
    )
)

echo.
echo ERROR: No se encontro Python instalado.
echo Descargalo de https://www.python.org/downloads/
echo y al instalar, marca el checkbox "Add Python to PATH".
echo.
pause
exit /b 1

:setup
echo Python encontrado: %PY_LAUNCHER%
echo.
echo Creando entorno virtual...
"%PY_LAUNCHER%" -m venv .venv
if errorlevel 1 goto error

echo.
echo Actualizando pip...
"%VENV_PY%" -m pip install --upgrade pip --quiet
if errorlevel 1 goto error

echo.
echo Instalando dependencias (puede tomar 2-3 minutos)...
"%VENV_PY%" -m pip install -r requirements.txt
if errorlevel 1 goto error

echo.
echo === Setup completado ===
echo.

:run
REM Verificacion sanity check
if not exist "%VENV_PY%" (
    echo ERROR: El entorno virtual quedo roto. Borra la carpeta .venv y ejecuta de nuevo.
    pause
    exit /b 1
)

if not exist ".env" (
    echo.
    echo ADVERTENCIA: No se encontro archivo .env
    echo El servidor puede fallar al iniciar.
    echo.
    timeout /t 3 >nul
)

echo.
echo ================================================
echo  Bot Casita
echo  Panel:  http://localhost:8000/login
echo  Login:  aguevardo / corruptos2026
echo  Stop:   Ctrl+C   o   cerrar esta ventana
echo ================================================
echo.

"%VENV_PY%" -m src.main

REM Si el server se cayó por error, pausar para que el usuario vea el mensaje
if errorlevel 1 (
    echo.
    echo El servidor se detuvo con un error.
    pause
)

goto end

:error
echo.
echo ====================
echo  ERROR en setup
echo ====================
echo Revisa los mensajes de arriba.
pause
exit /b 1

:end
endlocal
