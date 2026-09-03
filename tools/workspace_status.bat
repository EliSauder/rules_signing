@echo off
REM Windows counterpart to workspace_status.py. Bazel invokes the workspace
REM status command directly (no shell), and a bare .py file is not something
REM CreateProcess can launch on Windows without a registered file
REM association, so this thin, directly-executable .bat launches the actual
REM script via the Python interpreter explicitly.
python "%~dp0workspace_status.py"
