$ErrorActionPreference = 'Stop'
python -m pytest -q
python -m compileall src
