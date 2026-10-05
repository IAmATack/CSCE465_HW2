### My versions
Ubuntu 24.04 Desktop x86-64 ISO

Oracle VirtualBox 7.2.16 r174877

Python 3.12.3



### Task 0 Set up Environment
```
cd "$HOME/csce465-agentsec"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1
```

Check in .venv (python3 -m venv .venv)
```
python --version
```
Should print 3.12.3 for version

```
openssl version
```
Should print 3.0.13 for version

```
pip show cyptography pytest
```
Should print Version 49.0.0

```
openssl dhparam -in ffdhe3072.pem -text -noout | head -3
```
Should print: 
DH Parameters: (3072 bit)
GROUP: ffdhe3072


#### All following task commands run from the hw2 directory

### Task 1
Run in .venv (python3 -m venv .venv)
```
python baseline_ctr.py
```

### Task 2
Run in .venv (python3 -m venv .venv)
```
python handshake.py
```

### Task 3
Run in .venv (python3 -m venv .venv)
```
python secure_record.py
```

### Task 4
Run in .venv (python3 -m venv .venv)
```
pytest -q 
```