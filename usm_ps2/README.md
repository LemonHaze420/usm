# Ultimate Spider-Man (PS2)

### Requirements
1. `sudo apt install gcc-mipsel-linux-gnu binutils-mips-linux-gnu ninja-build`
2. `sudo apt install python3-pip`
3. `python3 -m pip install -U -r requirements.txt`

### Build
1. Extract `SLUS_208.70` into the root of this repo.
2. `./configure.py`
3. `ninja`