#!/bin/bash

# 1. Prepare JRE

make -C ./

# 2. Build `libchecker.so`

make -C ./libchecker/

# 3. Build `Dolly.class`

make -C ./dollyclass/

# 4. Build `dolly`
# Note: you need to craft the final patches manually (patch.py)

make -C ./dolly/

# 5. Done
