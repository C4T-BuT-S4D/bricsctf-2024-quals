python3 leak_flag_len.py models/leak_len_model /flag.txt
python3 solve_leak_len.py localhost 4224 models/leak_len_model.zip

python3 leak_flag.py models/leak_model /flag.txt 38
python3 solve.py localhost 4224 models/leak_model.zip 38