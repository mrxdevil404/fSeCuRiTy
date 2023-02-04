from os import system
from time import sleep
from random import choice
names = [ '.1b.sh' ,  '.2b.sh' , '.3b.sh' , '.4b.sh' , '.5b.sh' , '.6b.sh' ]
#system('clear')
#for i in range(2):
 #system(f'bash {choice(names)}')
sleep(1)
system('clear')
system(f'bash {choice(names)}')
