NAME=NetWork_Sniffer
SRC=main.c sniffer.c

LOG=log.txt
CC=gcc
RM=rm -rf

OBJ=$(SRC:.c=.o)

.PHONY:all
all:$(OBJ) $(NAME)
$(OBJ):$(SRC)
	$(CC) -c $(SRC)
$(NAME):$(OBJ)
	$(CC) -o $(NAME) $(OBJ)

clean:
	$(RM) $(OBJ) $(NAME) $(LOG)
			 
