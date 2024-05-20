source = main.c fixed.c crypt.c
object = $(source:.c=.o)
a.out = a.out
#CFLAGS = -g -Wall -DFIXED_DEBUG -DFIXED_8BIT
#CFLAGS = -g -Wall -O3 -DFIXED_RELEASE -DFIXED_64BIT
CFLAGS = -g -Wall

$(a.out) : $(object)
	$(CC) $(CFLAGS) -o $(a.out) $(object)

.PHONY : clean
clean :
	-rm -f $(a.out) $(object)

