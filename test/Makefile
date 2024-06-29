VPATH = ..:.
source = test.c test_fixed.c test_elliptic.c \
fixed.c sha.c random.c crypt.c elliptic.c addition.c signature.c
object = $(source:.c=.o)
a.out = a.out
#CFLAGS = -g -Wall -DFIXED_DEBUG -DFIXED_8BIT
#CFLAGS = -g -Wall -O3 -DFIXED_RELEASE -DFIXED_64BIT
CFLAGS = -g -Wall -I. -I.. ${compile_define}

$(a.out) : $(object)
	$(CC) $(CFLAGS) -o $(a.out) $(object)

.PHONY : clean
clean :
	-rm -f $(a.out) $(object)

