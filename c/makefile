# simple makefile

CFLAGS=-g -Wformat -Werror
LFLAGS=-L. -liam_msg -lcrypto -lssl -lcurl -lm -lpthread
INCL=iam_crypt.h  aws_sns.h cJSON.h

DEST=/data/local
DEST_LIB=$(DEST)/lib
DEST_INC=$(DEST)/include

all:	demo_send demo_recv demo_recv_multi libiam_msg.a test thread_send leaktest

.c.o:	$(INCL)
	$(CC) -c $(CFLAGS) $(@:.o=.c)

libiam_msg.a:	cJSON.o aws_sns.o aws_sqs.o iam_crypt.o iam_msg.o
	ar -rc libiam_msg.a cJSON.o aws_sns.o aws_sqs.o iam_crypt.o iam_msg.o

demo_recv.cgi:	demo_recv.cgi.o libiam_msg.a sns_fcgi.o
	cc -g -o demo_recv.cgi demo_recv.cgi.o sns_fcgi.o $(LFLAGS) -lfcgi

demo_send:	demo_send.o libiam_msg.a
	cc -g -o demo_send demo_send.o $(LFLAGS)
	
demo_recv:	demo_recv.o libiam_msg.a
	cc -g -o demo_recv demo_recv.o $(LFLAGS)
	
demo_recv_multi:	demo_recv_multi.o libiam_msg.a
	cc -g -o demo_recv_multi demo_recv_multi.o $(LFLAGS)
	
leaktest:	leaktest.o libiam_msg.a
	cc -g -o leaktest leaktest.o $(LFLAGS)
	
thread_send:	thread_send.o libiam_msg.a
	cc -g -o thread_send thread_send.o $(LFLAGS)
	
test:	test.o libiam_msg.a
	cc -g -o test test.o $(LFLAGS)
	
install:	libiam_msg.a
	cp libiam_msg.a $(DEST_LIB)
	cp iam_msg.h iam_crypt.h cJSON.h $(DEST_INC)

clean:
	rm -f *.o *.a demo_recv.cgi test demo_send demo_recv
