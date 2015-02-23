/* ========================================================================
 * Copyright (c) 2013 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

/* Send UW message to aws ( threading test) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "iam_crypt.h"
#include "iam_msg.h"


#include "cJSON.h"

char *prog;
char *message = "Hello, world, from c";
int nmessage = 5;

char *cryptid = "iamcrypt1";
char *signid = "iamsig1";

void usage() {
   fprintf(stderr, "usage: %s [-c cfg_file] [-m message] [-f message_file] [-n num_messages] [-t num_threads]\n", prog);
   exit (1);
}

/* Thread to send messages  */

void *th_sns_send(void *arg) {

   int tn = atoi((char*)arg);
   printf ("thread %d\n", tn);
   int i;
   for (i=0;i<nmessage;i++) {
      printf("%d sending\n", tn);
      char *txt = (char*) malloc(1024);
      sprintf(txt, "iam-thread-sender %d - %d", tn, i);
      IamMessage *msg = iam_newIamMessage();
      msg->contentType = strdup("json");
      msg->messageContext = strdup(txt);
      msg->messageType = strdup("pthest");
      msg->message = strdup(message);
      msg->sender = strdup(txt);
      iam_msgSend(msg, cryptid, signid);
      iam_freeIamMessage(msg);
      free(txt);
      sleep(tn);
   }
}

main(int argc, char **argv) {
   
   char *cfgfile = "etc/aws.conf.js";
   char *type = "uw-test-message";
   char *msgfile = NULL;
   char *s;

   int i;
   int nthread = 3;

   prog = argv[0];
   while (--argc > 0) {
     argv++;
     if (argv[0][0] == '-') {
        switch (argv[0][1]) {
        case 'c':
           if (--argc<=0) usage();
           cfgfile = (++argv)[0];
           break;
        case 'm':
           if (--argc<=0) usage();
           message = (++argv)[0];
           break;
        case 'f':
           if (--argc<=0) usage();
           msgfile = (++argv)[0];
           break;
        case 'n':
           if (--argc<=0) usage();
           s = (++argv)[0];
           nmessage = atoi(s);
           break;
        case 't':
           if (--argc<=0) usage();
           s = (++argv)[0];
           nthread = atoi(s);
           break;
        case '?':
           usage();
        }
      }
   }

   if (!iam_msgInit(cfgfile)) {
      fprintf(stderr, "config file error\n");
      exit(1);
   }

   for (i=0;i<nthread;i++) {
       char tht[8];
       sprintf(tht, "%d", i);
       pthread_t thread;
       pthread_attr_t pta;

       pthread_attr_init(&pta);
       pthread_attr_setdetachstate(&pta, PTHREAD_CREATE_DETACHED);
       pthread_create(&thread, &pta, th_sns_send, (void*) tht);
   }
   while (1) {
      sleep(2);
   }
}


