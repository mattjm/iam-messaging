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

/* Recv multiple message from aws */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "iam_crypt.h"
#include "aws_sqs.h"
#include "iam_msg.h"

#include "cJSON.h"

char *prog;

void usage() {
   fprintf(stderr, "usage: %s [-c cfg_file] -n max_messages \n", prog);
   exit (1);
}

main(int argc, char **argv) {
   
   char *cfgfile = "etc/aws.conf.js";
   int ntest = 10;
   int verbose = 0;

   prog = argv[0];
   while (--argc > 0) {
     argv++;
     if (argv[0][0] == '-') {
        switch (argv[0][1]) {
        case 'c':
           if (--argc<=0) usage();
           cfgfile = (++argv)[0];
           break;
        case 'n':
           if (--argc<=0) usage();
           char *s = (++argv)[0];
           ntest = atoi(s);
           break;
        case 'v':
           verbose = 1;
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

  int nm = sqs_getNumMessages();
  fprintf(stderr, "%d messages in the queue\n", nm);
  fprintf(stderr, "receiving %d at a time \n", ntest);
  
  int n, i;
  char *s;
  int tot = 0;
  
  for (;;) {
   SQSMessage *smsgs = sqs_getMessages(ntest);

   if (!smsgs) {
      printf("none, sleep 5min\n");
      sleep (60*5);
      continue;
   }

   i = 1;

   SQSMessage *smsg = smsgs;
   while (smsg) {
      if (verbose) printf("recv %d\n", i);
      if (!smsg->messageId) {
         IamMessage *err = iam_newIamMessage();
         err->error = smsg->verified;
         err->message = strdup(smsg->message);
         printf("err at %d: %s\n", tot, err->message);
         freeSQSMessage(smsg);
      } else {
         IamMessage *msg = iam_msgParse(smsg->message);

         if (verbose) {
             printf("message received: type: %s\n", msg->messageType);
             printf("uuid: %s\n", msg->uuid);
             printf("sent: %s\n", msg->timestamp);
             printf("sender: %s\n", msg->sender);
             printf("contentType: %s\n", msg->contentType);
             printf("context: [%s]\n", msg->messageContext);
             printf("message: [%s]\n", msg->message);
          }
      }
      sqs_deleteMessage(smsg->handle);
      SQSMessage *next = smsg->next;
      freeSQSMessage(smsg);
      smsg = next;
      i++;
      tot += 1;
   }
   printf("..%d\n", tot);
  }

  printf("%d processed\n", n);
  exit (0);
}


