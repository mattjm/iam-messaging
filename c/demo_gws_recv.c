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

/* Sample program to receive GWS messages from SQS */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "iam_crypt.h"
#include "iam_msg.h"

#include "cJSON.h"

char *prog;

void usage() {
   fprintf(stderr, "usage: %s [-c cfg_file] \n", prog);
   exit (1);
}

main(int argc, char **argv) {
   
   char *cfgfile = "etc/aws.conf.js";

   prog = argv[0];
   while (--argc > 0) {
     argv++;
     if (argv[0][0] == '-') {
        switch (argv[0][1]) {
        case 'c':
           if (--argc<=0) usage();
           cfgfile = (++argv)[0];
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

  int n, i;
  char *s;

  // get 5 and exit

  for (n=0;n<5;n++) {
     IamMessage *msg = iam_msgRecv();
     if (msg) {
        printf("message received: type: %s\n", msg->messageType);
        printf("uuid: %s\n", msg->uuid);
        printf("sent: %s\n", msg->timestamp);
        printf("sender: %s\n", msg->sender);
        printf("contentType: %s\n", msg->contentType);
        printf("context: [%s]\n", msg->messageContext);
         
        // examine the message context -- a JSON string
        
        cJSON *ctx = cJSON_Parse(msg->messageContext);
        if (ctx) {
           s = safeGetString(ctx, "action");
           if (s) printf("action: %s\n", s);
           s = safeGetString(ctx, "group");
           if (s) printf("group: %s\n", s);
           double dt = safeGetDouble(ctx, "time");
           if (!isnan(dt)) printf("time: %f\n", dt);
           s = safeGetString(ctx, "prev-group-name");
           if (s) printf("prev-group-name: %s\n", s);

           // see if there are actors -- a JSON sub-document
           cJSON *act = cJSON_GetObjectItem(ctx, "actors");
           if (act) {
              s = safeGetString(act, "id");
              if (s) printf("actor-id: %s\n", s);
              s = safeGetString(act, "as");
              if (s) printf("acting-as: %s\n", s);
           }

           // see if there are targets -- a JSON array
           cJSON *tgts = cJSON_GetObjectItem(ctx, "targets");
           if (tgts) {
              for (i=0; i<cJSON_GetArraySize(tgts); i++) {
                 cJSON *tgt = cJSON_GetArrayItem(tgts, i);
                 s = safeGetString(tgt, "target");
                 if (s) printf("target: %s\n", s);
              }
           }
           cJSON_Delete(ctx);
        }
        printf("message: [%s]\n", msg->message);
        iam_freeIamMessage(msg);
     } else {
        printf("no more messages\n");
        exit (0);
     }
  }
  printf("5 processed\n");
  exit (0);
}


