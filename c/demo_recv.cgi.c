/* ========================================================================
 * Copyright (c) 2012-2013 The University of Washington
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


/* SNS message receiver: cgi example */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

#include "aws_sns.h"
#include "iam_msg.h"

char *cfgfile = "etc/aws.conf.js";
extern int iamVerbose;


/* Message handler
 *
 * This is where something is done with the SNS message. 
 * (note stderr in a cgi goes to error_log, with apache at least)
 */
int sns_handler(SNSMessage *snsmsg) {
   // fprintf(stderr, "got [%s]\n", snsmsg->message);
   // decode and verify the iam message
   IamMessage *msg = iam_msgParse(snsmsg->message);
   if (msg) {
      // do something with it
      if (iamVerbose) {
         fprintf(stderr,"message received: type: %s\n", msg->messageType);
         fprintf(stderr,"uuid: %s\n", msg->uuid);
         fprintf(stderr,"sent: %s\n", msg->timestamp);
         fprintf(stderr,"sender: %s\n", msg->sender);
         fprintf(stderr,"contentType: %s\n", msg->contentType);
         fprintf(stderr,"context: [%s]\n", msg->messageContext);
         fprintf(stderr,"message: [%s]\n", msg->message);
      } else fprintf(stderr,"iam-message: [%s]\n", msg->messageContext);
      iam_freeIamMessage(msg);
   } else {
      fprintf(stderr, "not-iam message\n");
   }
   return (200);
}

/* Not sure why you'd do anything with a GET */
int get_handler() {
   fprintf(stderr, "got GET\n");
   sns_fcgi_response(200, "OK");
   return (200);
}

/* main: handle http requests */

int main(int argc, char** argv)
{
  fprintf(stderr, "demo_recv.cgi starting\n");
  if (!iam_msgInit(cfgfile)) {
      fprintf(stderr, "config file error\n");
      sns_fcgi_response(200, "config file error");
      exit(1);
   }
   sns_fcgi_main(sns_handler, get_handler);
   exit (0);
}


