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

/* Tests */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "iam_crypt.h"
#include "iam_msg.h"

#include "cJSON.h"

char *prog;
int debug = 0;

void usage() {
   fprintf(stderr, "usage: %s [-c cfg_file] [-m message]\n", prog);
   exit (1);
}

cJSON *config;
int err = 0;

// base64 test

int base64_test() {
   char *iv;
   char *et;
   char *dt;
   
   char *pt = iam_getFile(safeDupString(config, "base64_text"));
   if (debug) {
      printf(" > b64: plain: (%zu) [%s]\n", strlen(pt), pt);
   }

   char *b64 = iam_dataToBase64(pt, strlen(pt));
   if (debug) {
      printf(" > b64: base64: (%zu) [%s]\n", strlen(b64), b64);
   }

   dt = iam_base64ToText(b64);
   if (debug) {
      printf(" > b64: decoded: (%zu) [%s]\n", strlen(dt), dt);
   }

   if (strcmp(pt, dt)) {
      printf("base64 text fails\n");
      return 1;
   } else {
      if (debug) printf("base64 test OK\n");
   }
   return 0;
}
   
   
// crypt test
int crypt_test() {

   char *iv;
   char *et;
   char *dt;
   
   char *pt = iam_getFile(safeDupString(config, "crypt_text"));
   char *ckey = safeDupString(config, "crypt_key");
   if (debug) {
      printf(" > plain text: [%s]\n", pt);
      printf(" > crypt key:  [%s]\n", ckey);
   }

   // encrypt the plain text with the crypt key
   iam_encryptText(ckey, pt, strlen(pt), &et, &iv);
   if (debug) {
      printf(" > et=[%s]\n", et);
      printf(" > iv=[%s]\n", iv);
   }

   // decrypt
   int v = iam_decryptText(ckey, et, &dt, iv);
   if (debug) {
      printf(" > Drypt text: [%s]\n", dt);
   }
   if (strcmp(pt, dt)) {
      printf("crypt text fails\n");
      return 1;
   } else {
      if (debug) printf("crypt test OK\n");
   }
   return 0;
}
   
 
// signature test
int sig_test() {
   char *et;
   char *dt;
   
   char *pt = iam_getFile(safeDupString(config, "sig_text"));
   char *skey = safeDupString(config, "sig_key");
   if (debug) {
      printf(" > sig text: [%s]\n", pt);
      printf(" > sig key:  [%s]\n", skey);
   }

   // sign

   char *sig = iam_computeSignature(pt, skey);
   char *sigurl = iam_getSignUrl(skey);
   if (debug) {
      printf(" > sig=[%s]\n", sig);
      printf(" > url=[%s]\n", sigurl);
   }
 
   // verify
   int v = iam_verifySignature(pt, sig, sigurl);
   if (debug) printf("sig verify = %d\n", v);
   if (v==0) printf("sig fails\n");

   return v;
}


main(int argc, char **argv) {
   
   char *message = "Hello, world.";
   char *testcfg = "test.conf";
   char *cfgfile = "etc/aws.conf.js";
   char *type = "uw-test-message";

   prog = argv[0];
   while (--argc > 0) {
     argv++;
     if (argv[0][0] == '-') {
        switch (argv[0][1]) {
        case 'c':
           if (--argc<=0) usage();
           cfgfile = (++argv)[0];
           break;
        case 't':
           if (--argc<=0) usage();
           testcfg = (++argv)[0];
           break;
        case 'd':
           debug = 1;
           break;
        case '?':
           usage();
        }
      }
   }

   printf("debug = %d\n", debug);

   char *cfg = iam_getFile(testcfg);
   config = cJSON_Parse(cfg);
   if (!config) {
      fprintf(stderr, "config: bad json: %s\n", cfg);
      exit (1);
   }

   iam_msgInit(cfgfile);

   base64_test();
   // crypt_test();
   sig_test();
}


