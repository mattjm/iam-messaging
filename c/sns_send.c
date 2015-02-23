/* ========================================================================
 * Copyright (c) 2012 The University of Washington
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

/* Amazon SNS tools */

#include <stdio.h>
#include <stdlib.h>

#include "aws_sns.h"

#include "etc/aws_keys.h"

main() {
   sns_init(SNSHost, SNSArn, SNSKey, SNSKeyId);
   iam_addCryptkey("key1", "Y3drbGNtbGR3CmNta3cKZG1jd2Rjbmtqd25jamtkdwpjCmVjbWsKY21rZWRyY21kbXNja2R3Cg==");
   char *msg = "Hello, world! Goodbye, World.";
   sns_sendMessage("Hello", msg, strlen(msg));
}

