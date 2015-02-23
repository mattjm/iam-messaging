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

#ifndef _iam_msg_h
#define _iam_msg_h

typedef struct IamMessage_ {
  char *contentType;
  char *version;
  char *uuid;
  char *messageContext;
  char *messageType;
  char *messageId;
  char *timestamp;
  char *sender;
  char *message;
  int error;
} IamMessage;

IamMessage *iam_newIamMessage();
void iam_freeIamMessage(IamMessage *msg);
int iam_msgSend(IamMessage *msg, char *cryptid, char *signid);
int iam_msgSendArn(IamMessage *msg, char *cryptid, char *signid, char *host, char *arn);
IamMessage *iam_msgRecv();
IamMessage *iam_msgParse();

#endif /* _iam_msg_h */

