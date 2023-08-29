// Copyright 2023 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <iostream>

#include <signal.h>

#include <oslogin_utils.h>
#include <oslogin_sshca.h>

using std::cout;
using std::endl;

using oslogin_utils::AuthorizeUser;
using oslogin_utils::AuthOptions;

#define SYSLOG_PREFIX "google_authorized_principals"
#define SUCCESS 0
#define FAIL    1

void signal_handler(int signo) {
  _Exit(0);
}

int main(int argc, char* argv[]) {
  size_t fp_len;
  char *user_name, *cert, *fingerprint;
  struct sigaction sig;
  struct AuthOptions opts;
  string user_response;

  fp_len = 0;
  opts = { 0 };
  user_name = cert = fingerprint = NULL;

  SSHD_SYSLOG_OPEN();

  if (argc != 3) {
    SSHD_SYSLOG_ERR(SYSLOG_PREFIX, "usage: google_authorized_principals [username] [base64-encoded cert]");
    goto fail;
  }

  sig = { 0 };
  sig.sa_handler = signal_handler;
  sigemptyset(&sig.sa_mask);

  if (sigaction(SIGPIPE, &sig, NULL) == -1) {
    SSHD_SYSLOG_ERR(SYSLOG_PREFIX, "Unable to initialize signal handler. Exiting.");
    goto fail;
  }

  user_name = argv[1];
  cert = argv[2];

  fp_len = sshca_get_byoid_fingerprint(SYSLOG_PREFIX, cert, &fingerprint);
  opts.log_prefix = SYSLOG_PREFIX;
  opts.fingerprint = fingerprint;
  opts.fp_len = fp_len;

  if (AuthorizeUser(user_name, opts, &user_response)) {
    cout << user_name << endl;
  }

  free(fingerprint);
  SSHD_SYSLOG_CLOSE();

  return SUCCESS;

fail:
  SSHD_SYSLOG_CLOSE();
  return FAIL;
}
