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

using std::cout;
using std::endl;

using oslogin_utils::AuthOptions;
using oslogin_utils::AuthorizeUser;
using oslogin_utils::ParseJsonToSshKeys;

#define SYSLOG_PREFIX "google_authorized_keys"
#define SUCCESS 0
#define FAIL    1

void signal_handler(int signo) {
  _Exit(0);
}

int main(int argc, char *argv[]) {
  struct AuthOptions opts;
  struct sigaction sig;
  char *user_name;
  string user_response;

  SSHD_SYSLOG_OPEN();

  if (argc != 2) {
    SSHD_SYSLOG_ERR(SYSLOG_PREFIX, "usage: authorized_keys [username]");
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
  opts = { 0 };
  opts.log_prefix = SYSLOG_PREFIX;

  if (AuthorizeUser(user_name, opts, &user_response)) {
    // At this point, we've verified the user can log in. Grab the ssh keys from
    // the user response.
    std::vector<string> ssh_keys = ParseJsonToSshKeys(user_response);
    for (size_t i = 0; i < ssh_keys.size(); i++) {
      cout << ssh_keys[i] << endl;
    }
  }

  SSHD_SYSLOG_CLOSE();
  return SUCCESS;

fail:
  SSHD_SYSLOG_CLOSE();
  return FAIL;
}
