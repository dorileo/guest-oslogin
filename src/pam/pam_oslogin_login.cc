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

#define PAM_SM_ACCOUNT
#include <security/pam_modules.h>
#include <syslog.h>

#include <sstream>
#include <map>

#include "include/compat.h"
#include "include/oslogin_utils.h"

using oslogin_utils::AuthOptions;
using oslogin_utils::ContinueSession;
using oslogin_utils::GetUser;
using oslogin_utils::ParseJsonToChallenges;
using oslogin_utils::ParseJsonToKey;
using oslogin_utils::ParseJsonToEmail;
using oslogin_utils::StartSession;
using oslogin_utils::ValidateUserName;

extern "C" {

// pm_sm_acct_mgmt is the account management PAM implementation for non-admin users (or users
// without the proper loginAdmin policy). This account management module is intended for custom
// configuration handling only, where users need a way to in their stack configurations to
// differentiate a OS Login user. The Google Guest Agent will not manage the lifecycle of
// this module, it will not add this to the stack as part of the standard/default configuration
// set.
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc, const char** argv) {
  struct AuthOptions opts;
  const char *user_name;
  string user_response;

  if (pam_get_user(pamh, &user_name, NULL) != PAM_SUCCESS) {
    PAM_SYSLOG(pamh, LOG_INFO, "Could not get pam user.");
    return PAM_PERM_DENIED;
  }

  opts = { 0 };

  if (!AuthorizeUser(user_name, opts, &user_response)) {
    return PAM_PERM_DENIED;
  }

  return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv) {
  return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc,
                    const char** argv) {
  const char *user_name;

  if (pam_get_user(pamh, &user_name, NULL) != PAM_SUCCESS) {
    PAM_SYSLOG(pamh, LOG_INFO, "Could not get pam user.");
    return PAM_PERM_DENIED;
  }

  std::string str_user_name(user_name);
  if (!ValidateUserName(user_name)) {
    return PAM_PERM_DENIED;
  }

  std::string response;
  if (!(GetUser(str_user_name, &response))) {
    return PAM_PERM_DENIED;
  }

  // System accounts begin with the prefix `sa_`.
  std::string sa_prefix = "sa_";
  if (str_user_name.compare(0, sa_prefix.size(), sa_prefix) == 0) {
    return PAM_SUCCESS;
  }

  std::string email;
  if (!ParseJsonToEmail(response, &email) || email.empty()) {
    return PAM_PERM_DENIED;
  }

  response = "";
  if (!StartSession(email, &response)) {
    PAM_SYSLOG(pamh, LOG_ERR, "Bad response from the two-factor start session "
               "request: %s",
               response.empty() ? "empty response" : response.c_str());
    return PAM_PERM_DENIED;
  }

  std::string status;
  if (!ParseJsonToKey(response, "status", &status)) {
    PAM_SYSLOG(pamh, LOG_ERR, "Failed to parse status from start session "
                              "response");
    return PAM_PERM_DENIED;
  }

  if (status == "NO_AVAILABLE_CHALLENGES") {
    PAM_SYSLOG(pamh, LOG_ERR, "User has no two-factor methods enabled.");
    return PAM_PERM_DENIED; // User is not two-factor enabled, deny login.
  }

  std::string session_id;
  if (!ParseJsonToKey(response, "sessionId", &session_id)) {
    return PAM_PERM_DENIED;
  }

  std::vector<oslogin_utils::Challenge> challenges;
  if (!ParseJsonToChallenges(response, &challenges)) {
    PAM_SYSLOG(pamh, LOG_ERR, "Failed to parse challenge values from "
                              "JSON response");
    return PAM_PERM_DENIED;
  }

  std::map<std::string,std::string> user_prompts;
  user_prompts[AUTHZEN] = "Google phone prompt";
  user_prompts[TOTP] = "Security code from Google Authenticator application";
  user_prompts[INTERNAL_TWO_FACTOR] = "Security code from security key";
  user_prompts[IDV_PREREGISTERED_PHONE] = "Voice or text message verification code";
  user_prompts[SECURITY_KEY_OTP] = "Security code from a security key";

  oslogin_utils::Challenge challenge;
  if (challenges.size() > 1) {
    std::stringstream prompt;
    prompt << "Please choose from the available authentication methods: ";
    for(vector<oslogin_utils::Challenge>::size_type i = 0;
        i != challenges.size(); ++i) {
      prompt << "\n" << i+1 << ": " << user_prompts[challenges[i].type];
    }
    prompt << "\n\nEnter the number for the authentication method to use: ";

    char *choice = NULL;
    if (pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &choice, "%s",
                   prompt.str().c_str()) != PAM_SUCCESS) {
      pam_error(pamh, "Unable to get user input");
      return PAM_PERM_DENIED;
    }

    int choicei;
    if (sscanf(choice, "%d", &choicei) != 1) {
      pam_error(pamh, "Error parsing user input");
      return PAM_PERM_DENIED;
    }

    if (size_t(choicei) > challenges.size() || choicei <= 0) {
      pam_error(pamh, "Invalid option");
      return PAM_PERM_DENIED;
    }
    challenge = challenges[choicei - 1];
  } else {
    challenge = challenges[0];
  }

  if (challenge.status != "READY") {
    // Call continueSession with the START_ALTERNATE flag.
    if (!ContinueSession(true, email, "", session_id, challenge, &response)) {
      PAM_SYSLOG(pamh, LOG_ERR, "Bad response from two-factor continue session "
                 "request: %s",
                 response.empty() ? "empty response" : response.c_str());
      return PAM_PERM_DENIED;
    }
  }

  char *user_token = NULL;
  if (challenge.type == INTERNAL_TWO_FACTOR) {
    if (pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &user_token,
                   "Enter your security code: ") != PAM_SUCCESS) {
      pam_error(pamh, "Unable to get user input");
      return PAM_PERM_DENIED;
    }
  } else if (challenge.type == SECURITY_KEY_OTP) {
    if (pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &user_token,
        "Enter your security code by visiting https://g.co/sc: ") != PAM_SUCCESS) {
      pam_error(pamh, "Unable to get user input");
      return PAM_PERM_DENIED;
    }
  } else if (challenge.type == TOTP) {
    if (pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &user_token,
                   "Enter your one-time password: ") != PAM_SUCCESS) {
      pam_error(pamh, "Unable to get user input");
      return PAM_PERM_DENIED;
    }
  } else if (challenge.type == AUTHZEN) {
    if (pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &user_token,
                   "A login prompt has been sent to your enrolled device. "
                   "Press enter to continue") != PAM_SUCCESS) {
      pam_error(pamh, "Unable to get user input");
      return PAM_PERM_DENIED;
    }
  } else if (challenge.type == IDV_PREREGISTERED_PHONE) {
    if (pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &user_token,
                   "A security code has been sent to your phone. "
                   "Enter code to continue: ") != PAM_SUCCESS) {
      pam_error(pamh, "Unable to get user input");
      return PAM_PERM_DENIED;
    }
  } else {
    PAM_SYSLOG(pamh, LOG_ERR, "Unsupported challenge type %s",
               challenge.type.c_str());
    return PAM_PERM_DENIED;
  }

  if (!ContinueSession(false, email, user_token, session_id,
                       challenge, &response)) {
      PAM_SYSLOG(pamh, LOG_ERR, "Bad response from two-factor continue "
                 "session request: %s",
                 response.empty() ? "empty response" : response.c_str());
      return PAM_PERM_DENIED;
  }

  if (!ParseJsonToKey(response, "status", &status) || status != "AUTHENTICATED") {
    if (ParseJsonToKey(response, "rejectionReason", &status) && !status.empty()) {
      pam_error(pamh, status.c_str());
    }
    return PAM_PERM_DENIED;
  }

  return PAM_SUCCESS;
}
}
