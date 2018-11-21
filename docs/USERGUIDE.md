# F5 Security Hub 

## Introduction

F5 Security Hub is a BIG-IP iControl LX Extension for posting ASM log events to AWS Security Hub. AWS Security Hub provides a database and dashboard for managing security event notifications across an AWS Cloud Deployment.

This release is community supported, please provide feedback via [DevCentral](https://devcentral.f5.com/questions?tag=aws) (https://devcentral.f5.com/questions?tag=aws).

## Requirements

BIG-IP VE 13.1 running in AWS EC2

## Installation

#### 1. IAM Role Creation

https://aws.amazon.com/iam/

Create an IAM Role for your EC2 instance that gives SecurityHub access, name this role "BIGIPSecurityHubRole"

Attach this IAM role to any EC2 Instance running the BIG-IP VE that you'd like to use Security Hub with.


```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "securityhub:*",
            "Resource": "*"
        }
    ]
}
```

#### 2. Installation of F5 Security Hub  RPM

Download the RPM to the local machine you will access the BIG-IP GUI from.

Log in to the BIG-IP GUI and goto _iApps > Package Management LX_.

At the top right, click 'Import'

Click 'Choose File' and navigate to your local copy of the F5 Security Hub  RPM.

This will upload the file and install the extension. Note, the extension must be configured before it will send any events to Security Hub.


_If the package Management LX menu item is not present..._

Login to the bash shell on BIG-IP and enter the following command to enable iControl LX Extensions:

`touch /var/config/rest/iapps/enable`

Now restart BIG-IP, and the Package Management LX option should be available.

#### 3. BIG-IP Configuration

##### The Logging Profile

Installing the extension will create a remote logging profile called `securityhub-logger` that will connect to the Security Hub Extension to forward log messages.

##### Attach Logging Profile to Virtual Servers

Go on the BIG-IP and attach this logging profile to any virtual servers that have ASM profiles you want to track with Security Hub. 

To do this, select _Local Traffic > Virtual Servers > Virtual Server List_ and a list of virtual servers should appear.

Pick the virtual server you want to connect to Security Hub, and select _Security > Policies_ from the top menu. Note this is the same menu used to apply a WAF configuration.

For Log Profile, select "enabled", select "securityhub-logger" on the left side list, and click the move left icon (```<<```). Now click 'update'.

Once this is set up, you can configure the extension to send only the messages you want to AWS Security Hub. By default, no messages will be sent to Security Hub.

# Configuring F5 Security Hub 

## REST Endpoints

The extension has a few endpoints for configuration and querying the current state of the app. The region to send findings to, and log event filters must be set up before the extension will send any findings to Security Hub.

## /mgmt/shared/securityhub

### GET

List the current app configuration

Example Response:

```javascript
{
  "Region": "us-east-1",
  "Filters": {
    "method" : [
      {
        "Value": "GET",
        "Comparison": "EQUALS"
      }
    ]
  }
}

```

### POST

Post takes a JSON body as input for configuring the Region and Filters this extension will use for posting to SecurityHub. The Schema for this Object is listed in the appendix of this document.

This is a declarative API, so a POST looks exactly like the response from a GET, and the entire ruleset must be specified in the post. It is recommended you keep a copy of your desired filters in a file containing this object, and update and post this file when you need to make changes. It is not a bad idea to keep this file in your version control system, such as git.

The JSON body should have 2 top level properties: Region and Filters. Filters is an object containing keys that mach ASM logging fields sent by BIG-IP's remote logger. Each key's value is an array of filters. Any entry that satisfies at least one of these filters will be posted to Security Hub. A complete list of valid keys is listed in the next section.

Our example post body looks just like the example GET response:

```javascript
{
  "Region": "us-east-1",
  "Filters": {
    "method" : [
      {
        "Value": "GET",
        "Comparison": "EQUALS"
      }
    ]
  }
}

```

## Filters

F5-SHC will not post any findings to Security Hub by default. Configurating passthrough filters will allow ASM events in the log to get posted to securityhub. The following properties are logged by ASMs logger:

```
attack_type             blocking_exception_reason       captcha_result client_type
date_time               dest_ip                         dest_port
device_id               geo_location                    http_class_name
ip_address_intelligence ip_client                       ip_with_route_domain
is_truncated            login_result                    management_ip_address
method                  mobile_application_name         mobile_application_version
policy_apply_date       policy_name                     protocol
query_string            request                         request_status
response                response_code                   route_domain
session_id              severity                        sig_ids
sig_names               sig_set_names                   src_port
staged_sig_ids          staged_sig_names                staged_sig_set_names
sub_violations          support_id                      unit_hostname
uri username            violation_details               violation_rating
violations              virus_name                      websocket_direction
websocket_message_type  x_forwarded_for_header_value
```

A filter object looks like this:

```javascript

{
  "Value": "GET",
  "Comparison": "EQUALS"
}

```

Supported comparisons: EQUALS, CONTAINS, PREFIX

At this time, all properties are treated as a string.

If any one filter matches, the ASM Event will be posted to Security Hub.


# Appendix

## CURL examples

#### f5-Securityhub endpoint (get rule config)
`curl -k -u admin:admin https://bigip.example.com/mgmt/shared/securityhub`

#### f5-Securityhub endpoint (post rule config)

Log all illegal 'GET' requests

`curl -k -u admin:admin -X POST --data '{"Region":"us-east-1", "Filter": {"method":[{"Value":"GET","Comparison":"EQUALS"}]}}'  https://bigip.example.com/mgmt/shared/securityhub`


Log all non-browser requests

`curl -k -u admin:admin -X POST --data '{"Region":"us-east-1", "Filter": {"sig_names":[{"Value":"Automated client access","Comparison":"CONTAINS"}]}}'  https://bigip.example.com/mgmt/shared/securityhub`

Requests blocked by WAF

`curl -k -u admin:admin -X POST --data '{"Region":"us-east-1", "Filter": {"request_status":[{"Value":"blocked","Comparison":"EQUALS"}]}}'  https://bigip.example.com/mgmt/shared/securityhub`

Malformed JSON

`curl -k -u admin:admin -X POST --data '{"Region":"us-east-1", "Filter": {"violations":[{"Value":"Malformed JSON","Comparison":"CONTAINS"}]}}'  https://bigip.example.com/mgmt/shared/securityhub`

Match GET to endpoint '/incident1.txt' in the HTTP header

`curl -k -u admin:admin -X POST --data '{"Region":"us-east-1", "Filter": {"request":[{"Value":"GET /incident1.txt","Comparison":"CONTAINS"}]}}'  https://bigip.example.com/mgmt/shared/securityhub`

Match any request with 'Automated client access' or 'Web Server Probe'

`curl -k -u admin:admin -X POST --data '{"Region":"us-east-1", "Filter": {"sig_names":[{"Value":"Automated client access","Comparison":"CONTAINS"},{"Value":"Web Server Probe","Comparison":"CONTAINS"}]}}'  https://bigip.example.com/mgmt/shared/securityhub`

Match any request with 'Automated client access' or 'Web Server Probe' or any 'POST'

`curl -k -u admin:admin -X POST --data '{"Region":"us-east-1", "Filter": {"method":[{"Value":"POST","Comparison":"EQUALS"}],"sig_names":[{"Value":"Automated client access","Comparison":"CONTAINS"},{"Value":"Web Server Probe","Comparison":"CONTAINS"}]}}'  https://bigip.example.com/mgmt/shared/securityhub`

The post body for the last example (it's a little more complex):

```javascript

{
  "Region":"us-east-1",
  "Filter": {
    "method":[
      {
        "Value":"POST",
        "Comparison":"EQUALS"
      }
    ],
    "sig_names":[
      {
        "Value":"Automated client access",
        "Comparison":"CONTAINS"
      },
      {
        "Value":"Web Server Probe",
        "Comparison":"CONTAINS"}
    ]
  }
}

```

The configuration will forward findings that match any rule on the list.

To add more rules, add them to the existing configuration and POST them to the /mgmt/shared/securityhub endpoint on your BIG-IP


## Configuration Schema

```javascript
{
  "title": "Config",
  "type": "object",
  "definitions": {
    "FilterArray": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "Value",
          "Comparison"
        ],
        "additionalProperties": false,
        "properties": {
          "Value": {
            "type": "string"
          },
          "Comparison": {
            "type": "string",
            "enum": [
              "EQUALS",
              "PREFIX",
              "CONTAINS"
            ]
          }
        }
      }
    }
  },
  "required": [
    "Region",
    "Filter"
  ],
  "additionalProperties": false,
  "properties": {
    "Region": {
      "type": "string",
      "description": "AWS Region to send SecurityHub Findings to.",
      "enum": [
        "us-west-2",
        "us-east-1"
      ]
    },
    "Filter": {
      "type": "object",
      "properties": {
        "attack_type": {
          "$ref": "#/definitions/FilterArray"
        },
        "blocking_exception_reason": {
          "$ref": "#/definitions/FilterArray"
        },
        "captcha_result": {
          "$ref": "#/definitions/FilterArray"
        },
        "client_type": {
          "$ref": "#/definitions/FilterArray"
        },
        "date_time": {
          "$ref": "#/definitions/FilterArray"
        },
        "dest_ip": {
          "$ref": "#/definitions/FilterArray"
        },
        "dest_port": {
          "$ref": "#/definitions/FilterArray"
        },
        "device_id": {
          "$ref": "#/definitions/FilterArray"
        },
        "geo_location": {
          "$ref": "#/definitions/FilterArray"
        },
        "http_class_name": {
          "$ref": "#/definitions/FilterArray"
        },
        "ip_address_intelligence": {
          "$ref": "#/definitions/FilterArray"
        },
        "ip_client": {
          "$ref": "#/definitions/FilterArray"
        },
        "ip_with_route_domain": {
          "$ref": "#/definitions/FilterArray"
        },
        "is_truncated": {
          "$ref": "#/definitions/FilterArray"
        },
        "login_result": {
          "$ref": "#/definitions/FilterArray"
        },
        "management_ip_address": {
          "$ref": "#/definitions/FilterArray"
        },
        "method": {
          "$ref": "#/definitions/FilterArray"
        },
        "mobile_application_name": {
          "$ref": "#/definitions/FilterArray"
        },
        "mobile_application_version": {
          "$ref": "#/definitions/FilterArray"
        },
        "policy_apply_date": {
          "$ref": "#/definitions/FilterArray"
        },
        "policy_name": {
          "$ref": "#/definitions/FilterArray"
        },
        "protocol": {
          "$ref": "#/definitions/FilterArray"
        },
        "query_string": {
          "$ref": "#/definitions/FilterArray"
        },
        "request": {
          "$ref": "#/definitions/FilterArray"
        },
        "request_status": {
          "$ref": "#/definitions/FilterArray"
        },
        "response": {
          "$ref": "#/definitions/FilterArray"
        },
        "response_code": {
          "$ref": "#/definitions/FilterArray"
        },
        "route_domain": {
          "$ref": "#/definitions/FilterArray"
        },
        "session_id": {
          "$ref": "#/definitions/FilterArray"
        },
        "severity": {
          "$ref": "#/definitions/FilterArray"
        },
        "sig_ids": {
          "$ref": "#/definitions/FilterArray"
        },
        "sig_names": {
          "$ref": "#/definitions/FilterArray"
        },
        "sig_set_names": {
          "$ref": "#/definitions/FilterArray"
        },
        "src_port": {
          "$ref": "#/definitions/FilterArray"
        },
        "staged_sig_ids": {
          "$ref": "#/definitions/FilterArray"
        },
        "staged_sig_names": {
          "$ref": "#/definitions/FilterArray"
        },
        "staged_sig_set_names": {
          "$ref": "#/definitions/FilterArray"
        },
        "sub_violations": {
          "$ref": "#/definitions/FilterArray"
        },
        "support_id": {
          "$ref": "#/definitions/FilterArray"
        },
        "unit_hostname": {
          "$ref": "#/definitions/FilterArray"
        },
        "uri": {
          "$ref": "#/definitions/FilterArray"
        },
        "username": {
          "$ref": "#/definitions/FilterArray"
        },
        "violation_details": {
          "$ref": "#/definitions/FilterArray"
        },
        "violation_rating": {
          "$ref": "#/definitions/FilterArray"
        },
        "violations": {
          "$ref": "#/definitions/FilterArray"
        },
        "virus_name": {
          "$ref": "#/definitions/FilterArray"
        },
        "websocket_direction": {
          "$ref": "#/definitions/FilterArray"
        },
        "websocket_message_ty": {
          "$ref": "#/definitions/FilterArray"
        }
      }
    }
  },
  "$id": "foo",
  "$schema": "http://json-schema.org/draft-07/schema#"
}
```

