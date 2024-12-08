# Day 7 - AWS Log Analysis

![image.png](images/image.png)

## Introduction

Care4Wares' infrastructure runs in the cloud, so they chose AWS as their Cloud Service Provider (CSP). Instead of their workloads running on physical machines on-premises, they run on virtualised instances in the cloud. These instances are (in AWS) called EC2 instances (Amazon Elastic Compute Cloud). A few members of the Wareville SOC aren't used to log analysis on the cloud, and with a change of environment comes a change of tools and services needed to perform their duties. Their duties this time are to help Care4Wares figure out what has happened to the charity's funds; to do so, they will need to learn about an AWS service called CloudWatch.

## **Monitoring in an AWS Environment**

### **AWS CloudWatch**

### Overview:

- **Purpose:** Monitoring and observability for AWS environments.
- **Key Functionalities:**
    - Monitoring of system and application metrics.
    - Configuring alarms on metrics.
    - Log management with **CloudWatch Logs** for easy access, monitoring, and storage of logs from various sources.

### Core Components:

1. **Log Events:**
    - Single log entry recording an application "event."
    - Timestamped with log messages and metadata.
2. **Log Streams:**
    - Collection of log events from a single source.
3. **Log Groups:**
    - Collection of log streams, grouped logically (e.g., same service across multiple hosts).

### Requirements:

- **CloudWatch Agent** must be installed on instances to capture application and system metrics.

### Feature Highlight: Filter Patterns

- Enables querying of application logs for better analysis (useful for investigations).

## **AWS CloudTrail**

### Overview:

- **Purpose:** Monitoring actions in AWS environments (e.g., user actions, role permissions, service actions).
- **Core Features:**
    - **Always On:** Enabled by default for all AWS users.
    - **JSON-formatted:** Events captured in CloudTrail JSON format.
    - **Event History:** Records last 90 days of actions, queryable by attributes like "resource type."
    - **Custom Trails:** Define bespoke monitoring scenarios beyond the 90-day retention.
    - **Deliverable Logs:** Optional feature to deliver logs to CloudWatch for unified log management.

### Key Use Cases:

- Capturing actions within AWS services such as:
    - **S3:** Object storage actions.
    - **IAM:** Managing identities and access permissions.

### Benefits for Investigations:

- Tracks actions via management console or AWS CLI.
- Logs provide historical and real-time data for forensic analysis.

### Usage Insights:

- **CloudWatch Logs**: Ideal for system and application-level monitoring.
- **CloudTrail**: Essential for tracking user and service actions for security and compliance.

---

## jq

[Jq](https://jqlang.github.io/jq/) is a lightweight and flexible command line processor that can be used on JSON.

### Using Jq

Example data:

```json
[

{ "book_title": "Wares Wally", "genre": "children", "page_count": 20 },

{ "book_title": "Charlottes Web Crawler", "genre": "young_ware", "page_count": 120 },

{ "book_title": "Charlie and the 8 Bit Factory", "genre": "young_ware", "page_count": 108 },

{ "book_title": "The Princess and the Pcap", "genre": "children", "page_count": 48 },

{ "book_title": "The Lion, the Glitch and the Wardrobe", "genre": "young_ware", "page_count": 218 }

]
```

**Inputs to JQ**:

1. **Filter**: Defines how the JSON data will be processed or accessed.
2. **Input File**: The JSON file to be processed.

- **Starting the Filter**:
    - The filter starts with a `.` which represents the current input (the root of the JSON object or array).
- **Accessing an Array**:
    - Use `[]` to access the elements of an array in the JSON structure.

```bash
$ jq '.[]' book_list.json

{
  "book_title": "Wares Wally",
  "genre": "children",
  "page_count": 20
}
{
  "book_title": "Charlottes Web Crawler",
  "genre": "young_ware",
  "page_count": 120
}
{
  "book_title": "Charlie and the 8 Bit Factory",
  "genre": "young_ware",
  "page_count": 108
}
{
  "book_title": "The Princess and the Pcap",
  "genre": "children",
  "page_count": 48
}
{
  "book_title": "The Lion, the Glitch and the Wardrobe",
  "genre": "young_ware",
  "page_count": 218
}
```

We can grab specific elements from this JSON array using the following command:

```bash
$ jq  '.[] | .book_title' book_list.json

"Wares Wally"
"Charlottes Web Crawler"
"Charlie and the 8 Bit Factory"
"The Princess and the Pcap"
"The Lion, the Glitch and the Wardrobe"
```

---

## **The Peculiar Case of Care4Wares’ Dry Funds**

The responsible ware for the Care4Wares charity drive gave us the following info regarding this incident:

*We sent out a link on the 28th of November to everyone in our network that points to a flyer with the details of our charity. The details include the account number to receive donations. We received many donations the first day after sending out the link, but there were none from the  second day on. I talked to multiple people who claimed to have donated a respectable sum. One showed his transaction, and I noticed the account number was wrong. I checked the link, and it was still the same. I opened the link, and the digital flyer was the same except for the 
account number.*

McSkidy recalls putting the digital flyer, **`wareville-bank-account-qr.png`**, in an Amazon AWS S3 bucket named **`wareville-care4wares`**.

Pointers for now:

- Donations came in successfully the day after the link was distributed.
- However, all donations ceased from the second day onward.
- When a donor provided proof of their transaction—made three days after receiving the link—it revealed an incorrect account number.
- McSkidy had stored the digital flyer in the AWS S3 object named **`wareville-bank-account-qr.png`** under the bucket **`wareville-care4wares`**.
- The original link remains unchanged.

### S3 Bucket Log

```bash
{
  "eventVersion": "1.10",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAXRMKYT5O5Y2GLD4ZG",
    "arn": "arn:aws:iam::518371450717:user/wareville_collector",
    "accountId": "518371450717",
    "accessKeyId": "AKIAXRMKYT5OZCZPGNZ7",
    "userName": "wareville_collector"
  },
  "eventTime": "2024-10-21T22:13:24Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "ListObjects",
  "awsRegion": "ap-southeast-1",
  "sourceIPAddress": "34.247.218.56",
  "userAgent": "[aws-sdk-go/0.24.0 (go1.22.6; linux; amd64)]",
  "requestParameters": {
    "bucketName": "aoc-cloudtrail-wareville",
    "Host": "aoc-cloudtrail-wareville.s3.ap-southeast-1.amazonaws.com",
    "prefix": ""
  },
  "responseElements": null,
  "additionalEventData": {
    "SignatureVersion": "SigV4",
    "CipherSuite": "TLS_AES_128_GCM_SHA256",
    "bytesTransferredIn": 0,
    "AuthenticationMethod": "AuthHeader",
    "x-amz-id-2": "yqniVtqBrL0jNyGlvnYeR3BvJJPlXdgxvjAwwWhTt9dLMbhgZugkhlH8H21Oo5kNLiq8vg5vLoj3BNl9LPEAqN5iHpKpZ1hVynQi7qrIDk0=",
    "bytesTransferredOut": 236375
  },
  "requestID": "YKEKJP7QX32B4NZB",
  "eventID": "fd80529f-d0af-4f44-8034-743d8d92bdcf",
  "readOnly": true,
  "resources": [
    {
      "type": "AWS::S3::Object",
      "ARNPrefix": "arn:aws:s3:::aoc-cloudtrail-wareville/"
    },
    {
      "accountId": "518371450717",
      "type": "AWS::S3::Bucket",
      "ARN": "arn:aws:s3:::aoc-cloudtrail-wareville"
    }
  ],
  "eventType": "AwsApiCall",
  "managementEvent": false,
  "recipientAccountId": "518371450717",
  "eventCategory": "Data",
  "tlsDetails": {
    "tlsVersion": "TLSv1.3",
    "cipherSuite": "TLS_AES_128_GCM_SHA256",
    "clientProvidedHostHeader": "aoc-cloudtrail-wareville.s3.ap-southeast-1.amazonaws.com"
  }
}
```

| **Field** | **Description** |
| --- | --- |
| userIdentity | Details of the user account that acted on an object. |
| eventTime | When did the action occur? |
| eventType | What type of event occurred? (e.g., AwsApiCall or AwsConsoleSignIn, AwsServiceEvent) |
| eventSource | From what service was the event logged? |
| eventName | What specific action occurred? (e.g., ListObjects, GetBucketObject) |
| sourceIPAddress | From what IP did the action happen? |
| userAgent | What user agent was used to perform the action? (e.g., Firefox, AWS CLI) |
| requestParameters | What parameters were involved in the action? (e.g., BucketName) |

We can now understand that the log provides us with the following information:

- The IAM user, **`wareville_collector`**, listed all objects (`ListObjects` event) of the **S3 bucket** named **`aoc-cloudtrail-wareville`**.
- The IP address from which this request originated is **`34.247.218.56`**.
- The user agent indicates that the request was made using the **`AWS SDK tool for Go`**.

More logs are stored on the machine in the `~/wareville_logs` directory.

```bash
ubuntu@tryhackme:~/$ cd wareville_logs
ubuntu@tryhackme:~/$ ls
cloudtrail_log.json  rds.log
```

### Investigating cloudtrail_log.json:

```bash
ubuntu@tryhackme:~/wareville_logs$ jq -r '.Records[] | select(.eventSource == "s3.amazonaws.com" and .requestParameters.bucketName=="wareville-care4wares")' cloudtrail_log.json
```

| Command | Description |
| --- | --- |
| `jq -r 'FILTER' cloudtrail_log.json` | • The **-r** flag tells **jq** to output the results in RAW format instead of JSON. |
| `.Records[]` | • Instructs **jq** to parse the events in the Records container element. The **Records** field is the top element in the JSON-formatted CloudTrail log. |
| `| select(.eventSource == "s3.amazonaws.com" and .requestParameters.bucketName=="wareville-care4wares")` | • Uses the previous command's output, and filters it on the **eventSource** and **requestParameters.bucketName** keys.
• The value **s3.amazonaws.com** is used to filter events related to the Amazon AWS S3 service, and the value  **wareville-care4wares** is used to filter events related to the target S3 bucket. |

To focus on the more significant fields, we can make use of the following command:

```bash
$ jq -r '.Records[] | select(.eventSource == "s3.amazonaws.com" and .requestParameters.bucketName=="wareville-care4wares") | [.eventTime, .eventName, .userIdentity.userName // "N/A",.requestParameters.bucketName // "N/A", .requestParameters.key // "N/A", .sourceIPAddress // "N/A"]' cloudtrail_log.json
```

| Command | Description |
| --- | --- |
| `|
 [.eventTime, .eventName, .userIdentity.userName // 
"N/A",.requestParameters.bucketName // "N/A", .requestParameters.key // 
"N/A", .sourceIPAddress // "N/A"])'` | • The piped filter uses the previous command's output and formats it to only include the defined keys, such as **.eventTime**, **.eventName**, and **.userIdentity.userName**.
• The defined keys are enclosed with square brackets (`[]`)  **to process and create an array with the specified fields from each record**.
•  `// "N/A"` - If the defined key does not have a value, display **N/A** instead. |

To view the summarized information in a tabular form, we can use the following command:

```bash
$ jq -r '["Event_Time", "Event_Name", "User_Name", "Bucket_Name", "Key", "Source_IP"],(.Records[] | select(.eventSource == "s3.amazonaws.com" and .requestParameters.bucketName=="wareville-care4wares") | [.eventTime, .eventName, .userIdentity.userName // "N/A",.requestParameters.bucketName // "N/A", .requestParameters.key // "N/A", .sourceIPAddress // "N/A"]) | @tsv' cloudtrail_log.json | column -t
```

| Command | Description |
| --- | --- |
| `jq -r '["Event_Time", "Event_Name", "User_Name", "Bucket_Name", "Key", "Source_IP"], SELECT_FILTER | SPECIFIC FIELDS'` | • The new command prepends a column header row and is defined using square brackets since it is an array that corresponds to the selected fields.
• A comma is used before the select filter to combine with those of the select filter results we previously used. |
| `| @tsv'` | • Sets each array element, the output processed after the filters, as a line of tab-separated values. |
| `| column -t -s $'\t'` | • It takes the output of the **jq** command, now resulting in tab-separated values, and beautifies its result by processing all tabs and aligning the columns. |

### Key Findings

1. **Suspicious Events in the `wareville-care4wares` Bucket**:
    - Five logged events relate to the bucket.
    - Most events involve a user named **glitch**.
2. **Notable Event**:
    - **Action**: Uploaded a file named `wareville-bank-account-qr.png`.
    - **Timestamp**: November 28th.
    - **Context**: Coincides with no donations being made 2 days after the link was shared.
3. **Anomalous User**:
    - **User glitch**:
        - Previously unknown in the system.
        - No one in city hall with that name.
        - Matches the alias of a known hacker.

### Next Steps

- Investigate the **user `glitch`** to determine:
    - Their access patterns.
    - How they gained access to the system.
- Review security settings for the `wareville-care4wares` bucket.
- Analyze uploaded file (`wareville-bank-account-qr.png`) for malicious content.

### Investigating glitch:

We need to know the following now:

1. What was this anomalous user account been used for, when it was created, and who created it?
2. What event types are included in these log entries?
3. What is the timestamp of these log entries?
4. Which IPs are included in these log entries?
5. What tool/OS was used in these log entries?

```bash
$ jq -r '["Event_Time", "Event_Source", "Event_Name", "User_Name", "Source_IP"],(.Records[] | select(.userIdentity.userName == "glitch") | [.eventTime, .eventSource, .eventName, .userIdentity.userName // "N/A", .sourceIPAddress // "N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'
```

The results show that the user glitch mostly targeted the S3 bucket. The notable event is the **ConsoleLogin** entry, which tells us that the account was used to access the AWS Management Console using a browser.

```bash
$ jq -r '["Event_Time", "Event_type", "Event_Name", "User_Name", "Source_IP", "User_Agent"],(.Records[] | select(.userIdentity.userName == "glitch") | [.eventTime,.eventType, .eventName, .userIdentity.userName //"N/A",.sourceIPAddress //"N/A", .userAgent //"N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'
```

We see 2 user agents here:

| Command | Description |
| --- | --- |
| `S3Console/0.4, aws-internal/3 aws-sdk-java/1.12.750 Linux/5.10.226-192.879.amzn2int.x86_64
 OpenJDK_64-Bit_Server_VM/25.412-b09 java/1.8.0_412 
vendor/Oracle_Corporation cfg/retry-mode/standard` | • This is the userAgent string for the internal console used in AWS. It doesn’t provide much information. |
| `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36` | • This userAgent string provides us with 2 pieces of interesting information.
• The anomalous account uses a Google Chrome browser within a Mac OS system. |

Next, we need to check who created this account. This information can be obtained from IAM events.

```bash
$ jq -r '["Event_Time", "Event_Source", "Event_Name", "User_Name", "Source_IP"], (.Records[] | select(.eventSource == "iam.amazonaws.com") | [.eventTime, .eventSource, .eventName, .userIdentity.userName // "N/A", .sourceIPAddress // "N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'
```

Amongst the multiple `ListPolicies` events, we are able to see a `CreateUser` and a `AttachUserPolicy` event. The source IP where the requests were made is **53.94.201.69, which is the same IP Address used by the Glitch user.**

```bash
$ jq '.Records[] |select(.eventSource=="iam.amazonaws.com" and .eventName== "CreateUser")' cloudtrail_log.json
```

This output of the command above reveals that **McSkiddy** created the Glitch user.

We can see what permissions have been attached to the anomalous user by investigating the `AttachUserPolicy` event. 

```bash
$ jq '.Records[] | select(.eventSource=="iam.amazonaws.com" and .eventName== "AttachUserPolicy")' cloudtrail_log.json
```

McSkiddy  knows that she did not create the anomalous user and did not assign the privileged access. She also doesn’t recognize the IP address involved in the events and does not use a Mac OS; she only uses a Windows machine. All this information is different to the typical IP address and machine used by McSkidy, who would now need to prove that they are innocent.

Investigating the **`53.94.201.69` IP, we can see what users were accessed:**

```bash
$ jq -r '["Event_Time", "Event_Source", "Event_Name", "User_Name", "Source_IP"], (.Records[] | select(.sourceIPAddress=="53.94.201.69") | [.eventTime, .eventSource, .eventName, .userIdentity.userName // "N/A", .sourceIPAddress // "N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'
```

Based on the command output, three user accounts (**mcskidy**, **glitch**, and **mayor_malware**) were accessed from the same IP address.

Now we need to see if these users use just this one IP address:

```bash
$ jq -r '["Event_Time","Event_Source","Event_Name", "User_Name","User_Agent","Source_IP"],(.Records[] | select(.userIdentity.userName=="PLACEHOLDER") | [.eventTime, .eventSource, .eventName, .userIdentity.userName // "N/A",.userAgent // "N/A",.sourceIPAddress // "N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'
```

Replace “PLACEHOLDER” with the respective username.

We can now further investigate the following:

- Which IP does each user typically use to log into AWS?
- Which OS and browser does each user usually use?
- Are there any similarities or explicit differences between the IP addresses and operating systems used?

Findings at this stage include the following:

- The incident starts with an anomalous login with the user account **`mcskidy`**from IP **53.94.201.69**.
- Shortly after the login, an anomalous user account **`glitch`**was created.
- Then, the **`glitch`** user account was assigned **administrato**r permissions.
- The **`glitch`** user account then accessed the **S3 bucket** named **`wareville-care4wares`** and replaced the **`wareville-bank-account-qr.png`** file with a new one. The IP address and User-Agent used to log into the **`glitch`, `mcskidy`**, and **`mayor_malware`** accounts were the same.
- The User-Agent string and Source IP of recurrent logins by the user account **`mcskidy`** are different.

### Gathering more evidence

Wareville Bank has also provided us with the RDS Database logs. These are captured through their CloudWatch, which differs from the CloudTrail logs as they are not stored in JSON format. 

Investigating the RDS Logs:

We can simply use the `grep` command on `rds.log` to check instances of different SQL query actions.

```bash
$ grep INSERT rds.log
```

All `INSERT` queries from the RDS log pertain to who received the donations made we can see in the output the two recipients of all donations made within **November 28th, 2024**.

```bash
---REDACTED FOR BREVITY---
2024-11-28T15:22:17.728Z 2024-11-28T15:22:17.728648Z	  263 Query	INSERT INTO wareville_bank_transactions (account_number, account_owner, amount) VALUES ('8839 2219 1329 6917', 'Care4wares Fund', 342.80)
2024-11-28T15:22:18.569Z 2024-11-28T15:22:18.569279Z	  263 Query	INSERT INTO wareville_bank_transactions (account_number, account_owner, amount) VALUES ('8839 2219 1329 6917', 'Care4wares Fund', 929.57)
2024-11-28T15:23:02.605Z 2024-11-28T15:23:02.605700Z	  263 Query	INSERT INTO wareville_bank_transactions (account_number, account_owner, amount) VALUES ('----- REDACTED ----', 'Mayor Malware', 193.45)
2024-11-28T15:23:02.792Z 2024-11-28T15:23:02.792161Z	  263 Query	INSERT INTO wareville_bank_transactions (account_number, account_owner, amount) VALUES ('----- REDACTED ----', 'Mayor Malware', 998.13)
---REDACTED FOR BREVITY---
```

### Conclusion

The Care4wares Fund received all the donations until it changed into a different account at a specific time. The logs also reveal who received the donations afterwards, given the account 
owner's name. With all these findings, McSkidy confirmed the assumptions made during the investigation of the S3 bucket since the sudden change in bank details was reflected in the 
database logs. The timeline of events collected by McSkidy explains the connection of actions conducted by the culprit.

| **Timestamp** | **Source** | **Event** |
| --- | --- | --- |
| 2024-11-28 15:22:18 | CloudWatch RDS logs (rds.log) | Last donation received by the Care4wares Fund. |
| 2024-11-28 15:22:39 | CloudTrail logs (cloudtrail_log.json) | Bank details update on S3 bucket. |
| 2024-11-28 15:23:02 | CloudWatch RDS logs (rds.log) | First donation received by Mayor Malware. |

Now let’s move to answering the questions in the challenge.

---

## Questions

1. What is the other activity made by the user glitch aside from the ListObject action?
    
    
    We can use the following command to view the activities performed on the wareville-care4wares s3 bucket:
    
    ```bash
    $ jq -r '["Event_Time", "Event_Name", "User_Name", "Bucket_Name", "Key", "Source_IP"],(.Records[] | select(.eventSource == "s3.amazonaws.com" and .requestParameters.bucketName=="wareville-care4wares") | [.eventTime, .eventName, .userIdentity.userName // "N/A",.requestParameters.bucketName // "N/A", .requestParameters.key // "N/A", .sourceIPAddress // "N/A"]) | @tsv' cloudtrail_log.json | column -t
    ```
    
    ![image.png](images/image%201.png)
    
    We can see that the glitch user also performed the `PutObject` action aside from the `ListObject` action.
    
    Ans.: **PutObject**
    

2. What is the source IP related to the S3 bucket activities of the user glitch?

    We can use the following query to retrieve the IP address(es) used for S3 bucket activities performed by the user `glitch` :
    
    ```bash
    $ jq -r '["Event_Time","Event_Source","Event_Name", "User_Name","Source_IP"],(.Records[] | select(.userIdentity.userNam
    e=="glitch" and .eventSource=="s3.amazonaws.com") | [.eventTime, .eventSource, .eventName, .userIdentity.userName // "N/A", .sourceIPAddress // "N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\
    ```
    
    This query limits the selection to only S3 related actions performed by glitch.
    
    ![image.png](images/image%202.png)
    
    Here we can see that the IP address where these actions originate is `53.94.201.69` .
    
    Ans.: **53.94.201.69**

    
3. Based on the eventSource field, what AWS service generates the ConsoleLogin event?

    We can use the following query to filter out the value in the `eventSource` field for the `ConsoleLogin` events:
    
    ```bash
    $ jq -r '["Source", "Name"],(.Records[] | select(.eventName == "ConsoleLogin") | [.eventSource, .eventName]) | @tsv' cloudtrail_log.json | column -t -s $'\t'
    ```
    
    ![image.png](images/image%203.png)
    
    Here we can see that the source associated with the `ConsoleLogin` events is **`signin.amazonaws.com` .**
    
    Ans.: **signin.amazonaws.com**
    
4. When did the anomalous user trigger the ConsoleLogin event?

    We know from our investigation that the anomalous user is `glitch`.  Therefore we need to know when this user performed the `ConsoleLogin` activity. We can do that by using the following query:
    
    ```bash
    $ jq -r '["Time", "Name", "User"],(.Records[] | select(.eventName == "ConsoleLogin" and .userIdentity.userName == "glitch") | [.eventTime, .eventName, .userIdentity.userName]) | @tsv' cloudtrail_log.json | column -t -s $'\t'
    ```
    
    ![image.png](images/image%204.png)
    
    Ans.: **2024-11-28T15:21:54Z**
    

5. What was the name of the user that was created by the mcskidy user?

    We can obtain this information using the following query:
    
    ```bash
    $ jq -r '.Records[] | select(.eventName == "CreateUser" and .userIdentity.userName == "mcskidy")' cloudtrail_log.json
    ```
    
    ![image.png](images/image%205.png)
    
    From the `requestParameters` field, we can see that the userName associated with the `CreateUser` event is **glitch.**
    
    Ans.: **glitch**
    
6. What type of access was assigned to the anomalous user?
    
    We can obtain this information from the `AttachUserPolicy` event associated with the glitch user. The `requestParameters` field should contain our answer. The query used to obtain this is:

    
    ```bash
    $ jq -r '.Records[] | select(.eventName == "AttachUserPolicy" and .userIdentity.userName == "mcskidy")' cloudtrail_log.json
    ```
    
    ![image.png](images/image%206.png)
    
    The `policyName` attribute contains the value `arn:aws:iam::aws:policy/AdministratorAccess`.  From the [AWS Documentation](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AdministratorAccess.html), we see that this policy is used to grant a user complete access to AWS services and resources.
    
    Ans.: **AdministratorAccess**
  

7. Which IP does Mayor Malware typically use to log into AWS?
    
    We can grab the list of usernames used to log in to AWS first, by using the following command:
    
    ```bash
    $ jq -r '.Records[]' cloudtrail_log.json | grep userIdentity -A3 | grep arn | sort -u
    ```
    
    ![image.png](images/image%207.png)
    
    The user name of Mayor Malware is `mayor_malware` .
    
    Now we can filter the login events in the `cloudtrail_log.json` file for our user of interest using the following query:
    
    ```bash
    $ jq -r '.Records[] | select(.eventName == "ConsoleLogin" and .userIdentity.userName == "mayor_malware")' cloudtrail_log.json | grep "sourceIPAddress"
    ```
    
    ![image.png](images/image%208.png)
    
    We can see that `mayor_malware` performed the login activity 5 times (same information is present in our notes above), and all 5 times he used the same IP Address `53.94.201.69`.
    
    Ans.: **53.94.201.69** 
   

8. What is McSkidy's actual IP address?
    
    From our incident notes, we know that the incident began with an anomalous login for the `mcskidy` account, which meant the login happened from an IP address different from the one mcskidy usually uses. The actual IP address can therefore be retrieved using this command:
    
    ```bash
    $ jq -r '.Records[] | select(.eventName == "ConsoleLogin" and .userIdentity.userName == "mcskidy")' cloudtrail_log.json
     | grep "sourceIPAddress"
    ```
    
    ![image.png](images/image%209.png)
    
    Ans.: **31.210.15.79**

    
9. What is the bank account number owned by Mayor Malware?
    
    This information can be obtained from the RDS logs. We know every time a new transaction is performed, an `INSERT` query runs on the database containing details of the recipient bank account. The query will provide us with the bank account number of Mayor Malware:
    
    ```bash
    grep INSERT rds.log | grep "Mayor Malware"
    ```
    
    ![image.png](images/image%2010.png)
    
    Here we can see over multiple transactions to Mayor Malware’s account, the `account_number` value remains constant. We can therefore conclude that this is indeed the account number we are after.
    
    Ans.: **2394 6912 7723 1294**