# State Semantic mapping table
|State | semantic description|
|-----|---------|
|s0 | Indicates the initial status|
|s1 | Device is added by user1, user1 has control|
|s2 | No device is added, or no user has control|
|s3 | Device is shared by user1, user1 has control, user2 can accept share|
|s4 | Device is shared and accepted by user2, both users have control|
|s5 | Device is removed by user1, no user has control|
|s6 | Device is added again by user1 after removal, user1 has control|
|s7 | Device is shared again by user1 after being added, user1 has control, user2 can accept share|
|s8 | Device is shared and accepted by user2 after being added again, both users have control|

# Base model report
Every thing is OK.

# Divergent model report
Every thing is OK.

The analysis of both the base model and the divergent model shows that the state transitions and permissions are handled correctly according to the expected business logic and security requirements. There are no vulnerabilities such as unauthorized access or information leakage detected in the divergent model compared to the base model. The divergent model correctly handles the attacker's capabilities and restrictions, ensuring that the system's integrity and confidentiality are maintained.