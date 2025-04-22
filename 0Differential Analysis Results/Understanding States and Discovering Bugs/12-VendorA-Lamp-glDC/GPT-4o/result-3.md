# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Indicates the initial status|
|1 | Error state where no actions can be performed|
|2 | Error state where no actions can be performed|
|3 | User 1 has invited and User 2 has accepted the invitation, User 2 has control permissions|
|4 | User 1 has invited and User 2 has accepted the invitation, User 2 has control permissions|
|5 | User 1 has invited and User 2 has accepted the invitation, User 2 has control permissions, User 2 has executed local device control|
|6 | User 1 has invited and User 2 has accepted the invitation, User 2 has control permissions, User 2 has executed local device control, User 1 has removed the device|
|7 | User 1 has invited and User 2 has accepted the invitation, User 2 has control permissions, User 2 has executed local device control, User 1 has removed User 2 from the home|
|8 | User 1 has invited and User 2 has accepted the invitation, User 2 has control permissions, User 2 has executed local device control, User 1 has removed User 2 from the home, User 1 has removed the device|
|9 | User 1 has invited and User 2 has accepted the invitation, User 2 has control permissions, User 2 has executed local device control, User 1 has removed User 2 from the home, User 1 has removed the device, User 1 has added the device again|
|10 | User 1 has invited and User 2 has accepted the invitation, User 2 has control permissions, User 2 has executed local device control, User 1 has removed User 2 from the home, User 1 has removed the device, User 1 has added the device again, User 1 has removed the device again|

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Unauthorized Device Control
**Impact effect**: User 2 can control the device even after being removed from the home by User 1.

**Attack Path** :
1. User 1 invites User 2 and User 2 accepts the invitation (s0 -> s3).
2. User 2 executes local device control (s3 -> s5).
3. User 1 removes User 2 from the home (s5 -> s7).
4. User 2 still has the ability to control the device locally (s7 -> s7).

## Vulnerability 2: Unauthorized Device Control After Removal
**Impact effect**: User 2 can control the device even after User 1 removes the device and adds it again.

**Attack Path** :
1. User 1 invites User 2 and User 2 accepts the invitation (s0 -> s3).
2. User 2 executes local device control (s3 -> s5).
3. User 1 removes the device (s5 -> s6).
4. User 1 adds the device again (s6 -> s10).
5. User 2 still has the ability to control the device locally (s10 -> s5).