# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Indicates the initial status|
|1 | User1 has bound the device (plug)|
|2 | No device is bound, or no permissions are granted to any user|
|3 | User1 has shared the plug with user2, and user2 has accepted the share|
|4 | User2 has control over the device, and the attacker's knowledge set is filled (can perform API hooking)|
|5 | User1 has unshared the plug, but user2's knowledge set remains filled (can perform API hooking)|
|6 | User1 has removed the device, revoking all permissions, but user2's knowledge set remains filled (can perform API hooking)|
|7 | User1 has re-added the device after removal, user2's knowledge set remains filled but no control permissions|
|8 | User1 has re-shared the plug with user2 after re-adding the device, user2 has control permissions and knowledge set filled|

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Unauthorized Control Retention
**Impact effect**: User2 retains the ability to control the device even after permissions are supposedly revoked, due to knowledge set retention allowing API hooking.

**Attack Path** :
1. User2 accumulates knowledge through successful control actions in state s3.
2. User1 unshares the plug in state s3, transitioning to state s5, but user2's knowledge set remains filled.
3. User2 can still perform API hooking to control the device in state s5 despite having no UI control permissions.