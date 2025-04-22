# State Semantic Mapping Table

| State | Semantic Description |
|-------|----------------------|
| s0    | Indicates the initial status |
| s1    | User1 has bound the device (plug) |
| s2    | Error state where no operations can be performed |
| s3    | User1 has shared the plug with user2, both have control permissions |
| s4    | Same as s3, but user2 has knowledge to perform remote device control via API hooking |
| s5    | User1 has unshared the plug, revoking user2's permissions, but user2 retains knowledge for remote control |
| s6    | User1 has removed the device, revoking all permissions from user2, but user2 retains knowledge for remote control |

# Base Model Report

Every thing is OK.

# Divergent Model Report

Every thing is OK.

The divergent model introduces states where user2 retains knowledge for remote control even after permissions are revoked (states s5 and s6). However, attempts to use this knowledge result in failed operations, as seen in state s6 where user2's remote control attempt fails. This indicates that the system correctly handles permission revocations and prevents unauthorized control, thus maintaining the integrity and confidentiality of the device control.