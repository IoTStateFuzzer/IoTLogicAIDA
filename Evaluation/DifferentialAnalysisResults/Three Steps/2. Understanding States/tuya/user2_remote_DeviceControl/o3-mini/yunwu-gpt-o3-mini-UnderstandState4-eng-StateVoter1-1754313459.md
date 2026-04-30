# Base Model
| State | Final Semantic Description |
|-------|----------------------------|
| s0    | Initial state. |
| s1    | user1 has added the device instance once (device addition count = 1) with no sharing action performed; as a result, user2 holds no permissions. |
| s2    | Error state indicating an invalid or failed operation. |
| s3    | user1 added the device instance and then executed a direct device sharing action via SharePlug, granting user2 control permissions over that specific device instance only (non-family, temporary permission). |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state: No device is added or shared; neither user1 nor user2 holds any device permissions. |
| s1 | User1 has added the device once (device addition count = 1) without initiating any sharing; as a result, user2 has no permissions. |
| s2 | Error state due to an invalid or failed operation sequence. |
| s3 | User1 added the device and initiated a direct sharing action (SharePlug) under direct device sharing rules, automatically granting user2 an instance-specific, temporary control permission (invitation automatically accepted if applicable). |
| s4 | User1’s device remains added and shared, and user2 has exercised control, thereby confirming that the granted direct sharing permission applies only to that specific device instance. |
| s5 | After user2 controlled the device, user1 revoked the sharing (UnsharePlug), which withdraws the instance-specific direct sharing permission while the device remains added. |
| s6 | User1 removed the device after sharing and user2’s control action, which revokes any instance-based control permission and resets the device addition state. |
