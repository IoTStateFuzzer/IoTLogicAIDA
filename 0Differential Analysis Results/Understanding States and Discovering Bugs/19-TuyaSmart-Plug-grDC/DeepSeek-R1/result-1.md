

# State Semantic mapping table
| State | Semantic Description |
|-------|-----------------------|
| 0     | Initial state with no device added. |
| 1     | User1 has added the device (plug). Only User1 has control permissions. |
| 2     | Error state where no actions are executable. |
| 3     | User1 shared the device with User2. Both User1 and User2 have control permissions. |
| 4     | User2 executed remote DeviceControl after sharing, storing the action in their knowledge set. Both users retain control permissions. |
| 5     | User1 revoked User2's permissions via UnsharePlug. User2 retains replay knowledge but has no legitimate access. |
| 6     | User1 removed the device, revoking all permissions. System returns to a device-less state. |

# Base model report
Every thing is OK.

# Divergent model report
Every thing is OK.