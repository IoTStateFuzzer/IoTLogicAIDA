# State Semantic mapping table

| State | Semantic description |
| ----- | -------------------- |
| s0    | Initial state, user1 can add device, user2 has no control permissions, no operations can be performed by user2. |
| s1    | User1 has successfully added a device and shared camera. User2 has no permissions yet. |
| s2    | User1 can control devices but user2 has no permissions. No actions available for user2. |
| s3    | User1 can control devices, share camera (operation failed due to limitations), user2 can accept device sharing. |
| s4    | User1 can control devices, remove device, or unshare camera. User2 can accept device share and control the device after successful sharing. |
| s5    | Device is removed, no further operations can be performed. User2 cannot accept expired invitation. |
| s6    | User1 can control devices, share camera (operation successful), remove device, or unshare camera. User2 cannot accept expired invitation. |
| s7    | User1 can control devices, remove device, or unshare camera. User2 can accept the device share successfully. |
| s8    | User1 can control devices, share camera (operation failed), remove device, or unshare camera. User2 cannot accept the invitation if already in the family. |
| s9    | User1 can control devices, share camera (operation failed), remove device, or unshare camera. User2 can control devices after device sharing is accepted. |
| s10   | User1 can control devices, share camera, or remove device. User2 cannot accept share invitation if it doesn't exist. |
| s11   | User1 can control devices, share camera, or remove device. User2 cannot perform any operation. |
| s12   | User1 can control devices, share camera, remove device, or unshare camera. User2 can control devices after successful sharing. |
| s13   | User1 can control devices, share camera (operation failed), remove device, or unshare camera. User2 can accept device share after device removal. |
| s14   | User1 can control devices, share camera (operation failed), remove device, or unshare camera. User2 can accept device share successfully. |
| s15   | User1 can control devices, share camera (operation succeeded), remove device, or unshare camera. User2 cannot accept invitation if expired. |
| s16   | User1 can control devices, share camera (operation succeeded), remove device, or unshare camera. User2 cannot accept invitation if expired. |
| s17   | User1 can control devices, share camera (operation failed), remove device, or unshare camera. User2 can accept device share successfully. |
| s18   | User1 can control devices, share camera (operation failed), remove device, or unshare camera. User2 can control the device successfully. |
| s19   | User1 can control devices, share camera (operation failed), remove device, or unshare camera. User2 can successfully control the device after accepting device sharing. |
| s20   | User1 can control devices, share camera (operation succeeded), remove device, or unshare camera. User2 cannot accept invitation if expired. |
| s21   | User1 can control devices, share camera (operation failed), remove device, or unshare camera. User2 can accept device share successfully. |
| s22   | User1 can control devices, share camera (operation failed), remove device, or unshare camera. User2 can successfully control the device after sharing. |

Everything is OK.