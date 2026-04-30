# Base Model
| State | Final Consolidated Semantic Description |
|-------|-----------------------------------------|
| 0     | Initial state with no device added and no invitation sent; user2 not invited and has no control permissions. |
| 1     | user1 added the device once; user2 not invited and has no control permissions. |
| 2     | Error state. |
| 3     | user1 added the device once and invited user2 as a family member; user2 has not accepted the invitation and thus has no control permissions. |
| 4     | user1 invited user2 as a family member without adding the device; user2 has not accepted the invitation and has no control permissions. |
| 5     | user1 added the device once and invited user2 as a family member; user2 scanned the QR code but has not accepted the invitation yet and has no control permissions. |
| 6     | user1 added the device once and invited user2 as a family member; user2 accepted the invitation and, as family member, has permanent control rights over all user1 devices regardless of device addition count. |
| 7     | user1 added the device once and invited user2 twice; user2 accepted the last invitation and, as family member, has permanent control rights over all user1 devices. |
| 8     | user1 invited user2 as a family member without adding the device; user2 accepted the invitation and, as family member, has permanent control rights over all user1 devices despite zero device additions. |
| 9     | user1 invited user2 twice as a family member without adding the device; user2 accepted the last invitation and, as family member, has permanent control rights over all user1 devices. |
| 10    | user1 invited user2 as a family member without adding the device; user2 scanned the QR code but has not accepted the invitation and has no control permissions. |
| 11    | user1 added the device once; user2 accepted family membership but then quit the family, losing all family status and control permissions. |
| 12    | user1 invited user2 as family member without adding the device; user2 accepted the invitation but then quit family membership, losing all control permissions and status. |
| 13    | user1 invited user2 twice as family member without adding the device; user2 has not accepted the invitation and has no control permissions. |
| 14    | user1 added the device once and invited user2 twice; user2 scanned the QR code but has not accepted the last invitation and therefore has no control permissions or family status. |

# Divergent Model
| State | Final Semantic Description |
|-------|----------------------------|
| s0    | Initial state with no device added and no permissions granted. |
| s1    | user1 has added the device once; user2 is neither invited nor has any permissions or family membership. |
| s2    | Error state. |
| s3    | user1 has not added the device; user2 is invited as a family member but has not scanned or accepted the invitation; no control rights granted. |
| s4    | user1 has not added the device; user2 has scanned the invitation QR code but not yet accepted; user2 remains without control rights or family membership. |
| s5    | user1 has not added the device; user2 has scanned and accepted the family invitation; user2 is a family member with permanent control rights across all user1 devices despite device absence. |
| s6    | user1 has not added the device; user1 invited user2 twice; user2 accepted the invitation, becoming family member with permanent control rights on all devices. |
| s7    | user1 has added the device once; user1 invited user2 (once or twice); user2 scanned and accepted the invitation; user2 is a family member with permanent control rights including current device. |
| s8    | user1 has added the device once; user2 scanned and accepted family invitation; user2 holds family membership with permanent control rights over all user1 devices, including the added device. |
| s9    | user1 has invited user2; user2 scanned and accepted the invitation but subsequently quit family membership; user2 no longer has family rights or device control permissions. |
| s10   | user1 added the device once and invited user2; user2 scanned the invitation QR code but has not accepted yet; user2 has no permissions or family membership. |
| s11   | user1 added the device once and invited user2; user2 neither scanned nor accepted the invitation; no permissions or family membership granted. |
| s12   | user1 added the device once and invited user2; user2 accepted the invitation but then quit family membership; user2 no longer has permissions. |
| s13   | user1 added the device once and invited user2 twice; user2 scanned the invitation but has not accepted the second invitation; user2 lacks current family membership and control rights. |
| s14   | user1 invited user2 twice without adding device; user2 scanned but has not accepted the latest invitation; user2 does not have family membership or control rights. |
| s15   | user1 added the device once and invited user2 twice; user2 accepted the invitation and is presently a family member with active control rights over devices including the added device. |
| s16   | user1 added the device once, invited user2 twice; user2 accepted and controls device; user1 removed the device; user2 remains family member with permanent control rights over all user1 devices despite device removal. |
| s17   | user1 added then removed the device after inviting user2 twice; user2 accepted invitation but quit family membership after device removal; user2 no longer has permissions or control rights. |
| s18   | user1 removed and re-added the device once; user2 quit family membership after accepting; user2 no longer has family rights or device control permissions. |
| s19   | user1 added the device once and invited user2 twice; user2 accepted and controlled device, then quit family membership; permissions and control rights are revoked. |
| s20   | user1 added device once and invited user2 twice; user2 quit family membership then rescanned the invitation QR code but has not accepted again; user2 has no permissions. |
| s21   | user1 removed and re-added device once; user2 quit family membership, rescanned invitation QR code, but has not accepted any new invitation; no permissions granted. |
| s22   | user1 removed device; user2 quit family membership and rescanned invitation without acceptance; no permissions or control rights. |
| s23   | user1 removed device; user2 quit family membership, rescanned invitation; user1 re-invited user2; user2 has a pending invitation but has not accepted; no permissions yet. |
| s24   | user1 removed and re-added device once; user2 quit family membership, rescanned invitation; user1 re-invited user2; user2 has not accepted yet; no permissions granted. |
| s25   | user1 added device once; user2 quit family membership, rescanned invitation; user1 re-invited user2; user2 has pending acceptance; no control rights. |
| s26   | user1 added device once and invited user2; user2 accepted and is family member with control rights; user1 removed device; user2 retains family membership and control permissions on all devices despite removal. |
| s27   | user1 removed device after previously inviting user2 who accepted; user2 quit family membership after removal; user2 no longer has family rights or control permissions. |
| s28   | user1 removed and re-added device once; user2 accepted family invitation but quit family subsequently; no family membership or control rights remain. |
| s29   | user1 removed and re-added device once; user2 accepted family invitation and did not quit family; user2 remains family member with permanent control rights across devices. |
| s30   | user1 added device once and invited user2; user2 accepted invitation and currently holds family member status with active control over devices including the added device. |
| s31   | user1 added device once and invited user2; user2 accepted and controlled the device but later quit family membership; user2 lost all permissions and control rights. |
| s32   | user1 removed then re-added the device once; user2 accepted invitation and remains family member with permanent control rights despite device removal and re-addition. |

