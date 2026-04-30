# Base Model
| State | Final Semantic Description |
|-------|----------------------------|
| s0 | Initial state: no device has been added and no invitation has been sent; user2 has no permissions. |
| s1 | Error state; the operation sequence is invalid. |
| s2 | user1 added the device once with no invitation issued, so user2 has no access. |
| s3 | user1 added the device once and sent an invitation; user2 has been invited but has not yet accepted, leaving permission pending. |
| s4 | user1 issued an invitation without adding a device; user2 remains in a pending (unaccepted) state. |
| s5 | user1 added the device and sent an invitation; user2 scanned the QR code but has not yet completed acceptance, so permission remains pending. |
| s6 | user1 added the device and sent an invitation that was both scanned and accepted; as a result, user2 becomes a family member with permanent control rights. |
| s7 | user1 added the device and issued two invitations, with user2 accepting the later one; user2 is established as a family member with permanent control. |
| s8 | user1 sent an invitation without adding a device; user2 scanned and accepted the invitation, thereby becoming a family member. |
| s9 | user1 issued repeated invitations without any device addition, and user2 accepted a later invitation, establishing family membership. |
| s10 | user1 sent an invitation and user2 scanned the QR code, but without a completed acceptance, user2’s status remains pending. |
| s11 | user1 sent an invitation that was scanned and accepted, but subsequently revoked user2’s membership via RemoveFromHome, resulting in loss of control rights. |
| s12 | user1 completed an invitation (with acceptance from user2) but then revoked the membership and later added the device; consequently, user2 loses control rights. |
| s13 | user1 added the device and received invitation acceptance from user2, but later revoked the family membership, so user2 no longer has control rights. |
| s14 | user1 added the device and had user2 accept the invitation; however, a subsequent removal action revoked user2’s membership and control rights. |
| s15 | user1 added the device and obtained invitation acceptance from user2 (granting family membership), then revoked that acceptance and removed the device, leaving no active device and no permission for user2. |
| s16 | user1 issued an invitation (without adding a device) that was accepted, but later removed user2 from home, so user2’s control is revoked. |
| s17 | user1 had user2 accept an invitation (granted temporary family status) but then revoked it; after adding a device, a subsequent QR scan without a matching acceptance left user2 without valid control rights. |
| s18 | user1 added the device and processed an invitation that was accepted but later revoked; a subsequent QR scan did not lead to acceptance, so user2 remains without control. |
| s19 | Without adding a device, user1 sent an invitation that was accepted then revoked; a later QR scan did not restore acceptance, leaving user2 without permission. |
| s20 | user1 added the device and completed an invitation acceptance (granting family membership), but user2 later quit home, thereby relinquishing permanent control rights. |
| s21 | user1 added the device and received invitation acceptance from user2 but then revoked the membership and removed the device before re-adding it; consequently, user2 loses permanent control rights despite the active device. |
| s22 | user1 added the device and, after multiple invitation actions that led to acceptance, later revoked the membership and performed a device removal/re-addition; the final state is one active device with user2’s family membership revoked. |
| s23 | user1 added the device and completed an invitation that was subsequently revoked; after removing and re-adding the device, an extra QR scan without a follow-up acceptance left user2 without control rights. |
| s24 | user1 sent an invitation that was accepted by user2 but then revoked it before adding the device; as a result, even after the device is added, user2’s family membership remains cancelled. |
| s25 | user1 sent an invitation that was accepted by user2, but then user2 quit home; with no device added, user2 loses any control rights. |
| s26 | user1 added the device and completed an invitation acceptance that was later revoked, followed by removal of the device; no active device remains and user2 has no access. |
| s27 | user1 added the device and obtained invitation acceptance, which was subsequently revoked; after the device was removed and a further QR scan occurred without new acceptance, user2 remains without permission. |
| s28 | user1 initially completed an invitation (with acceptance) that was later revoked, then added the device and issued a new invitation that remains pending; thus, user2 does not have confirmed control rights. |
| s29 | Without any device added, user1 sent an invitation that was accepted and then revoked; a subsequent QR scan and new invitation left user2 pending, without control rights. |
| s30 | user1 added the device and processed an invitation acceptance that was later revoked; following a new invitation workflow (with a QR scan but no acceptance), user2’s status remains pending despite the active device. |
| s31 | user1 added the device and received invitation acceptance which was then revoked; after removing the device and issuing a new invitation (following a QR scan), there is no active device and user2 remains pending. |
| s32 | user1 added the device, then revoked a previously accepted invitation, removed and re-added the device, and finally issued a new invitation that was QR scanned but not accepted; the final state has one active device while user2’s status is pending. |
| s33 | user1 issued invitation actions that included a QR scan without a final acceptance and did not add a device; as a result, user2 remains in a pending state with no confirmed membership. |
| s34 | user1 added the device and sent invitations that resulted in a QR scan but no final acceptance; therefore, with one active device present, user2’s invitation remains pending. |

