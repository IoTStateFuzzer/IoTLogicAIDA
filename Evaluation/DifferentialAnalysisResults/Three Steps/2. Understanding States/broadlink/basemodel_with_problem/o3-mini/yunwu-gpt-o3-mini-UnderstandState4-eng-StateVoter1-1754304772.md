# Base Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state. |
| s1 | Error state. |
| s2 | user1 added one device instance; user2 has not been invited and thus holds no permissions. |
| s3 | user1 added a device and sent an invitation; user2 is invited but has not yet accepted. |
| s4 | user1 issued an invitation without adding a device; user2 remains pending invitation with no acceptance. |
| s5 | user1 added a device and sent an invitation; user2 scanned the QR code but has not yet accepted the invitation. |
| s6 | user1 added a device and sent an invitation; user2 scanned and accepted the invitation, thereby becoming a family member with permanent control rights. |
| s7 | user1 added a device and issued a duplicate invitation which user2 accepted, establishing family membership with permanent control rights. |
| s8 | user1 sent an invitation without adding a device; user2 scanned and accepted it, establishing family membership that will apply once a device is bound. |
| s9 | user1 issued multiple invitations without adding a device; user2 accepted one, thereby establishing family membership pending a device instance. |
| s10 | user1 sent an invitation and user2 scanned the QR code but did not accept, so no permissions are granted. |
| s11 | user1 sent an invitation that was accepted, but then revoked user2’s family membership via RemoveFromHome, thereby nullifying user2’s control rights. |
| s12 | After an accepted invitation was revoked, user1 added a device; as a result, user2 holds no control rights over the current device instance. |
| s13 | user1 added a device and sent an invitation that was accepted; however, user1 subsequently revoked the invitation (removing user2 from home), causing user2 to lose control rights. |
| s14 | user1 added a device and sent an invitation that was accepted, but later revoked family membership, thereby revoking user2’s control rights. |
| s15 | user1 added a device and had user2 accept the invitation; however, after revoking user2’s family membership and removing the device, no active device instance exists and user2 holds no rights. |
| s16 | user1 sent an invitation that was accepted, but then revoked user2’s family membership without any device being added, canceling user2’s permissions. |
| s17 | user1 invited user2 and received acceptance, but then revoked the family membership before adding a device; a subsequent QR scan by user2 does not grant any control rights. |
| s18 | user1 added a device and invited user2, who accepted; however, after the invitation was revoked, a later QR scan by user2 does not reinstate control rights. |
| s19 | user1 invited user2 and the invitation was accepted but later revoked; a subsequent QR scan by user2 does not restore control rights, with no device currently added. |
| s20 | user1 added a device and invited user2, who accepted to become a family member; however, user2 subsequently quit home, thereby relinquishing control rights. |
| s21 | user1 added a device and had user2 accept the invitation; later, user1 revoked family membership and removed the device, and even after re-adding it, user2 holds no permissions on the new instance. |
| s22 | user1 added a device and obtained invitation acceptance from user2, but subsequently revoked the family membership and cycled the device (removal and re-addition), resulting in user2 having no control rights on the current device. |
| s23 | user1 added a device and secured invitation acceptance from user2, but then revoked membership and removed the device; a subsequent QR scan on the re-added device does not confer permission to user2. |
| s24 | user1 sent an invitation that was accepted, but then revoked the family membership before adding the device; consequently, user2 loses control rights on any device instance. |
| s25 | user1 sent an invitation that was accepted by user2, but thereafter user2 quit home, thereby losing control rights. |
| s26 | user1 added a device and had user2 accept the invitation, but subsequently revoked the family membership and removed the device; as a result, user2 holds no control rights. |
| s27 | user1 added a device and invited user2, who accepted; however, after revoking family membership and removing the device, a later QR scan by user2 does not restore access. |
| s28 | user1 revoked a previously accepted invitation, then added a device and issued a new invitation that user2 scanned but has not yet accepted, leaving no granted control rights. |
| s29 | Without an active device, user1 reissued a new invitation after revoking a previous one; user2 scanned the QR code but acceptance remains pending, so no permissions are granted. |
| s30 | user1 added a device and initiated an invitation cycle that was accepted and later revoked; following a new invitation accompanied by a QR scan that has not been accepted, user2 remains without control rights despite the active device. |
| s31 | user1 added a device and invited user2, whose invitation was accepted but later revoked; after the device was removed, a new invitation was issued and awaits acceptance, leaving user2 without control. |
| s32 | user1 added a device and processed an invitation that was accepted and then revoked, removed and re-added the device, and issued a new invitation that only saw a QR scan; consequently, user2 is in a pending state without active permissions. |
| s33 | user1 sent invitations without adding a device; user2 scanned the QR code but did not accept, so no control rights are granted. |
| s34 | user1 added a device and sent multiple invitations, with user2 scanning the QR code but not accepting; as a result, user2 does not obtain control rights. |

