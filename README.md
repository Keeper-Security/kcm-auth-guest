kcm-auth-guest
==============

**kcm-auth-guest** is an authentication extension for KCM and Apache Guacamole
that automatically authenticates all users as "guest" users within a
predefined guest group. Users inherit whatever permissions are granted to that
group.

If authentication should additionally be allowed by non-guest users, the IP
addresses and subnets of non-guest users can be configured within
`guacamole.properties`.

Configuration Properties
------------------------

Property Name            | Description
------------------------ | -----------
`kcm-non-guest-networks` | A comma-separated list of all IP addresses and/or subnets (CIDR notation) that should not be considered guest users. If omitted, absolutely all users will be considered guest users.
`kcm-guest-group`        | The name of the group that should be assigned to all guest users. If omitted, the default group name `guests` will be used.
