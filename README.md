# Add link-layer (MAC) address to all Zeek logs

This script attempts to add the originator (source) and responder (destination) mac address to all logs that have the `conn_id` (`id`) field.

This script borrows heavily from the work done by the [corelight](https://corelight.com/ ) team's [log-add-vlan-everywhere](https://github.com/corelight/log-add-vlan-everywhere) plugin.
