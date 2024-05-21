## Description

Python script to manage my hetzner servers used for k3s studying.

- [Link to hcloud documentation](https://hcloud-python.readthedocs.io/en/stable/)
- [Link to hetzner dashboard](https://console.hetzner.cloud/projects/2839568/servers).

## Prerequisites

- [Create API token](https://docs.hetzner.com/cloud/api/getting-started/generating-api-token/) and place it in the `manager.py` file.
- Install [hcloud](https://github.com/hetznercloud/hcloud-python) via `requirements.txt`

## Usage

```sh
# Create default number of servers:
#   1 control plane
#   1 maria db
#   2 arm nodes
#   1 x86 node
./manager.py --create

# Create custom number of servers:
#   1 control plane
#   1 maria db
#   3 arm nodes
#   3 x86 node
./manager.py --create --arm-nodes 3 --x86-nodes 3

# Take snapshots and delete all servers
./manager.py --delete
```
