## Description

I use this to manage some instances in hetzner cloud. **Not open for pull requests/issues/feedback; it won't work for you, and it's mostly spaghetti code.** :spaghetti:

The idea is that servers can be created and deleted based on specific snapshot labels and naming convention, and the trick is that snapshots are created before deleting servers, so it's easy to recreate the infrastructure using those.

I'm only making the repo public so I can use it easily with [my ansible setup script](https://github.com/matuzalemmuller/setup-workstation), and so I have a public example on how to build a .deb package from a python3 virtualenv using [dh-virtualenv](https://github.com/spotify/dh-virtualenv).

The main library used to manage the infrastructure is [hcloud](https://hcloud-python.readthedocs.io/en/stable/). Terraform didn't really suit my needs for this project, so I put this script together to make it easier.

## Prerequisites

- [Create API token](https://docs.hetzner.com/cloud/api/getting-started/generating-api-token/)
- A bunch of existing snapshots in hcloud with specific labels and naming conventions. Seriouly, this won't work for you.
- If building the dpkg, install:
  - debhelper
  - dh-virtualenv
  - libffi-dev
  - python3
  - python3-setuptools
  - python3-pip

## Installation

Python package, virtualenv, dpkg. Pick your poison, but again, it won't work for you.

## Usage

Last warning: this won't work for you. So, not putting a lot of details here, just the help:

```
root@a867062d6e20:/hcloud-manager# hcloud-manager --help
usage: hcloud-manager [-h] [--add-token | --create | --delete-with-backup | --delete-no-backup | --list] [--arm-nodes ARM_NODES] [--x86-nodes X86_NODES]

Creates and deletes my VMs in hetzner cloud. I use this for quickly creating and deleting a small k3s cluster.

options:
  -h, --help            show this help message and exit
  --add-token           add hcloud token to config
  --create              create servers
  --delete-with-backup  take snapshots and delete servers
  --delete-no-backup    delete servers without taking snapshot
  --list                list running servers
  --arm-nodes ARM_NODES
                        Number of arm64 nodes. Must be equal or larger than 1
  --x86-nodes X86_NODES
                        Number of x86 nodes. Must be equal or larger than 1
```
