#!/usr/bin/env python3

import argparse
import logging
import sys

from hcloud import Client
from hcloud.locations import Location
from hcloud.images import Image
from hcloud.networks.domain import Network
from hcloud.server_types import ServerType
from hcloud.servers.domain import ServerCreatePublicNetwork
from hcloud.ssh_keys import SSHKey

# Hcloud token. Needs read and write permissions.
# https://docs.hetzner.com/cloud/api/getting-started/generating-api-token/
HCLOUD_TOKEN = ""


def create_logger():
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] - %(levelname)s - %(message)s",
        datefmt="%d/%b/%Y %H:%M:%S",
        stream=sys.stdout,
    )
    return logging


def get_images(htz_client: Client, state: str):
    """
    Gets snapshot ID for all servers.

    :param htz_client: hcloud client with valid token to perform read operations
    :param state:      snapshot state. Valid values are 'old' and 'current'
    :return images:    list of snapshot IDs.
    """
    images = dict()

    img_cplane = htz_client.images.get_all(
        label_selector=f"state={state},arch=arm64,role=control-plane"
    )
    img_node_arm = htz_client.images.get_all(
        label_selector=f"state={state},arch=arm64,role=node"
    )
    img_node_x86 = htz_client.images.get_all(
        label_selector=f"state={state},arch=x86,role=node"
    )
    img_db = htz_client.images.get_all(
        label_selector=f"state={state},arch=arm64,role=db"
    )
    img_size = [len(img_cplane), len(img_node_arm), len(img_node_x86), len(img_db)]

    # Expect to find one image of each type
    if any(x != 1 for x in img_size):
        logging.error(
            f"Found unexpected number of images/snapshots matching labels. Control plane: {len(img_cplane)}. Arm64 nodes: {len(img_node_arm)}. x86 nodes: {len(img_node_x86)}. db: {len(img_db)}"
        )
        sys.exit(1)

    # The get_all method returns a list, so here we always take the first element
    images["control_plane"] = img_cplane[0].id
    images["node_arm64"] = img_node_arm[0].id
    images["node_x86"] = img_node_x86[0].id
    images["db"] = img_db[0].id

    return images


def create_servers(
    htz_client: Client, n_arm_nodes: int, n_x86_nodes: int, logger: logging
):
    """
    Creates servers:    k3s control plane, nodes, and a maria db.
    :param htz_client:  hcloud client with valid token to perform read and write operations
    :param n_arm_nodes: number of arm nodes to create. Must be equal of larger than 1 or not be provided.
    :param n_x86_nodes: number of arm nodes to create. Must be equal of larger than 1 or not be provided.
    :param logger:      logger to be used to print information to stdout.
    :return:            void
    """
    if not n_arm_nodes:
        n_arm_nodes = 2

    if not n_x86_nodes:
        n_x86_nodes = 1

    # Retrieve all current snapshots to create servers
    logger.info("Finding images")
    images = get_images(htz_client, "current")
    logger.info(f"Images found: {images}")

    # Create control plane
    logger.info(f"Creating control plane k3s-control-plane...")
    control_plane = htz_client.servers.create(
        name="k3s-control-plane",
        server_type=ServerType(name="cax11"),
        image=Image(id=images["control_plane"]),
        location=Location(name="hel1"),
        public_net=ServerCreatePublicNetwork(enable_ipv4=False, enable_ipv6=True),
        ssh_keys=[SSHKey(name="thinkpad-generated")],
        firewalls=htz_client.firewalls.get_all(name="ssh-only"),
        labels={"role": "control-plane"},
        start_after_create=False,
    )

    # Create maria db
    logger.info(f"Creating server: maria-db...")
    db = htz_client.servers.create(
        name="maria-db",
        server_type=ServerType(name="cax11"),
        image=Image(id=images["db"]),
        location=Location(name="hel1"),
        public_net=ServerCreatePublicNetwork(enable_ipv4=False, enable_ipv6=True),
        ssh_keys=[SSHKey(name="thinkpad-generated")],
        firewalls=htz_client.firewalls.get_all(name="ssh-only"),
        labels={"role": "db"},
        start_after_create=False,
    )

    # Create arm and x86 nodes
    nodes = list()
    for i in range(1, n_arm_nodes + 1):
        logger.info(f"Creating server: k3s-node-arm-{i}...")
        nodes.append(
            htz_client.servers.create(
                name=f"k3s-node-arm-{i}",
                server_type=ServerType(name="cax11"),
                image=Image(id=images["node_arm64"]),
                location=Location(name="hel1"),
                public_net=ServerCreatePublicNetwork(
                    enable_ipv4=False, enable_ipv6=True
                ),
                ssh_keys=[SSHKey(name="thinkpad-generated")],
                firewalls=htz_client.firewalls.get_all(name="ssh-only"),
                labels={"role": "node-arm"},
                start_after_create=False,
            )
        )
    for i in range(1, n_x86_nodes + 1):
        logger.info(f"Creating server: k3s-node-x86-{i}...")
        nodes.append(
            htz_client.servers.create(
                name=f"k3s-node-x86-{i}",
                server_type=ServerType(name="cpx11"),
                image=Image(id=images["node_x86"]),
                location=Location(name="hel1"),
                public_net=ServerCreatePublicNetwork(
                    enable_ipv4=False, enable_ipv6=True
                ),
                ssh_keys=[SSHKey(name="thinkpad-generated")],
                firewalls=htz_client.firewalls.get_all(name="ssh-only"),
                labels={"role": "node-x86"},
                start_after_create=False,
            )
        )

    # Assign IP address to control plane before turning on server
    logger.info(f"Waiting for control plane to finish creating")
    control_plane.action.wait_until_finished(max_retries=200)
    logger.info(f"Attaching internal IP address to control plane: 10.0.0.2")
    assign_ip = htz_client.servers.attach_to_network(
        server=control_plane.server, network=Network(id=4252606), ip="10.0.0.2"
    ).wait_until_finished()
    htz_client.servers.power_on(control_plane.server)
    logger.info(
        f"Created control plane: {control_plane.server.name}. External IP: {control_plane.server.public_net.ipv6.ip}. Internal IP: 10.0.0.2"
    )

    # Assign IP address to maria db before turning on server
    logger.info(f"Waiting for maria-db to finish creating")
    db.action.wait_until_finished(max_retries=200)
    logger.info(f"Attaching internal IP address to maria-db: 10.0.0.5")
    assign_ip = htz_client.servers.attach_to_network(
        server=db.server, network=Network(id=4252606), ip="10.0.0.5"
    ).wait_until_finished()
    htz_client.servers.power_on(db.server)
    logger.info(
        f"Created db: {db.server.name}. External IP: {db.server.public_net.ipv6.ip}. Internal IP: 10.0.0.5"
    )

    # Assign IP addresses to nodes before turning on servers
    for i, node in enumerate(nodes, start=1):
        logger.info(f"Waiting for node {node.server.name} to finish creating")
        node.action.wait_until_finished(max_retries=200)
        last_octet = i + 9
        internal_ip = f"10.0.0.{last_octet}"
        logger.info(
            f"Attaching internal IP address to node {node.server.name}: {internal_ip}"
        )
        assign_ip = htz_client.servers.attach_to_network(
            server=node.server,
            network=Network(id=4252606),
            ip=internal_ip,
        ).wait_until_finished()
        htz_client.servers.power_on(node.server)
        logger.info(
            f"Created node {node.server.name}. External IP: {node.server.public_net.ipv6.ip}. Internal IP: {internal_ip}"
        )

    return


def delete_servers(htz_client: Client, logger: logging):
    """
    Delete 'old' snapshot, update 'current' snapshot to become 'old', create new 'current' snapshot, and delete all servers.
    :param htz_client:  hcloud client with valid token to perform read and write operations
    :param logger:      logger to be used to print information to stdout.
    :return:            void
    """
    # Retrieve 'old' snapshots so we can delete them. 'current' snapshots will become old
    logger.info("Retrieving existing images")
    images = get_images(htz_client, "old")

    # Delete 'old' snapshots
    logger.info("Deleting snapshots with label 'old'")
    htz_client.images.get_by_id(images["control_plane"]).delete()
    htz_client.images.get_by_id(images["node_arm64"]).delete()
    htz_client.images.get_by_id(images["node_x86"]).delete()
    htz_client.images.get_by_id(images["db"]).delete()
    logger.info("Completed")

    # Update 'current' snapshots to become 'old'
    images = get_images(htz_client, "current")
    logger.info("Re-labeling current snapshots to 'old'")
    htz_client.images.get_by_id(images["control_plane"]).update(
        labels={"state": "old", "arch": "arm64", "role": "control-plane"},
        description="cplane-arm64-snapshot-old",
    )
    htz_client.images.get_by_id(images["node_arm64"]).update(
        labels={"state": "old", "arch": "arm64", "role": "node"},
        description="node-arm64-snapshot-old",
    )
    htz_client.images.get_by_id(images["node_x86"]).update(
        labels={"state": "old", "arch": "x86", "role": "node"},
        description="node-x86-snapshot-old",
    )
    htz_client.images.get_by_id(images["db"]).update(
        labels={"state": "old", "arch": "arm64", "role": "db"},
        description="maria-db-snapshot-old",
    )
    logger.info("Completed")

    # Get list tof all running servers
    logger.info("Retrieving servers")
    servers_db = htz_client.servers.get_all(label_selector="role=db", name="maria-db")
    servers_cplane = htz_client.servers.get_all(label_selector="role=control-plane")
    servers_node_x86 = htz_client.servers.get_all(label_selector="role=node-x86")
    servers_node_arm = htz_client.servers.get_all(label_selector="role=node-arm")
    logging.info(
        f"Found running servers. Control plane: {len(servers_cplane)}. Arm64 nodes: {len(servers_node_arm)}. x86 nodes: {len(servers_node_x86)}. db: {len(servers_db)}."
    )

    # Create snapshots for all server types. Only one node of each type will have a snapshot created (they should be ephemeral)
    logging.info("Creating snapshots from current servers")
    if len(servers_db) > 0:
        img_db = servers_db[0].create_image(
            description="maria-db-current",
            labels={"state": "current", "arch": "arm64", "role": "db"},
        )
    if len(servers_cplane) > 0:
        img_cplane = servers_cplane[0].create_image(
            description="cplane-arm64-snapshot-current",
            labels={"state": "current", "arch": "arm64", "role": "control-plane"},
        )
    if len(servers_node_x86) > 0:
        img_node_x86 = servers_node_x86[0].create_image(
            description="node-x86-snapshot-current",
            labels={"state": "current", "arch": "x86", "role": "node"},
        )
    if len(servers_node_arm) > 0:
        img_node_arm = servers_node_arm[0].create_image(
            description="node-arm64-snapshot-current",
            labels={"state": "current", "arch": "arm64", "role": "node"},
        )

    # Wait until all snapshots are created before deleting servers
    img_db.action.wait_until_finished()
    img_cplane.action.wait_until_finished()
    if len(servers_node_x86) > 0:
        img_node_x86.action.wait_until_finished()
    if len(servers_node_arm) > 0:
        img_node_arm.action.wait_until_finished()
    logging.info("Completed")

    # Delete servers
    logging.info("Deleting servers")
    all_servers = servers_db + servers_cplane + servers_node_x86 + servers_node_arm
    for server in all_servers:
        server.delete()
    logging.info("Completed")

    return


def main():
    parser = argparse.ArgumentParser(
        description="Creates and deletes my k3s instances in hetzner cloud."
    )
    parser.add_argument(
        "--create",
        action="store_true",
        help="Create servers.",
    )
    parser.add_argument(
        "--delete",
        action="store_true",
        help="Delete servers.",
    )
    parser.add_argument(
        "--arm-nodes",
        required=False,
        type=int,
        help="Number of arm64 nodes. Must be equal or larger than 1",
    )
    parser.add_argument(
        "--x86-nodes",
        required=False,
        type=int,
        help="Number of x86 nodes. Must be equal or larger than 1",
    )
    args = vars(parser.parse_args())

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    logger = create_logger()
    logger.info("Starting Hetzner Cloud manager CLI for k3s cluster")

    # If x86-nodes is provided as argument, it must be larger than 0
    if args["x86_nodes"] is not None and args["x86_nodes"] < 1:
        logger.error("x86-nodes must be larger than 0")

    # If arm-nodes is provided as argument, it must be larger than 0
    if args["arm_nodes"] is not None and args["arm_nodes"] < 1:
        logger.error("arm-nodes must be larger than 0")

    htz_client = Client(token=HCLOUD_TOKEN)

    if args["create"]:
        logger.info("Action: create servers")
        create_servers(htz_client, args["arm_nodes"], args["x86_nodes"], logger)
    if args["delete"]:
        logger.info("Action: delete servers")
        delete_servers(htz_client, logger)


if __name__ == "__main__":
    main()
