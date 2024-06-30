#!/usr/bin/env python3

import argparse
import configparser
import getpass
import logging
import sys

# Not doing much exception handling because I want the script to bomb out with the entire exeption stack if anything fails ¯\_(ツ)_/¯
from hcloud import Client
from hcloud.locations import Location
from hcloud.images import Image
from hcloud.networks.domain import Network
from hcloud.server_types import ServerType
from hcloud.servers.domain import ServerCreatePublicNetwork
from hcloud.ssh_keys import SSHKey


def create_logger():
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] - %(levelname)s - %(message)s",
        datefmt="%d/%b/%Y %H:%M:%S",
        stream=sys.stdout,
    )
    return logging


def parse_config(first_login: bool, logger: logging):
    """
    Manage hcloud token stored at /home/$USER/.hcloud_token.
    The token needs read and write permissions.
    https://docs.hetzner.com/cloud/api/getting-started/generating-api-token/

    :return token:    token string.
    """
    config_file = "/home/" + getpass.getuser() + "/.hcloud_token"
    config = configparser.ConfigParser()

    if not first_login:
        config.read(config_file)

    if not config.has_option("token", "hcloud_token"):
        logger.info("No token found at " + config_file)
        token = input("Provide Hetzner API token: ")
        config["token"] = {"hcloud_token": token}

        try:
            with open(config_file, "w") as file:
                config.write(file)
                logger.info("Saved token at " + config_file)
        except Exception as error:
            print(error)
            sys.exit(1)

    return config["token"]["hcloud_token"]


def get_images(htz_client: Client, state: str):
    """
    Gets snapshot ID for all servers.

    :param htz_client: hcloud client with valid token to perform read operations.
    :param state:      snapshot state. Valid values are 'old' and 'current'.
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


def list_running_servers(htz_client: Client, logger: logging):
    """
    Returns dictionary with lists of running servers.
    :param htz_client:  hcloud client with valid token to perform read and write operations.
    :param logger:      logger to be used to print information to stdout.
    :return:            dictionary with lists of running servers [BoundImage]
    """
    # Get list of all running servers
    logger.info("Retrieving servers")
    servers_db = htz_client.servers.get_all(label_selector="role=db", name="maria-db")
    servers_cplane = htz_client.servers.get_all(label_selector="role=control-plane")
    servers_node_x86 = htz_client.servers.get_all(label_selector="role=node-x86")
    servers_node_arm = htz_client.servers.get_all(label_selector="role=node-arm")
    if any(
        x > 0
        for x in [
            len(servers_db),
            len(servers_cplane),
            len(servers_node_x86),
            len(servers_node_arm),
        ]
    ):
        logging.info(
            f"Found running servers. Control plane: {len(servers_cplane)}. Arm64 nodes: {len(servers_node_arm)}. x86 nodes: {len(servers_node_x86)}. db: {len(servers_db)}."
        )
    else:
        logging.info("No running servers")

    return {
        "servers_db": servers_db,
        "servers_cplane": servers_cplane,
        "servers_node_x86": servers_node_x86,
        "servers_node_arm": servers_node_arm,
    }


def create_servers(
    htz_client: Client,
    logger: logging,
    n_arm_nodes: int,
    n_x86_nodes: int,
    type_control_plane: str,
    type_arm_node: str,
    type_x86_node: str,
):
    """
    Creates servers:    k3s control plane, nodes, and a maria db.
    :param htz_client:  hcloud client with valid token to perform read and write operations.
    :param n_arm_nodes: number of arm nodes to create. Must be greater or equal to 1.
    :param n_x86_nodes: number of x86 nodes to create. Must be greater or equal to 1.
    :param type_control_plane: server spec to be used for control plane.
    :param type_arm_node: server spec to be used for arm nodes.
    :param type_x86_node: server spec to be used for x86 nodes.
    :param logger:      logger to be used to print information to stdout.
    :return:            void
    """

    logger.info("Checking if there are already servers created")
    servers = list_running_servers(htz_client, logger)

    servers_db = servers["servers_db"]
    servers_cplane = servers["servers_cplane"]
    servers_node_x86 = servers["servers_node_x86"]
    servers_node_arm = servers["servers_node_arm"]

    if any(
        x > 0
        for x in [
            len(servers_db),
            len(servers_cplane),
            len(servers_node_x86),
            len(servers_node_arm),
        ]
    ):

        logging.error(f"Can't create new servers until existing ones are deleted")
        sys.exit(1)

    # Retrieve all current snapshots to create servers
    logger.info("Finding images")
    images = get_images(htz_client, "current")
    logger.info(f"Images found: {images}")

    # Create control plane
    logger.info(f"Creating server: k3s-control-plane")
    control_plane = htz_client.servers.create(
        name="k3s-control-plane",
        server_type=ServerType(name="cax11"),
        image=Image(id=images["control_plane"]),
        location=Location(name="hel1"),
        public_net=ServerCreatePublicNetwork(enable_ipv4=True, enable_ipv6=True),
        ssh_keys=[SSHKey(name="thinkpad-generated")],
        firewalls=htz_client.firewalls.get_all(name="ssh-only"),
        labels={"role": "control-plane"},
        start_after_create=False,
    )

    # Create maria db
    logger.info(f"Creating server: maria-db")
    db = htz_client.servers.create(
        name="maria-db",
        server_type=ServerType(name="cax11"),
        image=Image(id=images["db"]),
        location=Location(name="hel1"),
        public_net=ServerCreatePublicNetwork(enable_ipv4=True, enable_ipv6=True),
        ssh_keys=[SSHKey(name="thinkpad-generated")],
        firewalls=htz_client.firewalls.get_all(name="ssh-only"),
        labels={"role": "db"},
        start_after_create=False,
    )

    # Create arm and x86 nodes
    nodes = list()
    for i in range(1, n_arm_nodes + 1):
        logger.info(f"Creating server: k3s-node-arm-{i}")
        nodes.append(
            htz_client.servers.create(
                name=f"k3s-node-arm-{i}",
                server_type=ServerType(name="cax11"),
                image=Image(id=images["node_arm64"]),
                location=Location(name="hel1"),
                public_net=ServerCreatePublicNetwork(
                    enable_ipv4=True, enable_ipv6=True
                ),
                ssh_keys=[SSHKey(name="thinkpad-generated")],
                firewalls=htz_client.firewalls.get_all(name="ssh-only"),
                labels={"role": "node-arm"},
                start_after_create=False,
            )
        )
    for i in range(1, n_x86_nodes + 1):
        logger.info(f"Creating server: k3s-node-x86-{i}")
        nodes.append(
            htz_client.servers.create(
                name=f"k3s-node-x86-{i}",
                server_type=ServerType(name="cx22"),
                image=Image(id=images["node_x86"]),
                location=Location(name="hel1"),
                public_net=ServerCreatePublicNetwork(
                    enable_ipv4=True, enable_ipv6=True
                ),
                ssh_keys=[SSHKey(name="thinkpad-generated")],
                firewalls=htz_client.firewalls.get_all(name="ssh-only"),
                labels={"role": "node-x86"},
                start_after_create=False,
            )
        )

    # Assign IP address to control plane before turning on server
    logger.info(f"Waiting for server creation: {control_plane.server.name}")
    control_plane.action.wait_until_finished(max_retries=200)
    # If server is not using base type, upgrade (by upgrading we can keep the disk smaller. Otherwise, the server needs to be created with a larger disk)
    if control_plane.server.server_type.name != type_control_plane:
        logger.info(
            f"Upgrading server spec to {type_control_plane}: {control_plane.server.name}"
        )
        control_plane.server.change_type(
            server_type=ServerType(name=type_control_plane), upgrade_disk=False
        ).wait_until_finished(max_retries=200)
    logger.info(
        f"Attaching internal IP address 10.0.0.2 to server: {control_plane.server.name}"
    )
    assign_ip = htz_client.servers.attach_to_network(
        server=control_plane.server, network=Network(id=4252606), ip="10.0.0.2"
    ).wait_until_finished(max_retries=500)
    htz_client.servers.power_on(control_plane.server)
    logger.info(
        f"Created server: {control_plane.server.name}. External IP: {control_plane.server.public_net.ipv4.ip}. Internal IP: 10.0.0.2"
    )

    # Assign IP address to maria db before turning on server
    logger.info(f"Waiting for server creation: {db.server.name}")
    db.action.wait_until_finished(max_retries=200)
    logger.info(f"Attaching internal IP address 10.0.0.5 to server: {db.server.name}")
    assign_ip = htz_client.servers.attach_to_network(
        server=db.server, network=Network(id=4252606), ip="10.0.0.5"
    ).wait_until_finished(max_retries=500)
    htz_client.servers.power_on(db.server)
    logger.info(
        f"Created server: {db.server.name}. External IP: {db.server.public_net.ipv4.ip}. Internal IP: 10.0.0.5"
    )

    # Assign IP addresses to nodes before turning on servers
    for i, node in enumerate(nodes, start=1):
        logger.info(f"Waiting for server creation: {node.server.name}")
        node.action.wait_until_finished(max_retries=200)
        # If server is not using base type, upgrade (by upgrading we can keep the disk smaller. Otherwise, the server needs to be created with a larger disk)
        if node.server.server_type.architecture == "x86":
            if node.server.server_type.name != type_x86_node:
                logger.info(
                    f"Upgrading server spec to {type_x86_node}: {node.server.name}"
                )
                node.server.change_type(
                    server_type=ServerType(name=type_x86_node), upgrade_disk=False
                ).wait_until_finished(max_retries=200)
        else:
            if node.server.server_type.name != type_arm_node:
                logger.info(
                    f"Upgrading server spec to {type_arm_node}: {node.server.name}"
                )
                node.server.change_type(
                    server_type=ServerType(name=type_arm_node), upgrade_disk=False
                ).wait_until_finished(max_retries=200)
        last_octet = i + 9
        internal_ip = f"10.0.0.{last_octet}"
        logger.info(
            f"Attaching internal IP address {internal_ip} to server: {node.server.name}"
        )
        assign_ip = htz_client.servers.attach_to_network(
            server=node.server,
            network=Network(id=4252606),
            ip=internal_ip,
        ).wait_until_finished(max_retries=500)
        htz_client.servers.power_on(node.server)
        logger.info(
            f"Created server: {node.server.name}. External IP: {node.server.public_net.ipv4.ip}. Internal IP: {internal_ip}"
        )

    return


def backup_images(htz_client: Client, logger: logging):
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
    running_servers = list_running_servers(htz_client, logger)

    # Create snapshots for all server types. Only one node of each type will have a snapshot created (they should be ephemeral)
    logging.info("Creating snapshots from current servers")
    if len(running_servers["servers_db"]) > 0:
        img_db = running_servers["servers_db"][0].create_image(
            description="maria-db-current",
            labels={"state": "current", "arch": "arm64", "role": "db"},
        )
    if len(running_servers["servers_cplane"]) > 0:
        img_cplane = running_servers["servers_cplane"][0].create_image(
            description="cplane-arm64-snapshot-current",
            labels={"state": "current", "arch": "arm64", "role": "control-plane"},
        )
    if len(running_servers["servers_node_x86"]) > 0:
        img_node_x86 = running_servers["servers_node_x86"][0].create_image(
            description="node-x86-snapshot-current",
            labels={"state": "current", "arch": "x86", "role": "node"},
        )
    if len(running_servers["servers_node_arm"]) > 0:
        img_node_arm = running_servers["servers_node_arm"][0].create_image(
            description="node-arm64-snapshot-current",
            labels={"state": "current", "arch": "arm64", "role": "node"},
        )

    # Wait until all snapshots are created before deleting servers
    if len(running_servers["servers_db"]) > 0:
        img_db.action.wait_until_finished(max_retries=500)
    if len(running_servers["servers_cplane"]) > 0:
        img_cplane.action.wait_until_finished(max_retries=500)
    if len(running_servers["servers_node_x86"]) > 0:
        img_node_x86.action.wait_until_finished(max_retries=500)
    if len(running_servers["servers_node_arm"]) > 0:
        img_node_arm.action.wait_until_finished(max_retries=500)
    logging.info("Completed")

    return


def delete_servers(htz_client: Client, logger: logging, backup: bool):
    """
    Delete 'old' snapshot, update 'current' snapshot to become 'old', create new 'current' snapshot, and delete all servers.
    :param htz_client:  hcloud client with valid token to perform read and write operations.
    :param logger:      logger to be used to print information to stdout.
    :return:            void
    """
    logger.info("Checking if there are servers running")
    servers = list_running_servers(htz_client, logger)

    servers_db = servers["servers_db"]
    servers_cplane = servers["servers_cplane"]
    servers_node_x86 = servers["servers_node_x86"]
    servers_node_arm = servers["servers_node_arm"]

    if (
        len(servers_db)
        == len(servers_cplane)
        == len(servers_node_x86)
        == len(servers_node_arm)
        == 0
    ):
        logging.error(f"Exiting since there are no servers to delete")
        sys.exit(1)

    if backup:
        logger.info("Taking backup of running images")
        backup_images(htz_client, logger)
    else:
        logger.info("Skipping backup")

    # Delete servers
    logging.info("Deleting servers")
    all_servers = servers_db + servers_cplane + servers_node_x86 + servers_node_arm
    for server in all_servers:
        server.delete()
    logging.info("Completed")

    return


def main():
    parser = argparse.ArgumentParser(
        description="Creates and deletes my VMs in hetzner cloud. I use this for quickly creating and deleting a small k3s cluster."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--add-token",
        action="store_true",
        help="add hcloud token to config",
    )
    group.add_argument(
        "--create",
        action="store_true",
        help="create servers",
    )
    group.add_argument(
        "--delete-with-backup",
        action="store_true",
        help="take snapshots and delete servers",
    )
    group.add_argument(
        "--delete-no-backup",
        action="store_true",
        help="delete servers without taking snapshot",
    )
    group.add_argument(
        "--list",
        action="store_true",
        help="list running servers",
    )
    parser.add_argument(
        "--arm-nodes",
        required=False,
        nargs="?",
        const=1,
        default=1,
        type=int,
        help="number of arm64 vms. Must be greater or equal to 1. Default = 1",
    )
    parser.add_argument(
        "--x86-nodes",
        required=False,
        nargs="?",
        const=2,
        default=2,
        type=int,
        help="number of x86 vms. Must be greater or equal to 1. Default = 2",
    )
    parser.add_argument(
        "--cplane-spec",
        required=False,
        nargs="?",
        default="cax11",
        type=str,
        help="server type for control plane. Default = cax11",
    )
    parser.add_argument(
        "--arm-node-spec",
        required=False,
        nargs="?",
        default="cax11",
        type=str,
        help="server type for arm nodes. Default = cax11",
    )
    parser.add_argument(
        "--x86-node-spec",
        required=False,
        nargs="?",
        default="cx22",
        type=str,
        help="server type for x86 nodes. Default = cx22",
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

    if args["add_token"]:
        logger.info("Action: add hcloud token to config")
        parse_config(True, logger)
        sys.exit(0)

    hcloud_token = parse_config(False, logger)
    htz_client = Client(token=hcloud_token)

    if args["create"]:
        logger.info("Action: create servers")
        create_servers(
            htz_client=htz_client,
            logger=logger,
            n_arm_nodes=args["arm_nodes"],
            n_x86_nodes=args["x86_nodes"],
            type_control_plane=args["cplane_spec"],
            type_arm_node=args["arm_node_spec"],
            type_x86_node=args["x86_node_spec"],
        )
    if args["delete_with_backup"]:
        logger.info("Action: delete servers with backup")
        delete_servers(htz_client=htz_client, logger=logger, backup=True)
    if args["delete_no_backup"]:
        logger.info("Action: delete servers without backup")
        delete_servers(htz_client=htz_client, logger=logger, backup=False)
    if args["list"]:
        logger.info("Action: list servers")
        list_running_servers(htz_client=htz_client, logger=logger)


if __name__ == "__main__":
    main()
