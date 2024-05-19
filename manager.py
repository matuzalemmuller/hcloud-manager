#!/usr/bin/env python3

import argparse
import logging
import sys

from hcloud import Client
from hcloud.images import Image
from hcloud.server_types import ServerType
from hcloud.ssh_keys import SSHKey
from hcloud.locations import Location
from hcloud.servers.domain import ServerCreatePublicNetwork
from hcloud.networks.domain import Network


def create_logger():
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] - %(levelname)s - %(message)s",
        datefmt="%d/%b/%Y %H:%M:%S",
        stream=sys.stdout,
    )
    return logging


def get_images(htz_client: Client):
    images = dict()

    img_cplane = htz_client.images.get_all(
        label_selector="state=current,arch=arm64,role=control-plane"
    )
    img_node_arm = htz_client.images.get_all(
        label_selector="state=current,arch=arm64,role=node"
    )
    img_node_amd64 = htz_client.images.get_all(
        label_selector="state=current,arch=amd64,role=node"
    )

    if len(img_node_arm) != len(img_node_amd64) != len(img_cplane) != 1:
        logging.error(
            f"Found unexpected number of images/snapshots matching labels. Control plane: {len(img_cplane)}. Arm64 nodes: {len(img_node_arm)}. Amd64 nodes: {len(img_node_amd64)}"
        )
        sys.exit(1)

    images["control-plane"] = img_cplane[0].id
    images["img_node_arm64"] = img_node_arm[0].id
    images["img_node_amd64"] = img_node_amd64[0].id

    return images


def create_servers(
    htz_client: Client, n_arm_nodes: int, n_amd64_nodes: int, logger: logging
):
    if not n_arm_nodes:
        n_arm_nodes = 2

    if not n_amd64_nodes:
        n_amd64_nodes = 0

    logger.info("Finding images")
    images = get_images(htz_client)
    logger.info(f"Images found: {images}")

    logger.info(f"Creating control plane k3s-control-plane...")
    control_plane = htz_client.servers.create(
        name="k3s-control-plane",
        server_type=ServerType(name="cax11"),
        image=Image(id=images["control-plane"]),
        location=Location(name="hel1"),
        public_net=ServerCreatePublicNetwork(enable_ipv4=False, enable_ipv6=True),
        ssh_keys=[SSHKey(name="thinkpad-generated")],
        firewalls=htz_client.firewalls.get_all(name="ssh-only"),
        start_after_create=False,
    )

    nodes = list()
    for i in range(1, n_arm_nodes + 1):
        logger.info(f"Creating node k3s-node-arm-{i}...")
        nodes.append(
            htz_client.servers.create(
                name=f"k3s-node-arm-{i}",
                server_type=ServerType(name="cax11"),
                image=Image(id=images["img_node_arm64"]),
                location=Location(name="hel1"),
                public_net=ServerCreatePublicNetwork(
                    enable_ipv4=False, enable_ipv6=True
                ),
                ssh_keys=[SSHKey(name="thinkpad-generated")],
                firewalls=htz_client.firewalls.get_all(name="ssh-only"),
                start_after_create=False,
            )
        )

    for i in range(1, n_amd64_nodes + 1):
        logger.info(f"Creating node k3s-node-amd-{i}...")
        nodes.append(
            htz_client.servers.create(
                name=f"k3s-node-amd-{i}",
                server_type=ServerType(name="cpx11"),
                image=Image(id=images["img_node_amd64"]),
                location=Location(name="hel1"),
                public_net=ServerCreatePublicNetwork(
                    enable_ipv4=False, enable_ipv6=True
                ),
                ssh_keys=[SSHKey(name="thinkpad-generated")],
                firewalls=htz_client.firewalls.get_all(name="ssh-only"),
                start_after_create=False,
            )
        )

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

    return True


def main():
    htz_client = Client(token="")
    logger = create_logger()
    logger.info("Starting Hetzner Cloud manager CLI for k3s cluster")

    parser = argparse.ArgumentParser(
        description="Creates and deletes my k3s instances in hetzner cloud."
    )
    parser.add_argument(
        "--create",
        action="store_true",
        help="Create instances.",
    )
    parser.add_argument(
        "--arm-nodes", required=False, type=int, help="Number of arm64 nodes"
    )
    parser.add_argument(
        "--amd64-nodes", required=False, type=int, help="Number of amd64 nodes"
    )
    args = vars(parser.parse_args())

    if args["create"]:
        logger.info("Action: create servers")
        create_servers(htz_client, args["arm_nodes"], args["amd64_nodes"], logger)


if __name__ == "__main__":
    main()
