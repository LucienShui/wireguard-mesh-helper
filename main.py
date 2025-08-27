import re
import subprocess
from subprocess import CompletedProcess
from typing import Tuple, List

from yaml import safe_load

from entity import Node, ClusterConfig

mesh_ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{2}$")


def validate_ip(ip: str) -> bool:
    if mesh_ip_pattern.match(ip):
        ip, mask = ip.split("/")
        ip_splits = [int(num) for num in ip.split(".")]
        if len(ip_splits) != 4:
            return False
        for i, num in enumerate(ip_splits):
            if i + num == 0 or not 0 <= num <= 255:
                return False
        return int(mask) == 32
    return False


def remote_run(hostname: str, command: str | List[str]) -> CompletedProcess:
    if isinstance(command, list):
        command = " && ".join(command)
    return subprocess.run([
        "ssh", "-o", "StrictHostKeyChecking=no", f"root@{hostname}", command
    ], capture_output=True, text=True)


def get_keys(hostname: str) -> Tuple[str, str]:
    private_filename = "key"
    public_filename = "key.pub"
    check_result = remote_run(hostname, [
        "cd /etc/wireguard",
        f"[ -f {private_filename} ] && [ -f {public_filename} ]"
    ])
    if check_result.returncode != 0:
        create_result = remote_run(hostname, [
            "cd /etc/wireguard",
            f"touch {private_filename} && chmod 600 {private_filename}",
            f"wg genkey > {private_filename}",
            f"touch {public_filename} && chmod 600 {public_filename}",
            f"wg pubkey < {private_filename} > {public_filename}"
        ])
        assert create_result.returncode == 0
    cat_result = remote_run(hostname, ["cd /etc/wireguard", f"cat {public_filename} {private_filename}"])
    stdout: str = cat_result.stdout
    split_result: List[str] = stdout.strip().split("\n")
    public_key, private_key = split_result
    return public_key, private_key


def validate_host(hostname: str) -> bool:
    result = remote_run(hostname, "which wg > /dev/null && [ -d /etc/wireguard ]")
    if result.returncode != 0:
        print({"hostname": hostname, "stderr": result.stderr, "stdout": result.stdout, "code": result.returncode})
        return False
    return True


def remote_write(hostname: str, text: str, dst_file: str) -> bool:
    result = remote_run(hostname, f"cat << EOF > {dst_file}\n{text}\nEOF")
    return result.returncode == 0


def main():
    with open("config.yaml") as f:
        config_dict: dict = safe_load(f)
    config = ClusterConfig.model_validate(config_dict)
    name: str = config.name
    node_list: List[Node] = []
    mesh_ip_set: set = set()
    external_ip_set: set[tuple[str, int]] = set()

    for region_config in config.regions:
        region = region_config.name
        region_ip_set: set = set()
        for node_config in region_config.nodes:
            hostname = node_config.name
            if not validate_host(hostname):
                continue
            public_key, private_key = get_keys(hostname)
            node = Node.model_validate(node_config.model_dump(exclude_none=True) | {
                "region": region,
                "hostname": hostname,
                "public_key": public_key,
                "private_key": private_key
            })

            assert validate_ip(node.mesh_ip), node.mesh_ip
            assert node.internal_ip not in region_ip_set, node.internal_ip
            assert node.mesh_ip not in mesh_ip_set, node.mesh_ip
            if node.external_ip:
                assert (node.external_ip, node.wg_port) not in external_ip_set, node.hostname
            region_ip_set.add(node.internal_ip)
            mesh_ip_set.add(node.mesh_ip)
            external_ip_set.add((node.external_ip, node.wg_port))

            node_list.append(node)

    for x in node_list:
        config_list = [x.to_server()]
        for y in node_list:
            if x.mesh_ip == y.mesh_ip:
                continue
            if x.region == y.region:
                config_list.append(y.to_peer("internal"))
            else:
                if y.external_ip:
                    config_list.append(y.to_peer("external"))
                else:
                    config_list.append(y.to_peer("none"))

        node_wg_config: str = "\n\n".join(config_list)
        remote_write(x.hostname, node_wg_config, f"/etc/wireguard/{name}.conf")


if __name__ == '__main__':
    main()
