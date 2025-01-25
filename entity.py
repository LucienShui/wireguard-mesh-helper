from typing import Optional, Literal

from pydantic import BaseModel, Field


class NodeConfig(BaseModel):
    name: str
    external_ip: Optional[str] = Field(default=None)
    internal_ip: str
    wg_port: int
    mesh_ip: str


class RegionConfig(BaseModel):
    name: str
    nodes: list[NodeConfig]


class ClusterConfig(BaseModel):
    name: str
    regions: list[RegionConfig]


class Node(BaseModel):
    internal_ip: str
    external_ip: Optional[str] = Field(default=None)
    mesh_ip: str
    wg_port: int
    wg_base_dir: Optional[str] = Field(default="/etc/wireguard")

    region: str
    hostname: str
    public_key: str
    private_key: str

    def to_server(self) -> str:
        return "\n".join([
            f"[Interface]  # {self.region}/{self.hostname}",
            f"PrivateKey = {self.private_key}",
            f"Address = {self.mesh_ip}",
            f"ListenPort = {self.wg_port}"
        ])

    def to_peer(self, endpoint_type: Literal["external", "internal", "none"]) -> str:
        assert endpoint_type in ["external", "internal", "none"], f"Unknown endpoint type: {endpoint_type}"
        result_list = [f"[Peer]  # {self.region}/{self.hostname}"]
        if endpoint_type in ["external", "internal"]:
            result_list.append(
                f"Endpoint = {self.external_ip if endpoint_type == 'external' else self.internal_ip}:{self.wg_port}")
        result_list.extend([
            f"PublicKey = {self.public_key}",
            f"AllowedIPs = {self.mesh_ip}",
            f"PersistentKeepalive = 25"
        ])
        return "\n".join(result_list)
