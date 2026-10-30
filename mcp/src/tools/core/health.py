from typing import Dict, Any
from src.docker_client import GregorForgeDockerClient
from src.execution_policy import VERSION_DIAGNOSTIC_TOOLS
from src.models.common import HealthStatus

class HealthChecker:
    """
    Comprehensive health check system for GregorForge toolbox.
    Monitors container status, tool availability, and resource usage.
    """

    def __init__(self, docker_client: GregorForgeDockerClient):
        self.docker_client = docker_client

        # Essential tools that must be present for the toolbox to be "healthy".
        # This gates the healthy/unhealthy verdict only, NOT what the model sees.
        self.essential_tools = sorted(VERSION_DIAGNOSTIC_TOOLS)

    def check(self) -> HealthStatus:
        """
        Perform comprehensive health check.

        Returns:
            HealthStatus with detailed health information
        """
        # Get basic health from Docker client
        health_info = self.docker_client.health_check()

        # Check if container is running
        if not health_info["container_running"]:
            return HealthStatus(
                healthy=False,
                container_running=False,
                message=health_info["message"],
            )

        # In diagnostic-only mode, probe only the small essential set. Broad
        # capability discovery implies active tools are ready when execution is
        # deliberately disabled.
        all_tools_status = self.docker_client.check_tools_bulk(self.essential_tools)

        # The healthy/unhealthy verdict rests only on the essential tools.
        essential_status = {t: all_tools_status.get(t, False) for t in self.essential_tools}
        essential_healthy = all(essential_status.values())
        disk_usage = health_info.get("disk_usage")

        # Check disk space warning
        disk_warning = False
        if disk_usage and "use_percent" in disk_usage:
            use_percent = int(disk_usage["use_percent"].rstrip("%"))
            disk_warning = use_percent > 80

        # Overall health determination
        healthy = essential_healthy and not disk_warning

        # Build message
        if not essential_healthy:
            missing_tools = [tool for tool, status in essential_status.items() if not status]
            message = f"Essential tools missing: {', '.join(missing_tools)}"
        elif disk_warning:
            message = f"Disk usage warning: {disk_usage['use_percent']} used"
        else:
            message = "Diagnostics available; active execution disabled"

        return HealthStatus(
            healthy=healthy,
            container_running=True,
            tools_available=all_tools_status,
            disk_usage=disk_usage,
            message=message,
        )

    def check_tool(self, tool_name: str) -> Dict[str, Any]:
        """
        Check if a specific tool is available and get its version.

        Args:
            tool_name: Name of the tool to check

        Returns:
            Dictionary with tool status and version info
        """
        available = self.docker_client.check_tool_available(tool_name)

        version_info = None
        if available and tool_name in VERSION_DIAGNOSTIC_TOOLS:
            result = self.docker_client.execute_command(
                [tool_name, "--version"], timeout=10
            )
            if result.success:
                version_info = result.stdout.strip().split("\n")[0]

        return {
            "tool_name": tool_name,
            "available": available,
            "version": version_info,
        }

    def check_network_connectivity(self) -> Dict[str, Any]:
        """
        Check network connectivity from the container.

        Returns:
            Dictionary with connectivity status
        """
        return {
            "status": "disabled",
            "reason": "Network diagnostics are disabled with active tool execution.",
        }

    def get_resource_usage(self) -> Dict[str, Any]:
        """
        Get detailed resource usage information.

        Returns:
            Dictionary with resource usage stats
        """
        resources = {}

        # Get disk usage
        disk_result = self.docker_client.execute_command("df -h", timeout=10)
        if disk_result.success:
            resources["disk"] = disk_result.stdout

        # Get memory usage
        mem_result = self.docker_client.execute_command("free -h", timeout=10)
        if mem_result.success:
            resources["memory"] = mem_result.stdout

        # Get running processes count
        return resources

    def diagnose(self) -> Dict[str, Any]:
        """
        Run comprehensive diagnostics.

        Returns:
            Dictionary with full diagnostic information
        """
        return {
            "health": self.check().model_dump(),
            "network": self.check_network_connectivity(),
            "resources": self.get_resource_usage(),
            "essential_tools": {
                tool: self.check_tool(tool) for tool in self.essential_tools
            },
        }
